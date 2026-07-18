# SENTINEL

SENTINEL ingests live IOC feeds and security writeups, validates and enriches
indicators, preserves source lineage, maps to MITRE ATT&CK, generates
type-aware detections, delivers alerts to Telegram, and runs a
replay-evaluated self-improvement loop over its skill files.

## What actually works today

- **Live IOC pulls** from ThreatFox, URLhaus, FeodoTracker, OTX,
  MalwareBazaar, and PhishTank with freshness filtering
  (`sentinel/agents/scraper.py`).
- **Writeup ingestion**: RSS/blog entries are treated as source material, not
  IOCs. Article bodies are fetched, HTML-stripped, and candidate indicators
  (defanged domains/URLs, IPs, hashes, CVEs) are extracted with provenance
  back to the article (`sentinel/agents/ioc_extract.py`, `SourceMaterial` +
  `IOCSighting` tables).
- **Lineage-preserving dedupe**: IOC values stay canonical in `iocs`, but
  every source occurrence is recorded in `ioc_sightings`, so corroboration
  (distinct observing sources) is countable and shown in alerts.
- **Bounded writeup discovery** (`sentinel/agents/discovery.py`): additive,
  analyst-style search profiles (keywords, freshness window, allow/deny hosts,
  strict fetch/time budgets) triage candidate articles *before* fetching,
  prefer pages with explicit "Indicators of Compromise" sections, extract at
  high fidelity from those sections (including non-defanged domains on
  indicator-list lines), and skip weak pages quickly. Results enter the normal
  pipeline with `provenance="discovery"` plus search-profile/extraction-mode
  attribution, and analyst TP/FP feedback folds into a durable
  `discovery_memory` table that future triage consults — the learnable knobs
  live in `skills/discovery/SKILL.md` where the Karpathy loop can reach them.
  Run standalone with `sentinel discover`; inspect learning with
  `sentinel discovery-memory --sync`. Pipeline integration is opt-in via
  `discovery.enabled` in config.yaml.
- **Enrichment** via VirusTotal, Shodan, AbuseIPDB, optional WHOIS, with a
  weighted risk score. Enrichment is now bounded by configurable provider
  timeouts, batch size, and a per-run IOC cap so a large feed pull cannot fan
  out unbounded API work in one pass.
- **MITRE ATT&CK matching** via TF-IDF over a local STIX bundle.
- **Type-aware detection generation** for Sigma, KQL, SPL, YARA, and
  CrowdStrike: domains get dns_query rules, URLs get proxy rules, IPs get
  network_connection rules, hashes get process_creation/hash-module rules.
  Types the CrowdStrike IOC API cannot accept are skipped with a reason
  rather than pushed wrong.
- **Telegram delivery + feedback**: alert cards with corroboration counts and
  inline Confirm/False Positive/Needs Review buttons; verdicts persist with
  the IOC's source snapshot.
- **Karpathy loop (source trust)** with a real replay metric: proposals edit
  a trust score in `skills/sources/SKILL.md`, and the metric recomputes
  would-have-alerted precision/recall (F0.5) over the labeled feedback window
  under the edited trust — so the number can actually move because of the
  patch. Runs are readiness-gated, worktree-isolated, and fully logged to
  `experiment_logs` with confusion-matrix detail. See
  [docs/karpathy_loop.md](docs/karpathy_loop.md).
  Live optimization currently supports the `source` loop only; scoring and
  detection remain non-live surfaces until their metrics are directly
  production-meaningful.

## Quickstart

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .          # or: pip install -r requirements.txt
cp .env.example .env                # fill in keys (see below)
.venv/bin/pytest                    # temp sqlite, no live network required
```

Runtime dependencies: PostgreSQL and Redis, plus a local MITRE ATT&CK
enterprise STIX bundle pointed at by `MITRE_STIX_PATH`. SQLite works for local
experiments
(`DATABASE_URL=sqlite+aiosqlite:///./data/sentinel.db`).

For production Postgres deployments, tune the async engine through `db.*` in
`config.yaml` (`pool_pre_ping`, `pool_recycle_seconds`, `pool_size`,
`max_overflow`).

Required env keys per command are validated at startup; the minimum for the
pipeline is `DATABASE_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and
`MITRE_STIX_PATH`.

Feed-ingestion keys pull new threat data into SENTINEL:
`OTX_API_KEY`, `THREATFOX_API_KEY`, `MALWAREBAZAAR_API_KEY`, and optionally
`PHISHTANK_APP_KEY`.

Enrichment keys do not ingest new indicators; they validate, enrich, and score
IOCs after ingestion:
`VT_API_KEY`, `SHODAN_API_KEY`, and `ABUSEIPDB_API_KEY`.

Key production runtime knobs:
- `sources.mix.max_items_per_source`
- `enrichment.provider_timeout_seconds`
- `enrichment.batch_size`
- `enrichment.max_iocs_per_run`
- `delivery.telegram_digest_candidate_pool_size`
- `karpathy.min_keep_delta`
- `karpathy.max_false_positive_increase`
- `karpathy.max_true_positive_drop`
- `karpathy.lease_ttl_seconds`

All of those optional keys degrade gracefully when absent. `PHISHTANK_APP_KEY`
is optional; without it the implemented PhishTank source stays disabled rather
than hammering the flaky public endpoint.

## Commands

```bash
sentinel cron-run            # production one-shot pull/store/enrich/Telegram run
sentinel feedback-service    # production always-on Telegram feedback + Karpathy learner
sentinel run-once            # full pipeline: scrape -> validate -> enrich -> score -> rules -> deliver
sentinel scraper-diagnose    # per-feed fetch/kept/stale/balance diagnostics, no delivery
sentinel daily-digest        # last-24h digest to Telegram
sentinel scheduler           # legacy combined scheduler for scrape cadence + daily digest
sentinel karpathy-service    # debug-only: run only the Karpathy loop scheduler
sentinel karpathy-status     # readiness, active lease, and recent Karpathy run history
sentinel telegram-listen     # debug-only: capture analyst feedback buttons without Karpathy
sentinel karpathy-validate --loop source --scenario improve   # shadow-mode loop mechanics
sentinel karpathy-run --loop source --max-experiments 1       # readiness-gated live loop
```

(Equivalent: `.venv/bin/python -m sentinel.cli <command>`.)

## Ops model

- External cron: run `sentinel cron-run` at your chosen time, e.g. `0 7 * * *`.
- Long-lived learning process: run `sentinel feedback-service` so analyst button clicks are captured and the Karpathy loop learns from them in the same service.
- Operator inspection: run `sentinel karpathy-status --loop source` to see preflight state, active lease ownership, and recent experiment outcomes.

Recommended production shape:

```bash
# 7:00 AM pull/store/alert run
0 7 * * * cd /path/to/SENTINEL && env PYTHONPATH=. .venv/bin/python -m sentinel.cli cron-run
```

```bash
# separate always-on feedback + learner service
env PYTHONPATH=. .venv/bin/python -m sentinel.cli feedback-service
```

Legacy split-service commands remain available for debugging, but they are no
longer the primary operator path.

Telegram alert cards now include a dedicated `Remove IOC` button. That action
purges the IOC plus its linked sightings and feedback rows from the database;
use `False Positive` when you want analyst learning without deleting the row.

## Karpathy Notes

- Live Karpathy currently supports the `source` loop only.
- Promotion now requires more than a positive metric blip: the loop enforces a
  minimum delta plus replay guardrails on true-positive loss and false-positive
  increase.
- Live runs acquire a DB-backed lease via `service_leases`, so duplicate
  `feedback-service` or `karpathy-service` instances do not optimize concurrently.
- Experiment logs now carry skill hashes and keep/revert decision details so
  every promoted change can be traced back to the exact evaluated skill state.

## Data model (v2)

- `iocs` — canonical indicator (unique on normalized-value hash), enrichment
  and scoring state.
- `ioc_sightings` — one row per (IOC, source, provenance, reference); counts
  repeats, links writeup-extracted IOCs to their article. Provenance is
  `feed`, `writeup`, or `manual`.
- `source_materials` — writeups/articles: URL, title, published/fetched
  timestamps, extracted text, extraction status.
- `feedback_records` — analyst verdicts with the IOC's source snapshotted at
  feedback time.
- `experiment_logs` — Karpathy experiments with eval mode (`replay`/`live`),
  target, metric before/after, and full eval detail JSON.
- `schema_migrations` — lightweight migration ledger for additive schema
  upgrades applied by the runtime bootstrap.

Schema upgrades are currently additive and version-recorded:
`sentinel.db.migrations.ensure_schema` creates missing tables, applies known
`ALTER TABLE ADD COLUMN` upgrades, and records each applied step in
`schema_migrations`. Alembic should be used for staged production schema
changes that go beyond additive column rollout.

## Repo layout

- `sentinel/agents/` — scraper, validator, enricher, scorer, rule generator,
  delivery, learner, IOC extraction.
- `sentinel/loops/` — Karpathy loop base, source/scoring/detection loops,
  replay evaluator, LLM providers.
- `sentinel/db/` — SQLAlchemy models, session, additive migrations.
- `skills/` — versioned prompt/config files the loops are allowed to edit;
  `skills/CHANGELOG.md` records every kept change.
- `generated/detections/` — committed detection artifacts by platform.
- `tests/` — async sqlite temp databases, no live network.

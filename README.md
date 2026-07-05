# SENTINEL

SENTINEL ingests live IOC feeds and security writeups, validates and enriches
indicators, preserves source lineage, maps to MITRE ATT&CK, generates
type-aware detections, delivers alerts to Telegram, and runs a
replay-evaluated self-improvement loop over its skill files.

## What actually works today

- **Live IOC pulls** from ThreatFox, URLhaus, FeodoTracker, and OTX with
  freshness filtering (`sentinel/agents/scraper.py`).
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
  weighted risk score.
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

## Quickstart

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e .          # or: pip install -r requirements.txt
cp .env.example .env                # fill in keys (see below)
.venv/bin/pytest                    # 99 tests, no network or database needed
```

Runtime dependencies: PostgreSQL and Redis (`docker-compose up postgres redis`),
plus a local MITRE ATT&CK enterprise STIX bundle pointed at by
`MITRE_STIX_PATH`. SQLite works for local experiments
(`DATABASE_URL=sqlite+aiosqlite:///./data/sentinel.db`).

Required env keys per command are validated at startup; the minimum for the
pipeline is `DATABASE_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and
`MITRE_STIX_PATH`. Enrichment keys (`VT_API_KEY`, `SHODAN_API_KEY`,
`ABUSEIPDB_API_KEY`) and feed keys (`OTX_API_KEY`, `THREATFOX_API_KEY`)
degrade gracefully when absent.

## Commands

```bash
sentinel run-once            # full pipeline: scrape -> validate -> enrich -> score -> rules -> deliver
sentinel scraper-diagnose    # per-feed fetch/kept/stale diagnostics, no delivery
sentinel daily-digest        # last-24h digest to Telegram
sentinel scheduler           # APScheduler service (interval scrape + daily digest)
sentinel telegram-listen     # capture analyst feedback buttons
sentinel karpathy-validate --loop source --scenario improve   # shadow-mode loop mechanics
sentinel karpathy-run --loop source --max-experiments 1       # readiness-gated live loop
```

(Equivalent: `.venv/bin/python -m sentinel.cli <command>`.)

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

Schema upgrades are additive: `sentinel.db.migrations.ensure_schema` creates
new tables and issues `ALTER TABLE ADD COLUMN` for columns added since the
database was created (Alembic migration files are the eventual replacement).

## Repo layout

- `sentinel/agents/` — scraper, validator, enricher, scorer, rule generator,
  delivery, learner, IOC extraction.
- `sentinel/loops/` — Karpathy loop base, source/scoring/detection loops,
  replay evaluator, LLM providers.
- `sentinel/db/` — SQLAlchemy models, session, additive migrations.
- `skills/` — versioned prompt/config files the loops are allowed to edit;
  `skills/CHANGELOG.md` records every kept change.
- `generated/detections/` — committed detection artifacts by platform.
- `tests/` — 99 tests; async sqlite in-memory, no live network.

# SENTINEL

SENTINEL ingests live IOC feeds and security writeups, validates and enriches
indicators, preserves source lineage, maps to MITRE ATT&CK, generates
type-aware detections, delivers alerts to Telegram, and runs a
replay-evaluated self-improvement loop over its skill files.

## What actually works today

- **Live IOC pulls** from ThreatFox, URLhaus, TweetFeed, FeodoTracker, OTX,
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
git clone https://github.com/Nicholas-devsec/SENTINEL.git
cd SENTINEL
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

## EC2 Live Testing Runbook

Use this when cloning the repo onto a fresh EC2 instance for multi-day
Telegram/Karpathy testing.

### 1. Clone And Install

```bash
git clone https://github.com/Nicholas-devsec/SENTINEL.git
cd SENTINEL
python3 --version
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e .
cp .env.example .env
mkdir -p data
```

SENTINEL requires Python 3.12+. Ubuntu 24.04/26.04 AMIs are fine as long as
`python3 --version` reports 3.12 or newer. If you need to check the Ubuntu
release, use `cat /etc/os-release`; there is no `ubuntu --version` command.

The package also installs a `sentinel` console command, but the examples below use
`.venv/bin/python -m sentinel.cli ...` so cron/systemd do not depend on shell
activation.

Pull the local MITRE ATT&CK bundle before the first run:

```bash
git clone https://github.com/mitre-attack/attack-stix-data.git data/attack-stix-data
```

### 2. Configure `.env`

Minimum required for cron pull/store/enrich/Telegram:

```bash
DATABASE_URL=sqlite+aiosqlite:///./data/sentinel.db
REDIS_URL=disabled
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
MITRE_STIX_PATH=/absolute/path/to/enterprise-attack.json
VT_API_KEY=...
SHODAN_API_KEY=...
ABUSEIPDB_API_KEY=...
```

On the standard EC2 checkout used in this runbook, set:

```bash
MITRE_STIX_PATH=/home/ubuntu/SENTINEL/data/attack-stix-data/enterprise-attack/enterprise-attack.json
```

If you copied `.env` or `config.yaml` from a laptop, remove any workstation
paths such as `/mnt/storage/...`; those paths will not exist on EC2.

Feed pull keys:

```bash
OTX_API_KEY=...
THREATFOX_API_KEY=...
MALWAREBAZAAR_API_KEY=...
PHISHTANK_APP_KEY=
```

Karpathy/feedback learning:

```bash
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.openai.com/v1
```

`PHISHTANK_APP_KEY`, SendGrid, CrowdStrike, Redis, and email are optional for
the current Telegram-first test flow.

### 3. Configure `config.yaml`

Primary live-test knobs:

```yaml
schedule:
  pipeline_cron: "5 0 * * *"
  timezone: "America/Vancouver"
  enable_karpathy_job: false
  karpathy_loop_cron: "0 3 * * 0"

workflow:
  telegram_feed_alert_limit_per_run: 5
  telegram_type_limits_per_run:
    ipv4: 2
    domain: 1
    hash: 1
  telegram_feed_article_alert_limit_per_run: 1
  telegram_discovery_article_alert_limit_per_run: 1
```

The current setup sends up to six Telegram messages per cron run:
two direct feed IPs, one direct feed domain, one direct feed hash, one
configured-feed article, and one discovery/open-web article. Keep
`delivery.telegram_max_alerts_per_run` at least as high as that total.

`checkpoint_research` is configured as a curated RSS writeup source but is
disabled. Check Point's AWS WAF has returned HTTP 202 with
`x-amzn-waf-action: challenge` and no RSS body to the non-browser scraper.
Before enabling it, verify from the runtime host that both the feed and
article pages can be fetched consistently; a 202 response can otherwise be
parsed as an empty feed.

`sans_isc_diary` uses SANS ISC's title/summary diary RSS feed and a cautious
article parser. The parser currently emits hashes with an adjacent hash label
and IPs tied to scanner or attacker context, while excluding known public DNS
resolvers, linked citations, and general-news CVEs. It remains disabled during
analyst review: an initial
live test incorrectly included public DNS resolvers from a RedTail diary;
the follow-up test produced only a scanner IP from a Proxmox diary. Both tests
used a temporary 120-hour article window; the configured window is 72 hours.

Retention is on by default so unalerted feed-only noise does not clog the DB:

```yaml
retention:
  enabled: true
  prune_on_cron: true
  unalerted_feed_ioc_ttl_days: 5
  alerted_ioc_ttl_days: 90
  article_ioc_ttl_days: 30
  keep_feedback_labeled: true
```

### 4. Smoke Test Before Scheduling

```bash
env PYTHONPATH=. .venv/bin/python -m sentinel.cli status
env PYTHONPATH=. .venv/bin/python -m sentinel.cli scraper-diagnose
env PYTHONPATH=. .venv/bin/python -m sentinel.cli cron-run
```

Expected `cron-run` behavior:

- Scrapes live threat feeds and configured writeup feeds.
- Runs discovery/open-web article search if `discovery.enabled: true`.
- Stores IOCs, sightings, source material, pipeline run stats, and alert
  ledger rows.
- Sends Telegram alerts according to `workflow` and `delivery` limits.
- Runs retention pruning at the end of the cron run.

Use this to inspect what happened:

```bash
env PYTHONPATH=. .venv/bin/python -m sentinel.cli status
env PYTHONPATH=. .venv/bin/python -m sentinel.cli discovery-memory --sync
env PYTHONPATH=. .venv/bin/python -m sentinel.cli karpathy-status --loop source
```

### 5. Production Commands

Run exactly two production processes:

```bash
# one-shot pull/store/enrich/Telegram pipeline, launched by cron
env PYTHONPATH=. .venv/bin/python -m sentinel.cli cron-run
```

```bash
# always-on Telegram feedback listener plus scheduled Karpathy learner
env PYTHONPATH=. .venv/bin/python -m sentinel.cli feedback-service
```

Legacy `telegram-listen` and `karpathy-service` still exist for debugging, but
the primary production model is `cron-run` plus `feedback-service`.

### 6. Cron Setup

External cron uses the EC2 host's cron timezone, not `config.yaml`. On Ubuntu,
set the instance timezone before installing a Vancouver-time crontab:

```bash
sudo timedatectl set-timezone America/Vancouver
timedatectl
```

Example crontab for a `12:05 AM America/Vancouver` run:

```cron
5 0 * * * cd /home/ubuntu/SENTINEL && env PYTHONPATH=. .venv/bin/python -m sentinel.cli cron-run >> logs/cron-run.log 2>&1
```

If the EC2 host stays on UTC, `5 0 * * *` runs at `00:05 UTC`, which is
`5:05 PM America/Vancouver` during daylight saving time. Either set the host
timezone as shown above, or convert the schedule to UTC yourself.

Create the log directory first:

```bash
mkdir -p logs
```

The `logs/cron-run.log` file is created by the first scheduled cron run. If
`tail logs/cron-run.log` says the file does not exist immediately after setup,
that only means cron has not fired yet.

### 7. systemd Feedback Service

Create `/etc/systemd/system/sentinel-feedback.service`:

```ini
[Unit]
Description=SENTINEL Telegram feedback listener and Karpathy learner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/ubuntu/SENTINEL
Environment=PYTHONPATH=.
ExecStart=/home/ubuntu/SENTINEL/.venv/bin/python -m sentinel.cli feedback-service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-feedback
sudo systemctl status sentinel-feedback --no-pager
systemctl is-active sentinel-feedback
journalctl -u sentinel-feedback -f
```

If `systemctl is-active sentinel-feedback` prints `active`, the Telegram
feedback listener and scheduled Karpathy learner can keep running after you
exit SSH. Do not also run the legacy `telegram-listen` or `karpathy-service`
processes in production; `feedback-service` covers both jobs.

### 8. Multi-Day Karpathy Testing Loop

Daily operator loop:

```bash
env PYTHONPATH=. .venv/bin/python -m sentinel.cli status
env PYTHONPATH=. .venv/bin/python -m sentinel.cli discovery-memory --sync
env PYTHONPATH=. .venv/bin/python -m sentinel.cli karpathy-status --loop source
```

In Telegram, click only the feedback buttons:

- `True Positive`: keep and reward this IOC/source/article pattern.
- `False Positive`: records negative feedback; article-scope FP handling also
  teaches discovery memory to deprioritize noisy publishers/articles.
- `Needs Review`: keeps the item available for later judgment without treating
  it as a confirmed TP or FP.

When enough labeled samples exist, enable scheduled Karpathy runs:

```yaml
schedule:
  enable_karpathy_job: true
  karpathy_loop_cron: "0 3 * * 0"
  karpathy_loop_type: "source"
```

For manual shadow validation without changing live files:

```bash
env PYTHONPATH=. .venv/bin/python -m sentinel.cli karpathy-validate --loop source --scenario improve
```

For one readiness-gated live optimization:

```bash
env PYTHONPATH=. .venv/bin/python -m sentinel.cli karpathy-run --loop source --max-experiments 1
```

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

# SENTINEL — Codex Project Brief
> Agentic Threat Intelligence Platform  
> Drop this file in the repo root. Start every Codex session by saying: "Read CODEX.md first."

---

## What this project is

SENTINEL is an autonomous, self-improving threat intelligence platform. It runs as a cron job that:

1. **Scrapes** IOC feeds and security news articles from live sources
2. **Validates** and deduplicates every indicator
3. **Enriches** through VirusTotal, Shodan, AbuseIPDB, WHOIS, and MITRE ATT&CK
4. **Scores** each IOC 0–100 with risk level and ATT&CK TTP mapping
5. **Generates** Sigma rules, CrowdStrike IOC API payloads, KQL, SPL, and YARA
6. **Delivers** via Telegram bot (with inline analyst feedback) and daily email digest
7. **Learns** — a Karpathy Loop runs automated optimization experiments on skill files

---

## Architecture overview

```
Cron scheduler
    │
    ▼
ScraperAgent          ← loads skills/sources/SKILL.md
    │ (Redis queue)
    ▼
ValidationAgent       ← loads skills/validation/SKILL.md
    │
    ▼
EnrichmentAgent       ← loads skills/enrichment/SKILL.md
    │
    ▼
ScoringAgent          ← loads skills/mitre/SKILL.md
    │
    ├──► RuleGeneratorAgent   ← loads skills/detection/SKILL.md
    │         │ push to CrowdStrike / git commit Sigma rules
    │
    └──► DeliveryAgent        ← loads skills/delivery/SKILL.md
              │ Telegram alert + email digest
              │ analyst feedback → FeedbackRecord table
              ▼
         LearnerAgent
              │ updates skill files based on feedback + metrics
              ▼
         KarpathyLoop (3x)
              │ runs N experiments, measures metric, keeps best skill file version
              └──► git commit to skills/CHANGELOG.md
```

---

## Invariants — never break these

- Every agent loads ONE skill file at `__init__` as a system prompt injection
- Only `LearnerAgent` and `KarpathyLoop` are permitted to write to skill files
- Every skill file write must be followed by a `git commit` with a structured message
- The Karpathy Loop modifies ONE skill file per experiment, measures ONE metric, has ONE time budget
- No agent imports from another agent — they communicate via Redis queue or DB only

---

## Skill file system

```
skills/
├── sources/SKILL.md          # feed URLs, trust scores, rate limits
├── validation/SKILL.md       # IOC regex patterns, FP allowlists
├── enrichment/SKILL.md       # API configs, scoring weights
├── detection/SKILL.md        # Sigma/KQL/SPL/YARA templates, CrowdStrike schema
├── delivery/SKILL.md         # message templates, severity routing
├── mitre/SKILL.md            # TTP keyword map, ATT&CK IDs + severity weights
├── learner/SKILL.md          # self-update rules, what can/cannot be changed
├── CHANGELOG.md              # append-only log of all skill file changes
└── INDEX.md                  # maps each agent class to its skill file
```

Each SKILL.md has this structure:
```markdown
---
version: 1.0.0
last_updated: YYYY-MM-DD
updated_by: [agent or human]
---

# [Skill name]

## [Section 1]
... content the agent uses as instructions ...

## [Section N]
<!-- learner: append here -->
```

The `<!-- learner: append here -->` comment is the write anchor for LearnerAgent.

---

## Karpathy Loop — the three invariants

Per Karpathy's autoresearch design (adapted for threat intel):

| # | Invariant | SENTINEL implementation |
|---|-----------|------------------------|
| 1 | Agent modifies ONE file | One skill file per loop type |
| 2 | ONE measurable metric | Precision / hit rate / score correlation |
| 3 | Fixed time budget | `asyncio.wait_for(timeout=budget)` |

**Three loop types:**

- **Loop 1 — Source quality** → modifies `skills/sources/SKILL.md` → metric: precision (TP/total)
- **Loop 2 — Rule effectiveness** → modifies `skills/detection/SKILL.md` → metric: rule hit rate
- **Loop 3 — Score calibration** → modifies `skills/enrichment/SKILL.md` → metric: score vs analyst severity correlation

The loop agent calls the Anthropic API with the current skill file + experiment history, receives a JSON patch (one change + reasoning), applies it, measures the metric, keeps the best version, reverts failures.

---

## Directory structure

```
sentinel/
├── agents/
│   ├── base.py               # BaseAgent: skill loading, async run(), logging
│   ├── scraper.py            # ScraperAgent + source adapters
│   ├── validator.py          # ValidationAgent
│   ├── enricher.py           # EnrichmentAgent (async fan-out)
│   ├── scorer.py             # ScoringAgent + MITRE mapping
│   ├── rule_generator.py     # RuleGeneratorAgent
│   ├── delivery.py           # DeliveryAgent (Telegram + email)
│   └── learner.py            # LearnerAgent
├── loops/
│   ├── karpathy_loop.py      # ThreatIntelLoop base class
│   ├── source_loop.py        # Loop 1
│   ├── detection_loop.py     # Loop 2
│   └── scoring_loop.py       # Loop 3
├── integrations/
│   ├── virustotal.py
│   ├── shodan.py
│   ├── abuseipdb.py
│   ├── crowdstrike.py        # IOC ingestion API
│   ├── mitre_attack.py       # ATT&CK data loader + TF-IDF index
│   └── taxii_client.py       # STIX/TAXII feed consumer
├── db/
│   ├── models.py             # IOC, Source, FeedbackRecord, ExperimentLog
│   ├── session.py            # SQLAlchemy async session factory
│   └── vector_store.py       # ChromaDB wrapper for IOC embeddings
├── delivery/
│   ├── telegram_bot.py       # Bot setup, handlers, inline keyboard
│   └── email_digest.py       # SendGrid HTML digest builder
├── scheduler/
│   └── cron.py               # APScheduler job definitions
├── skills/                   # (see skill file system above)
├── tests/
│   ├── conftest.py           # fixtures, mock API responses
│   ├── test_scraper.py
│   ├── test_validator.py
│   ├── test_enricher.py
│   ├── test_scorer.py
│   ├── test_rule_generator.py
│   ├── test_delivery.py
│   ├── test_learner.py
│   └── test_karpathy_loop.py
├── docs/
│   ├── architecture.md       # Mermaid diagram source
│   └── blog_post_draft.md    # LinkedIn / Medium article
├── config.yaml               # all keys and settings (never commit secrets)
├── .env.example              # env var template
├── requirements.txt
├── CODEX.md                  # this file
└── README.md
```

---

## Key data models

```python
# db/models.py

class IOC(Base):
    id: uuid
    value: str                    # normalized IOC value
    type: str                     # ipv4, domain, md5, sha256, url, cve
    source: str                   # originating feed
    source_trust: float           # from skills/sources/SKILL.md at scrape time
    first_seen: datetime
    last_seen: datetime
    risk_score: float             # 0–100
    severity: str                 # critical/high/medium/informational
    vt_detections: int
    shodan_ports: list[int]
    abuse_confidence: int
    mitre_techniques: list[str]   # e.g. ["T1566.001", "T1059"]
    mitre_tactics: list[str]
    sigma_rule: str               # generated Sigma YAML
    crowdstrike_pushed: bool
    analyst_verdict: str          # confirmed/false_positive/needs_review/null
    campaign_id: str | None       # vector cluster ID from ChromaDB

class FeedbackRecord(Base):
    id: uuid
    ioc_id: uuid
    analyst_id: str               # Telegram user ID
    verdict: str
    timestamp: datetime
    channel: str                  # telegram/email/manual

class ExperimentLog(Base):
    id: uuid
    loop_type: str                # source/detection/scoring
    experiment_number: int
    hypothesis: str
    patch_applied: str
    metric_before: float
    metric_after: float
    delta: float
    kept: bool
    timestamp: datetime
```

---

## Codex prompt sequence

Run these prompts in order. Each one is a self-contained task.

### Prompt 1 — Scaffold
```
Read CODEX.md. Create the full project scaffold: all directories,
config.yaml with placeholder keys for every integration, BaseAgent
class in agents/base.py with skill-loading and async run() method,
all SQLAlchemy models in db/models.py, and APScheduler cron setup in
scheduler/cron.py.
```

### Prompt 2 — Scraper agent
```
Read CODEX.md agents/base.py db/models.py skills/sources/SKILL.md.
Build ScraperAgent with adapters for: AlienVault OTX (TAXII 2.1 via
taxii2-client), abuse.ch URLhaus CSV, FeodoTracker JSON, generic RSS
(feedparser). Each adapter returns List[RawIOC]. Load source trust
scores from SKILL.md. Push to Redis queue on completion.
```

### Prompt 3 — Validation agent
```
Read CODEX.md agents/base.py db/models.py skills/validation/SKILL.md.
Build ValidationAgent: IPv4/6 regex + octet validation, domain TLD
check, hash length detection (md5/sha1/sha256), URL scheme validation,
CVE pattern. Reject RFC1918, localhost, and entries in
data/tranco_top10k.txt. Deduplicate by SHA-256 of normalized value.
Load FP patterns from SKILL.md. Persist valid IOCs to DB.
```

### Prompt 4 — Enrichment agent
```
Read CODEX.md agents/base.py db/models.py skills/enrichment/SKILL.md.
Build async EnrichmentAgent. For each validated IOC, fan out with
asyncio.gather to: VirusTotal (vt-py), Shodan (shodan SDK), AbuseIPDB
(REST), python-whois. Use asyncio.Semaphore per API for rate limiting.
Merge results into EnrichedIOC. Compute weighted risk score 0-100 using
weights from SKILL.md. Handle API errors gracefully — partial enrichment
is acceptable.
```

### Prompt 5 — Scoring + MITRE
```
Read CODEX.md agents/base.py db/models.py skills/mitre/SKILL.md.
Build ScoringAgent. Load MITRE ATT&CK enterprise JSON from
mitre-attack-data package. Build TF-IDF index of technique descriptions.
For each enriched IOC, extract context (description, tags, enrichment
text), compute cosine similarity against technique index, return top-3
ATT&CK technique IDs + tactic names. Map risk score to severity enum:
90-100=critical, 70-89=high, 50-69=medium, <50=informational.
```

### Prompt 6 — Detection rule generator
```
Read CODEX.md agents/base.py skills/detection/SKILL.md.
Build RuleGeneratorAgent. Use Jinja2 to render templates from SKILL.md.
For every IOC with score >= 50, generate:
  - Sigma YAML rule (network_connection logsource)
  - CrowdStrike IOC API POST payload (type/value/action/severity/platforms)
  - KQL query (for Microsoft Sentinel)
  - SPL savedsearch (for Splunk)
  - YARA rule for hash types only
Push to CrowdStrike Falcon via POST /indicators/entities/iocs/v1.
Commit Sigma/KQL/SPL/YARA files to git with GitPython.
```

### Prompt 7 — Telegram + email delivery
```
Read CODEX.md agents/base.py skills/delivery/SKILL.md.
Build DeliveryAgent with python-telegram-bot (async, v20+).
For IOCs with risk_score >= 70, send immediate Telegram alert with
InlineKeyboardMarkup: ["Confirm Threat", "False Positive", "Needs Review"].
Handle callback_query_handler, store verdict in FeedbackRecord.
Build daily_digest() that queries all medium+ IOCs from last 24h,
renders Jinja2 HTML email template, sends via SendGrid.
```

### Prompt 8 — Learner agent
```
Read CODEX.md agents/base.py skills/learner/SKILL.md db/models.py.
Build LearnerAgent with these behaviors:
  1. Query FeedbackRecord, compute FP rate per source over rolling 48h.
     If rate > 0.15, reduce trust_score in skills/sources/SKILL.md by 0.05.
  2. If analyst marks IOC as FP and same pattern seen 3+ times,
     append pattern to <!-- learner: append here --> in validation/SKILL.md.
  3. Query ExperimentLog, append successful optimizations to detection/SKILL.md.
All changes: read file → apply change → write file → git commit with message:
"learner: [date] updated [skill] — [reason] (delta: [value])"
Append structured entry to skills/CHANGELOG.md.
```

### Prompt 9 — Karpathy Loop
```
Read CODEX.md loops/ db/models.py skills/learner/SKILL.md.
Build ThreatIntelLoop base class in loops/karpathy_loop.py. Three loop types:
  - source: skill=sources/SKILL.md, metric=precision(TP/total IOCs last 48h)
  - detection: skill=detection/SKILL.md, metric=rule_hit_rate(rules fired/total)
  - scoring: skill=enrichment/SKILL.md, metric=spearman(predicted_score, analyst_score)
For each experiment: call Anthropic API (claude-sonnet-4-20250514) with current skill
+ history, get JSON {description, patch, section, reasoning}, apply patch, run metric
with asyncio.wait_for(timeout=budget), keep if improved, revert if not.
Log to ExperimentLog. Stop if delta < 0.001 for 3 consecutive experiments.
```

### Prompt 10 — Tests + README
```
Read CODEX.md and all agents/. Write pytest suite using respx to mock all HTTP
calls, fakeredis for Redis, and SQLite for DB. Test each agent with real fixture
IOCs. Write README.md with: one-para pitch, mermaid architecture diagram,
feature list, quickstart, config reference, "How the Karpathy Loop works"
section, example Telegram alert screenshot placeholder, example Sigma rule
output block, and contributing guide.
```

---

## Config reference

```yaml
# config.yaml
schedule:
  scrape_interval_hours: 4
  daily_digest_time: "08:00"
  karpathy_loop_day: "sunday"

thresholds:
  alert_score: 70          # Telegram immediate alert
  rule_score: 50           # generate detection rules
  karpathy_experiments: 25 # experiments per loop run
  karpathy_budget_mins: 30 # time budget per experiment

sources:
  otx_api_key: ${OTX_API_KEY}
  feeds:
    - name: urlhaus
      url: https://urlhaus-api.abuse.ch/v1/urls/recent/
      trust: 0.91
    - name: feodotracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.json
      trust: 0.93

enrichment:
  virustotal_key: ${VT_API_KEY}
  shodan_key: ${SHODAN_API_KEY}
  abuseipdb_key: ${ABUSEIPDB_API_KEY}
  weights:
    vt_ratio: 0.35
    abuse_confidence: 0.30
    source_trust: 0.20
    recency: 0.15

crowdstrike:
  client_id: ${CS_CLIENT_ID}
  client_secret: ${CS_CLIENT_SECRET}
  base_url: https://api.crowdstrike.com

delivery:
  telegram_token: ${TELEGRAM_BOT_TOKEN}
  telegram_chat_id: ${TELEGRAM_CHAT_ID}
  sendgrid_key: ${SENDGRID_API_KEY}
  email_from: sentinel@yourdomain.com
  email_to: [analyst@yourdomain.com]

anthropic:
  api_key: ${ANTHROPIC_API_KEY}
  model: claude-sonnet-4-20250514

db:
  url: ${DATABASE_URL}   # postgresql+asyncpg://...
  redis_url: ${REDIS_URL}

git:
  skills_repo_path: ./skills
  author_name: SENTINEL Learner
  author_email: sentinel@bot
```

---

## Portfolio checklist

- [ ] All 10 Codex prompts completed and tested
- [ ] README.md has Mermaid architecture diagram
- [ ] README.md has example Sigma rule output
- [ ] README.md has Telegram alert screenshot
- [ ] `docs/blog_post_draft.md` written (for LinkedIn / Medium)
- [ ] GitHub Actions CI runs pytest on every push
- [ ] 8 LinkedIn posts drafted (one per build phase)
- [ ] Project pinned to GitHub profile
- [ ] Project linked in LinkedIn featured section

---

*SENTINEL — Build something worth talking about.*

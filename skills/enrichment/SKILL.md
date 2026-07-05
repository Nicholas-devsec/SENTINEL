---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Enrichment Skill

## Providers
- VirusTotal
- Shodan
- AbuseIPDB
- WHOIS

## Scoring Weights
- vt_ratio: 0.30
- abuse_confidence: 0.25
- source_trust: 0.10
- recency: 0.10
- context: 0.15
- corroboration: 0.10

## Scoring Notes
- Trust and recency are intentionally small so no single feed clears the
  detection threshold on trust alone; evidence and analyst curation must carry
  an indicator across the bar.
- context: credit for indicators pulled from an explicit writeup IOC section
  (1.0) or other writeup/discovery extraction (0.6); direct feeds earn 0.0.
- corroboration: credit for indicators observed by multiple independent
  sources (0.5 for two sources, 1.0 for three or more).

## Enrichment Rules
- Partial enrichment is acceptable when an upstream API fails.
- Preserve raw provider response snippets needed for downstream scoring.

## Learner Updates
<!-- learner: append here -->


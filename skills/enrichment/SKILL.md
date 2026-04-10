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
- vt_ratio: 0.35
- abuse_confidence: 0.30
- source_trust: 0.20
- recency: 0.15

## Enrichment Rules
- Partial enrichment is acceptable when an upstream API fails.
- Preserve raw provider response snippets needed for downstream scoring.

## Learner Updates
<!-- learner: append here -->


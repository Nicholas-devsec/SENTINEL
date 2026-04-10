---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Sources Skill

## Feed Inventory
- AlienVault OTX TAXII 2.1 feed
- abuse.ch URLhaus CSV and recent URL API
- abuse.ch FeodoTracker JSON
- Generic RSS security news feeds

## Trust Scores
- urlhaus: 0.91
- feodotracker: 0.93
- otx: 0.90
- rss_default: 0.60

## Rate Limits
- Respect provider-specific API limits and use per-source throttling.
- Prefer incremental fetches and preserve source attribution on every IOC.

## Source Handling Rules
- Normalize source names before queuing indicators.
- Record feed metadata needed for analyst traceability.

## Learner Updates
<!-- learner: append here -->


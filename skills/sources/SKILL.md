---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Sources Skill

## Feed Inventory
- abuse.ch ThreatFox recent IOC API
- AlienVault OTX TAXII 2.1 feed
- abuse.ch URLhaus CSV and recent URL API
- TweetFeed.live Twitter/X community IOC API
- abuse.ch FeodoTracker JSON
- Cisco Talos blog RSS
- Palo Alto Unit 42 blog RSS
- Kaspersky Securelist blog RSS
- CrowdStrike blog RSS
- SentinelOne blog RSS
- Rapid7 blog RSS
- GBHackers blog RSS
- Generic RSS security news feeds

## Trust Scores
- threatfox: 0.94
- urlhaus: 0.91
- tweetfeed: 0.62
- feodotracker: 0.93
- otx: 0.90
- talos_blog: 0.68
- unit42_blog: 0.68
- securelist_blog: 0.67
- crowdstrike_blog: 0.67
- sentinelone_blog: 0.66
- rapid7_blog: 0.66
- gbhackers_blog: 0.64

## Rate Limits
- Respect provider-specific API limits and use per-source throttling.
- Prefer incremental fetches and preserve source attribution on every IOC.

## Source Handling Rules
- Normalize source names before queuing indicators.
- Record feed metadata needed for analyst traceability.
- Treat TweetFeed IOCs as community-reported hunting/watchlist candidates unless corroborated by enrichment or another source.

## Learner Updates
<!-- learner: append here -->

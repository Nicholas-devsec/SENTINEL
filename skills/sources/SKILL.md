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
- OpenPhish Community snapshot-diff phishing URL feed
- abuse.ch FeodoTracker JSON
- Cisco Talos blog RSS
- Google Cloud Threat Intelligence RSS
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
- openphish: 0.82
- feodotracker: 0.93
- otx: 0.90
- talos_blog: 0.68
- google_cloud_threat_intelligence: 0.70
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
- Treat OpenPhish Community as a snapshot-diff feed: baseline without emitting, emit only URLs added since a prior successful snapshot inside the configured freshness window, and rebaseline without emitting after stale gaps.
- Treat Google Cloud Threat Intelligence writeups as section-only: emit IOCs only from explicit IOC/Indicators sections; do not fallback-extract generic article links.

## Learner Updates
<!-- learner: append here -->

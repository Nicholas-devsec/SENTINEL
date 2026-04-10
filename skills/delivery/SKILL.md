---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Delivery Skill

## Notification Channels
- Telegram immediate alerts for high-risk indicators
- Daily email digest for medium-and-above indicators

## Message Templates
- Include IOC value, type, score, severity, source, and ATT&CK mappings.
- Provide analyst feedback actions where supported.

## Routing Rules
- Send immediate alerts for score >= 70.
- Batch the previous 24 hours of medium+ IOCs into the daily digest.

## Learner Updates
<!-- learner: append here -->


# SENTINEL Architecture

```mermaid
flowchart TD
    Cron[Cron Scheduler] --> Scraper[ScraperAgent]
    Scraper --> Validator[ValidationAgent]
    Validator --> Enricher[EnrichmentAgent]
    Enricher --> Scorer[ScoringAgent]
    Scorer --> RuleGen[RuleGeneratorAgent]
    Scorer --> Delivery[DeliveryAgent]
    Delivery --> Learner[LearnerAgent]
    Learner --> Loop[Karpathy Loops]
```


---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# MITRE Skill

## Mapping Strategy
- Build a text index over ATT&CK technique descriptions.
- Use enrichment context and source descriptions for similarity matching.

## Severity Weights
- critical: 90-100
- high: 70-89
- medium: 50-69
- informational: 0-49

## Output Rules
- Return the top three ATT&CK techniques with associated tactics.
- Favor high-confidence technique matches over broad generic mappings.

## Learner Updates
<!-- learner: append here -->


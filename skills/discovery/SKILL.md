---
version: 1.0.0
last_updated: 2026-07-03
updated_by: human
---

# Discovery Skill

Tunable heuristics for the bounded writeup-discovery pass. Profiles (what to
search, where, budgets) live in config.yaml and belong to the operator; the
weights and signals here are the learnable surface a Karpathy loop or the
learner may adjust, one section per experiment.

## Triage Weights
- keyword_hits: 0.35
- title_keyword_bonus: 0.20
- freshness: 0.15
- source_trust: 0.10
- memory: 0.20

## Gating
- min_triage_score: 0.35
- min_section_iocs: 2
- min_fallback_iocs: 3
- min_body_words: 40

## Section Signals
- indicators of compromise
- indicator of compromise
- iocs
- ioc
- indicators
- atomic indicators
- network indicators
- file indicators
- file hashes
- c2 infrastructure
- c2 servers

## Notes
- min_triage_score must stay above the no-keyword baseline that freshness +
  source_trust + memory alone can produce (~0.30 with the default weights),
  otherwise keyword-poor pages consume fetch budget.
- keyword_hits: fraction of profile keywords present in title+summary+tags.
- title_keyword_bonus: added when any keyword appears in the title itself.
- freshness: 1.0 at publish time, decaying to 0.0 at the profile window edge.
- memory: Laplace-smoothed analyst precision for the source (0.5 = no data).
- min_section_iocs: sections yielding fewer indicators are treated as weak.
- min_fallback_iocs: whole-body extractions below this are discarded as noise.
- min_body_words: fetched pages with no IOC section AND fewer words than
  this are classified as empty shells (JS apps, consent pages), not as
  articles lacking indicators; extraction always runs first so IOC-dense
  thin pages are never discarded.

## Learner Updates
<!-- learner: append here -->

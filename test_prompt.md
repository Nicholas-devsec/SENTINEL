Add a human-like, bounded writeup discovery capability to SENTINEL.

This is an additive feature.
It is not a repo takeover.
It is not a product pivot.
It should complement the current SENTINEL system, not replace it.

Do not re-review the repo.
Do not give architecture theory.
Do not reinterpret this as replacing existing ingestion.

Important framing:
SENTINEL already has:
- direct IOC feed ingestion
- RSS/writeup ingestion
- enrichment/scoring/delivery
- Telegram analyst feedback
- replay/Karpathy learning direction

Your task is to add a new modular discovery-and-curation capability on top of that existing system.

What I want:
I want SENTINEL to gain an additional workflow that behaves more like a good human threat analyst:
- search for fresh writeups using configurable parameters
- triage which pages are worth spending time on
- prefer pages with explicit IOC/Indicators sections
- extract high-fidelity indicators when present
- skip weak pages quickly
- feed strong results into the current SENTINEL pipeline
- send useful findings to Telegram
- remember what sources/search patterns/pages produced TP vs FP outcomes
- expose knobs that Karpathy/feedback can refine over time

This should be implemented as an addition to the project.
It should NOT replace:
- direct IOC feed ingestion
- current RSS/writeup support
- the existing delivery/scoring architecture

Desired additive behavior:
1. Use specific keyword/search parameters to discover candidate writeups
2. Apply freshness/time constraints
3. Apply a strict fetch/search budget
4. Fetch candidate pages
5. Prefer pages with explicit IOC/Indicators sections
6. If a page has a strong IOC section, extract from it
7. If it does not, skip it and move on quickly
8. Push high-fidelity extracted findings into the existing SENTINEL pipeline and Telegram delivery
9. Track analyst TP/FP feedback from Telegram for these modular-search-derived results
10. Persist that learning in a durable knowledge/memory structure so the system improves over time
11. Make the Karpathy loop able to refine this added search-and-curation capability over time

Very important:
This is NOT just better RSS ingestion.
This is an additive modular discovery pipeline with bounded budget and analyst-feedback-driven refinement.

Implement these capabilities

1. Additive discovery layer
Create a modular discovery layer that can work from configurable search profiles rather than only hardcoded RSS feeds.

This should live alongside the existing source/feed system, not replace it.

It should support configurable parameters like:
- search keywords / keyword groups
- freshness window
- max candidates
- time budget / fetch budget
- source allowlist / denylist
- strictness settings
- preference for IOC-heavy language such as:
  - IOC
  - IOCs
  - Indicators of Compromise
  - hash
  - C2
  - payload
  - phishing
  - stealer
  - malware
  - loader
  - backdoor
  - CVE

If a full web-search integration is too large for one pass, implement the best additive stepping stone cleanly so the repo can support it properly later.
But bias toward real functionality, not just scaffolding.

2. Human-like candidate triage
Before fetching full article bodies, rank or filter candidates using:
- title
- summary
- tags
- source
- freshness
- IOC-like wording
- likely signal density

Use a bounded budget.
Do not spend time evenly across all sources.

3. IOC-section preference
After fetching a page, try to detect whether it has:
- explicit IOC section
- explicit indicators table
- hashes/IPs/URLs grouped together
- “Indicators of Compromise” wording
- “IOCs” wording
- structured list/table of indicators

If yes:
- prioritize extraction from that section
- use the section as the main signal source

If not:
- either do a lower-confidence extraction
- or skip the page, depending on the source/profile and signal quality

I want the system to skip weak pages quickly.

4. Budget/time constraints
This additive pipeline must be bounded.
Implement clear controls for:
- total search/discovery time budget
- per-source candidate cap
- per-page fetch budget or timeout
- maximum number of pages processed per run

Make those controls configurable.

5. Integration with existing pipeline
High-fidelity results from this modular discovery path should flow into the normal existing SENTINEL flow:
- validation
- enrichment
- scoring
- storage
- Telegram alerts
- analyst feedback

Do not create a disconnected parallel system unless absolutely necessary.

6. Feedback attribution and memory
For alerts originating from this modular search/discovery path, track analyst feedback in a way that preserves:
- source
- search profile / search terms
- article/writeup
- extraction mode (IOC-section vs fallback extraction)
- verdict (TP/FP/review)

Persist this into a durable knowledge/memory structure.
You can implement this as a table, model, document, or another repo-native structure.

The point is:
the agent should remember what worked and what did not.

I want something like a memory/knowledge structure of:
- good sources
- bad sources
- good search patterns
- bad search patterns
- good article styles
- bad article styles
- high-yield IOC section signals
- noisy patterns to avoid

7. Karpathy-loop readiness
Do not redesign Karpathy again unless necessary.
But make this new additive discovery path learnable.

I want future Karpathy-loop optimization to be able to refine things like:
- source preference
- search term weighting
- candidate triage strictness
- IOC-section preference
- extraction gating
- alert quality heuristics

So structure the new controls and stored metrics so the loop has something real to optimize later.

Implementation constraints
- Stay scoped to this ask
- Do not turn this into a generic architecture rewrite
- Be practical and incremental
- Keep the current system intact
- Add to it rather than replacing it
- Do real implementation, not just TODOs
- Add/update tests for meaningful behavior changes
- Keep changes understandable and tunable

If you must choose, prioritize:
1. additive modular discovery/search profiles
2. IOC-section detection and gating
3. bounded budgeted candidate selection
4. feedback-attributed memory/knowledge structure
5. clean integration path for Karpathy-loop improvement

Output format:
1. Plan
2. Implementation
3. Tests
4. Follow-up

Important:
Implement this as an additive capability layered onto existing SENTINEL, not as a takeover of the repo’s core identity or existing ingestion model.
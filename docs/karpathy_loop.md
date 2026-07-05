# Karpathy Loop

## What It Is
The Karpathy loop is SENTINEL's controlled self-improvement system. It proposes small edits to a single skill file, measures whether the change improved a real metric, keeps only positive changes, and reverts everything else.

The goal is to make the pipeline better over time without letting the model rewrite the system freely.

## What It Can Optimize
- `source`: source trust and source-handling guidance in [skills/sources/SKILL.md](/mnt/storage/nichoalas/Desktop/AGENTIC_IOC_ENRICHMENT/skills/sources/SKILL.md)
- `scoring`: severity and calibration guidance in [skills/mitre/SKILL.md](/mnt/storage/nichoalas/Desktop/AGENTIC_IOC_ENRICHMENT/skills/mitre/SKILL.md)
- `detection`: detection template guidance in [skills/detection/SKILL.md](/mnt/storage/nichoalas/Desktop/AGENTIC_IOC_ENRICHMENT/skills/detection/SKILL.md)

## How It Works
1. Load the current target skill file.
2. Build a prompt with the loop type, experiment number, current skill text, and recent experiment history.
3. Ask the configured LLM provider for JSON with:
   - `description`
   - `patch`
   - `section`
   - `reasoning`
4. Validate that exactly one existing skill section is being changed.
5. Apply the proposed patch to that section only.
6. Measure the loop metric before and after the change.
7. Keep the change only if `delta > 0`.
8. If the change is kept:
   - append to [skills/CHANGELOG.md](/mnt/storage/nichoalas/Desktop/AGENTIC_IOC_ENRICHMENT/skills/CHANGELOG.md)
   - create a git commit
   - log the experiment in `experiment_logs`
9. If the change is not kept:
   - revert the skill file immediately
   - still record the experiment result in `experiment_logs`

## Metrics
### Source Loop (replay evaluation)
The source loop metric is a **replay evaluation**, not a static historical ratio.
The old metric (confirmed/false_positive ratio per source) could not change when
a trust score was edited, which meant the loop could never actually learn.

The replay metric ([sentinel/loops/replay_eval.py](/mnt/storage/nichoalas/Desktop/AGENTIC_IOC_ENRICHMENT/sentinel/loops/replay_eval.py)) works like this:

1. Load the feedback-labeled IOC window (analyst verdicts = ground truth, default 14 days).
2. Recompute each labeled IOC's risk score under the trust scores **currently in
   the skill file**. The enrichment formula is linear in source trust, so the
   replayed score is exact:
   `risk_new = risk_stored + w_trust * 100 * (trust_skill - trust_stored)`.
3. Re-apply the alert threshold and score would-have-alerted against verdicts
   with F0.5 (precision-weighted; recall still counts so the loop cannot win by
   muting every source).

Editing a trust score mechanically moves this metric: raising a noisy source's
trust pushes its false positives back above the alert threshold (metric drops);
lowering it suppresses them (metric rises) unless it also suppresses confirmed
threats (recall penalty).

Each experiment logs the full confusion matrix, trust table, and per-source
breakdown to `experiment_logs.details` with `eval_mode="replay"`, so every
kept/rejected decision is auditable.

### Scoring Loop
Measures correlation between `risk_score` and `analyst_verdict`.

This stays blocked until there is enough real analyst verdict coverage.

### Detection Loop
Measures the ratio of generated detection rules that were actually pushed.

This is intentionally secondary in the MVP because CrowdStrike is disabled.

## Safety Rules
- One skill file per loop run
- One section per experiment
- Invalid JSON is rejected
- Missing sections are rejected
- Metric failures revert immediately
- Only positive-delta changes are kept
- Live runs require preflight readiness checks
- Live runs use an ephemeral git worktree branch under `.karpathy_runs/`

## Shadow Validation Mode
Use shadow mode to prove the loop mechanics without touching the live repo or calling the live model.

Command:
```bash
.venv/bin/python -m sentinel.cli karpathy-validate --loop source --scenario improve --max-experiments 1
```

Supported scenarios:
- `improve`
- `decline`
- `invalid-json`
- `missing-section`
- `tiny-deltas`

Shadow mode uses:
- scripted provider responses
- deterministic metrics
- disposable temp repo copies

## Live Mode
Use live mode only after the repo is committed and enough feedback exists.

Command:
```bash
.venv/bin/python -m sentinel.cli karpathy-run --loop source --max-experiments 1
```

Before a live run, SENTINEL checks:
- OpenAI key is configured
- target skill file exists
- `skills/CHANGELOG.md` exists
- git repo is present
- target skill and changelog are tracked in git
- target skill and changelog are clean
- loop-specific data sufficiency thresholds are met

If any check fails, the loop does not run.

## Current MVP Recommendation
Start with the `source` loop only.

Recommended order:
1. Run the live threat-intel pipeline.
2. Keep `telegram-listen` running.
3. Collect analyst feedback from Telegram buttons.
4. Once enough `confirmed` and `false_positive` verdicts exist across at least two sources, run one bounded `source` loop experiment.
5. Review the branch/worktree output manually before merging anything.

## Why This Matters
This is the part of SENTINEL that turns it from a static IOC pipeline into a measurable learning system. The value is not that the model edits text; the value is that each change is constrained, scored, audited, and only retained when it improves a real operational signal.

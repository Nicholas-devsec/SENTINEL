from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.alert_policy import build_alert_policy
from sentinel.config import SentinelSettings
from sentinel.db.models import IOC, FeedbackRecord
from sentinel.loops.replay_eval import ReplayEvaluator, parse_trust_scores


NOW = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)


SKILL_TEMPLATE = """---
version: 1.0.0
---

# Sources Skill

## Trust Scores
- threatfox: 0.94
- otx: {otx_trust}
"""


@pytest.fixture
def skill_path(tmp_path: Path) -> Path:
    path = tmp_path / "SKILL.md"
    path.write_text(SKILL_TEMPLATE.format(otx_trust="0.90"), encoding="utf-8")
    return path


async def seed_labeled_data(db_session_factory) -> None:
    rows = [
        # Confirmed threats from threatfox, well above the 70 threshold.
        ("threatfox", 0.94, 85.0, "confirmed"),
        ("threatfox", 0.94, 80.0, "confirmed"),
        # otx false positives that alerted at ingest trust 0.90.
        ("otx", 0.90, 71.0, "false_positive"),
        ("otx", 0.90, 70.5, "false_positive"),
    ]
    async with db_session_factory() as session:
        for index, (source, trust, risk, verdict) in enumerate(rows):
            ioc = IOC(
                value=f"indicator-{index}.test",
                dedupe_hash=f"hash-{index}",
                type="domain",
                source=source,
                source_trust=trust,
                first_seen=NOW,
                last_seen=NOW,
                risk_score=risk,
            )
            session.add(ioc)
            await session.flush()
            session.add(
                FeedbackRecord(
                    ioc_id=ioc.id,
                    analyst_id="analyst-1",
                    verdict=verdict,
                    timestamp=NOW,
                    channel="telegram",
                    source=source,
                )
            )
        await session.commit()


def build_evaluator(db_session_factory, skill_path: Path) -> ReplayEvaluator:
    settings = SentinelSettings.model_validate(
        {
            "thresholds": {"alert_score": 35},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )
    return ReplayEvaluator(
        session_factory=db_session_factory,
        skill_path=skill_path,
        alert_policy=build_alert_policy(settings),
        trust_weight=0.20,
        now_fn=lambda: NOW,
    )


def test_parse_trust_scores(skill_path: Path) -> None:
    scores = parse_trust_scores(skill_path.read_text(encoding="utf-8"))
    assert scores == {"threatfox": 0.94, "otx": 0.90}


@pytest.mark.asyncio
async def test_replay_metric_changes_when_trust_changes(db_session_factory, skill_path: Path) -> None:
    """End-to-end over the real SQL path: editing the skill file moves the metric."""
    await seed_labeled_data(db_session_factory)
    evaluator = build_evaluator(db_session_factory, skill_path)

    baseline = await evaluator.evaluate()
    # Both otx FPs replay above the threshold: tp=2 fp=2 -> F0.5 = 0.5556
    assert baseline.true_positive == 2
    assert baseline.false_positive == 2
    assert baseline.metric == pytest.approx(0.5556, abs=1e-3)

    skill_path.write_text(SKILL_TEMPLATE.format(otx_trust="0.80"), encoding="utf-8")
    improved = await evaluator.evaluate()
    # otx risk drops by 0.20*100*0.10 = 2.0 points: both FPs suppressed.
    assert improved.false_positive == 0
    assert improved.true_negative == 2
    assert improved.metric == pytest.approx(1.0)
    assert improved.metric > baseline.metric

    # Raising trust of the noisy source degrades the metric symmetrically.
    skill_path.write_text(SKILL_TEMPLATE.format(otx_trust="0.95"), encoding="utf-8")
    degraded = await evaluator.evaluate()
    assert degraded.false_positive == 2
    assert degraded.metric == pytest.approx(baseline.metric)


@pytest.mark.asyncio
async def test_replay_penalizes_suppressing_confirmed_threats(db_session_factory, skill_path: Path) -> None:
    """Recall keeps the loop from winning by muting a source that finds real threats."""
    async with db_session_factory() as session:
        ioc = IOC(
            value="real-threat.test",
            dedupe_hash="hash-real",
            type="domain",
            source="threatfox",
            source_trust=0.94,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=71.0,
        )
        session.add(ioc)
        await session.flush()
        session.add(
            FeedbackRecord(
                ioc_id=ioc.id,
                analyst_id="analyst-1",
                verdict="confirmed",
                timestamp=NOW,
                channel="telegram",
                source="threatfox",
            )
        )
        await session.commit()
    evaluator = build_evaluator(db_session_factory, skill_path)

    baseline = await evaluator.evaluate()
    assert baseline.metric == pytest.approx(1.0)

    # Cratering threatfox trust suppresses the confirmed threat -> recall drops to 0.
    content = skill_path.read_text(encoding="utf-8").replace("- threatfox: 0.94", "- threatfox: 0.80")
    skill_path.write_text(content, encoding="utf-8")
    degraded = await evaluator.evaluate()
    assert degraded.false_negative == 1
    assert degraded.metric == 0.0


@pytest.mark.asyncio
async def test_replay_uses_latest_verdict_per_ioc(db_session_factory, skill_path: Path) -> None:
    async with db_session_factory() as session:
        ioc = IOC(
            value="retriaged.test",
            dedupe_hash="hash-retriaged",
            type="domain",
            source="otx",
            source_trust=0.90,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=90.0,
        )
        session.add(ioc)
        await session.flush()
        session.add(
            FeedbackRecord(
                ioc_id=ioc.id,
                analyst_id="analyst-1",
                verdict="false_positive",
                timestamp=datetime(2026, 6, 29, 12, 0, tzinfo=UTC),
                channel="telegram",
            )
        )
        session.add(
            FeedbackRecord(
                ioc_id=ioc.id,
                analyst_id="analyst-2",
                verdict="confirmed",
                timestamp=datetime(2026, 6, 30, 9, 0, tzinfo=UTC),
                channel="telegram",
            )
        )
        await session.commit()
    evaluator = build_evaluator(db_session_factory, skill_path)

    result = await evaluator.evaluate()

    assert result.total_labeled == 1
    assert result.true_positive == 1
    assert result.false_positive == 0


@pytest.mark.asyncio
async def test_replay_prefers_feedback_source_snapshot_over_current_ioc_source(db_session_factory, skill_path: Path) -> None:
    async with db_session_factory() as session:
        ioc = IOC(
            value="source-snapshot.test",
            dedupe_hash="hash-source-snapshot",
            type="domain",
            source="threatfox",
            source_trust=0.90,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=71.0,
        )
        session.add(ioc)
        await session.flush()
        session.add(
            FeedbackRecord(
                ioc_id=ioc.id,
                analyst_id="analyst-1",
                verdict="false_positive",
                timestamp=NOW,
                channel="telegram",
                source="otx",
            )
        )
        ioc.source = "threatfox"
        await session.commit()
    skill_path.write_text(SKILL_TEMPLATE.format(otx_trust="0.80"), encoding="utf-8")
    evaluator = build_evaluator(db_session_factory, skill_path)

    result = await evaluator.evaluate()

    assert "otx" in result.per_source
    assert "threatfox" not in result.per_source
    assert result.true_negative == 1

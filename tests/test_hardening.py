"""Tests for the production-hardening layer.

Covers the alert ledger (cross-run alert dedup), explainable score
breakdowns, defanged Telegram rendering, the deterministic replay trust
sweep, the labeled-sample keep gate, and the pipeline run ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.enricher import EnrichmentAgent
from sentinel.config import SentinelSettings
from sentinel.db.models import IOC, AlertEvent, FeedbackRecord, PipelineRun
from sentinel.delivery.telegram_bot import defang, format_alert_message
from sentinel.loops.replay_eval import ReplayEvaluator
from sentinel.loops.source_loop import SourceQualityLoop
from sentinel.alert_policy import build_alert_policy


NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "thresholds": {"alert_score": 55},
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "12345",
                "alert_resend_after_hours": 72,
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )


class FakeTelegramBot:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def send_message(self, **kwargs) -> None:
        self.messages.append(kwargs)


# --- defanged display ---------------------------------------------------------


def test_defang_never_leaves_live_links() -> None:
    assert defang("evil.example", "domain") == "evil[.]example"
    assert defang("94.154.43.12", "ipv4") == "94[.]154[.]43[.]12"
    assert defang("https://evil.example/payload.exe", "url") == "hxxps://evil[.]example/payload.exe"
    # Inert types pass through untouched.
    assert defang("a" * 64, "sha256") == "a" * 64
    assert defang("CVE-2026-1234", "cve") == "CVE-2026-1234"


def test_defang_is_stable_for_already_defanged_input() -> None:
    assert defang("evil[.]example", "domain") == "evil[.]example"
    assert defang("hxxps://evil[.]example/x", "url") == "hxxps://evil[.]example/x"


# --- explainable scoring ------------------------------------------------------


def test_score_components_sum_to_risk_score() -> None:
    agent = EnrichmentAgent.__new__(EnrichmentAgent)  # skip network client setup
    weights = {
        "vt_ratio": 0.20,
        "abuse_confidence": 0.20,
        "source_trust": 0.05,
        "recency": 0.05,
        "context": 0.30,
        "corroboration": 0.20,
    }
    components = agent.score_components(
        weights=weights,
        vt_ratio=0.5,
        abuse_confidence=80,
        source_trust=0.9,
        recency_score=1.0,
        context_score=1.0,
        corroboration=0.5,
    )
    assert components["vt_ratio"] == pytest.approx(10.0)
    assert components["abuse_confidence"] == pytest.approx(16.0)
    assert components["context"] == pytest.approx(30.0)
    assert components["corroboration"] == pytest.approx(10.0)
    total = agent._score_ioc(
        weights=weights,
        vt_ratio=0.5,
        abuse_confidence=80,
        source_trust=0.9,
        recency_score=1.0,
        context_score=1.0,
        corroboration=0.5,
    )
    assert total == pytest.approx(sum(components.values()), abs=0.01)


def test_alert_message_renders_why_this_score_from_breakdown() -> None:
    rendered = format_alert_message(
        value="evil.example",
        ioc_type="domain",
        source="discovery:example.com",
        risk_score=44.7,
        severity="medium",
        mitre_techniques=[],
        mitre_tactics=[],
        attributes={
            "score_breakdown": {
                "context": 30.0,
                "corroboration": 10.0,
                "recency": 4.7,
                "vt_ratio": 0.0,
            }
        },
    )
    assert "<b>Why this score</b>" in rendered
    assert "article context +30.0" in rendered
    assert "corroboration +10.0" in rendered
    # Zero-point components stay out of the operator's view.
    assert "VirusTotal +0.0" not in rendered


# --- alert ledger -------------------------------------------------------------


async def _seed_ioc(session_factory, *, value: str = "8.8.8.8") -> IOC:
    async with session_factory() as session:
        row = IOC(
            value=value,
            dedupe_hash=f"hash-{value}",
            type="ipv4",
            source="feed-a",
            source_trust=0.9,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=80.0,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row


@pytest.mark.asyncio
async def test_alert_ledger_suppresses_resend_within_window(db_session_factory) -> None:
    row = await _seed_ioc(db_session_factory)
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=db_session_factory,
    )
    item = {
        "id": str(row.id),
        "value": row.value,
        "type": row.type,
        "source": row.source,
        "risk_score": 80.0,
        "severity": "high",
        "mitre_techniques": [],
        "mitre_tactics": [],
        "last_seen": datetime.now(UTC),
    }

    first = await agent.run([item])
    assert first.immediate_alerts == 1
    assert len(telegram_bot.messages) == 1

    # Same IOC on the next cron run: ledger suppresses the duplicate alert.
    second = await agent.run([item])
    assert second.immediate_alerts == 0
    assert len(telegram_bot.messages) == 1

    async with db_session_factory() as session:
        from sqlalchemy import select

        events = list((await session.scalars(select(AlertEvent))).all())
    assert len(events) == 1
    assert events[0].alert_kind == "immediate"
    assert str(events[0].ioc_id) == str(row.id)


@pytest.mark.asyncio
async def test_alert_ledger_excludes_already_alerted_from_digest(db_session_factory) -> None:
    row = await _seed_ioc(db_session_factory, value="9.9.9.9")
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=db_session_factory,
    )
    async with db_session_factory() as session:
        session.add(
            AlertEvent(
                ioc_id=row.id,
                channel="telegram",
                alert_kind="immediate",
                sent_at=datetime.now(UTC) - timedelta(hours=2),
            )
        )
        await session.commit()

    item = {
        "id": str(row.id),
        "value": row.value,
        "type": row.type,
        "source": row.source,
        "risk_score": 80.0,
        "severity": "high",
        "mitre_techniques": [],
        "mitre_tactics": [],
        "last_seen": datetime.now(UTC),
    }
    response = await agent.daily_digest([item])
    assert response["count"] == 0


# --- deterministic replay trust sweep ----------------------------------------


SKILL_TEMPLATE = """---
version: 1.0.0
---

# Sources Skill

## Trust Scores
- threatfox: 0.94
- otx: 0.90
"""


@pytest.mark.asyncio
async def test_replay_sweep_finds_grid_optimum(db_session_factory, tmp_path: Path) -> None:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(SKILL_TEMPLATE, encoding="utf-8")
    async with db_session_factory() as session:
        rows = [
            ("threatfox", 0.94, 85.0, "confirmed"),
            ("threatfox", 0.94, 80.0, "confirmed"),
            ("otx", 0.90, 71.0, "false_positive"),
            ("otx", 0.90, 70.5, "false_positive"),
        ]
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

    settings = SentinelSettings.model_validate(
        {
            "thresholds": {"alert_score": 70},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )
    evaluator = ReplayEvaluator(
        session_factory=db_session_factory,
        skill_path=skill_path,
        alert_policy=build_alert_policy(settings),
        trust_weight=0.20,
        now_fn=lambda: NOW,
    )
    sweep = await evaluator.sweep("otx", [0.80, 0.90, 0.95])
    # Lowering otx trust improves the continuous replay score by bringing the
    # noisy-source predictions closer to the analyst target of 0.0.
    assert sweep[0.80] > sweep[0.90]
    assert sweep[0.80] == pytest.approx(0.7480, abs=1e-3)
    assert max(sweep, key=sweep.get) == 0.80


# --- labeled-sample keep gate -------------------------------------------------


def _build_source_loop(tmp_path: Path) -> SourceQualityLoop:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(SKILL_TEMPLATE, encoding="utf-8")

    class NullProvider:
        async def complete(self, prompt: str) -> str:
            raise AssertionError("provider must not be called")

    return SourceQualityLoop(
        provider=NullProvider(),
        skill_path=skill_path,
        budget_minutes=1,
        settings=build_settings(),
        session_factory=lambda: None,
        target_source="otx",
    )


def test_keep_gate_rejects_tiny_labeled_windows(tmp_path: Path) -> None:
    loop = _build_source_loop(tmp_path)
    from sentinel.loops.karpathy_loop import ExperimentProposal

    proposal = ExperimentProposal(
        description="Adjust trust for otx",
        patch="trust_score: otx -> 0.85",
        section="Trust Scores",
        reasoning="test",
        source_name="otx",
        new_trust=0.85,
    )
    decision = loop.decide_keep(
        proposal=proposal,
        metric_before=0.50,
        metric_after=0.70,
        eval_details_before={"total_labeled": 4, "confusion": {"tp": 1, "fp": 1}},
        eval_details_after={"total_labeled": 4, "confusion": {"tp": 1, "fp": 0}},
    )
    assert decision.kept is False
    assert decision.reason.startswith("insufficient_labeled_data")


def test_keep_gate_allows_adequate_labeled_windows(tmp_path: Path) -> None:
    loop = _build_source_loop(tmp_path)
    from sentinel.loops.karpathy_loop import ExperimentProposal

    proposal = ExperimentProposal(
        description="Adjust trust for otx",
        patch="trust_score: otx -> 0.85",
        section="Trust Scores",
        reasoning="test",
        source_name="otx",
        new_trust=0.85,
    )
    decision = loop.decide_keep(
        proposal=proposal,
        metric_before=0.50,
        metric_after=0.70,
        eval_details_before={"total_labeled": 40, "confusion": {"tp": 10, "fp": 10}},
        eval_details_after={"total_labeled": 40, "confusion": {"tp": 10, "fp": 2}},
    )
    assert decision.kept is True


# --- pipeline run ledger ------------------------------------------------------


@pytest.mark.asyncio
async def test_pipeline_run_ledger_records_success(db_session_factory, monkeypatch) -> None:
    from sentinel import pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "AsyncSessionFactory", db_session_factory)
    run_id = await pipeline_module._start_pipeline_run()
    assert run_id is not None
    result = pipeline_module.PipelineResult(
        scraped=10,
        validated=8,
        enriched=8,
        scored=8,
        generated=1,
        immediate_alerts=2,
        digest_candidates=4,
        stage_durations={"total": 12.3},
    )
    await pipeline_module._finish_pipeline_run(run_id, status="succeeded", result=result)

    async with db_session_factory() as session:
        row = await session.get(PipelineRun, run_id)
    assert row is not None
    assert row.status == "succeeded"
    assert row.finished_at is not None
    assert row.counts["scraped"] == 10
    assert row.counts["immediate_alerts"] == 2
    assert row.stage_durations["total"] == 12.3


@pytest.mark.asyncio
async def test_ops_status_reports_runs_alerts_and_feedback(db_session_factory) -> None:
    from sentinel.runtime import collect_ops_status, format_ops_status

    row = await _seed_ioc(db_session_factory, value="7.7.7.7")
    async with db_session_factory() as session:
        session.add(
            PipelineRun(
                started_at=datetime.now(UTC) - timedelta(minutes=10),
                finished_at=datetime.now(UTC),
                status="succeeded",
                counts={"scraped": 5, "validated": 4, "immediate_alerts": 1, "digest_candidates": 2},
                stage_durations={"total": 33.1},
            )
        )
        session.add(
            AlertEvent(
                ioc_id=row.id,
                channel="telegram",
                alert_kind="immediate",
                sent_at=datetime.now(UTC) - timedelta(hours=1),
            )
        )
        session.add(
            FeedbackRecord(
                ioc_id=row.id,
                analyst_id="analyst-1",
                verdict="false_positive",
                timestamp=datetime.now(UTC) - timedelta(days=1),
                channel="telegram",
                source="feed-a",
            )
        )
        await session.commit()

    report = await collect_ops_status(session_factory=db_session_factory)
    assert report.alerts_24h == {"immediate": 1}
    assert report.feedback_7d == {"false_positive": 1}
    assert len(report.pipeline_runs) == 1
    rendered = format_ops_status(report)
    assert "status=succeeded" in rendered
    assert "immediate=1" in rendered
    assert "false_positive=1" in rendered

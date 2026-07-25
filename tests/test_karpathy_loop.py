from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from git import Repo

from sentinel.config import SentinelSettings
from sentinel.loops.detection_loop import DetectionEffectivenessLoop
from sentinel.loops.source_loop import SourceQualityLoop


class FakeProvider:
    def __init__(self, responses: list[dict]) -> None:
        self.responses = list(responses)

    async def complete(self, prompt: str) -> str:
        if not self.responses:
            raise RuntimeError("No more provider responses")
        return json.dumps(self.responses.pop(0))


class FakeSession:
    def __init__(self, *, experiment_logs=None, feedback_rows=None, labeled_rows=None) -> None:
        self.experiment_logs = experiment_logs if experiment_logs is not None else []
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        if labeled_rows is not None:
            self.labeled_rows = labeled_rows

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakeSessionFactory:
    def __init__(self, *, feedback_rows=None, labeled_rows=None) -> None:
        self.experiment_logs: list[dict] = []
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        self.labeled_rows = labeled_rows

    def __call__(self) -> FakeSession:
        return FakeSession(
            experiment_logs=self.experiment_logs,
            feedback_rows=self.feedback_rows,
            labeled_rows=self.labeled_rows,
        )


class SequencedMetric:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)

    async def __call__(self) -> float:
        if not self.values:
            raise RuntimeError("No more metric values")
        return self.values.pop(0)


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "thresholds": {
                "alert_score": 70,
                "rule_score": 50,
                "karpathy_experiments": 10,
                "karpathy_budget_mins": 1,
            },
            "git": {
                "skills_repo_path": "./skills",
                "author_name": "SENTINEL Learner",
                "author_email": "sentinel@bot",
            },
            # Pin the replay trust weight so the source-loop math below is
            # independent of the production default.
            "enrichment": {"weights": {"source_trust": 0.20}},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.fixture
def source_repo(tmp_path: Path) -> Path:
    repo_path = tmp_path / "repo"
    skills_dir = repo_path / "skills"
    skills_dir.mkdir(parents=True)
    (repo_path / "README.md").write_text("temp repo\n", encoding="utf-8")
    (skills_dir / "CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    (skills_dir / "sources.SKILL.md").write_text(
        "---\nversion: 1.0.0\nlast_updated: 2026-04-08\nupdated_by: human\n---\n\n# Sources Skill\n\n## Trust Scores\n- threatfox: 0.94\n- otx: 0.90\n\n## Learner Updates\n<!-- learner: append here -->\n",
        encoding="utf-8",
    )
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources.SKILL.md"])
    repo.index.commit("init")
    return repo_path


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo_path = tmp_path / "repo"
    skills_dir = repo_path / "skills"
    skills_dir.mkdir(parents=True)
    (repo_path / "README.md").write_text("temp repo\n", encoding="utf-8")
    (skills_dir / "CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    (skills_dir / "detection.SKILL.md").write_text(
        "---\nversion: 1.0.0\nlast_updated: 2026-04-08\nupdated_by: human\n---\n\n# Detection Skill\n\n## Templates\nold body\n\n## Learner Updates\n<!-- learner: append here -->\n",
        encoding="utf-8",
    )
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/detection.SKILL.md"])
    repo.index.commit("init")
    return repo_path


@pytest.mark.asyncio
async def test_karpathy_loop_keeps_improved_patch_and_logs_commit(temp_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "description": "Improve template specificity",
                "patch": "new body with tighter rules",
                "section": "Templates",
                "reasoning": "should improve hit rate",
            }
        ]
    )
    metrics = SequencedMetric([0.40, 0.52])
    sessions = FakeSessionFactory()
    loop = DetectionEffectivenessLoop(
        provider=provider,
        skill_path=temp_repo / "skills/detection.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=sessions,
        repo_path=temp_repo,
        changelog_path=str(temp_repo / "skills/CHANGELOG.md"),
        metric_override=metrics,
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    )

    outcomes = await loop.optimize(max_experiments=1)

    assert len(outcomes) == 1
    assert outcomes[0].kept is True
    assert "new body with tighter rules" in (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8")
    assert sessions.experiment_logs[0]["kept"] is True
    assert "loop=detection" in (temp_repo / "skills/CHANGELOG.md").read_text(encoding="utf-8")
    assert Repo(temp_repo).head.commit.message.startswith("karpathy:")


@pytest.mark.asyncio
async def test_karpathy_loop_reverts_failed_patch_and_stops_after_three_small_deltas(temp_repo: Path) -> None:
    provider = FakeProvider(
        [
            {"description": "Attempt 1", "patch": "trial one", "section": "Templates", "reasoning": "r1"},
            {"description": "Attempt 2", "patch": "trial two", "section": "Templates", "reasoning": "r2"},
            {"description": "Attempt 3", "patch": "trial three", "section": "Templates", "reasoning": "r3"},
        ]
    )
    metrics = SequencedMetric([0.50, 0.5004, 0.50, 0.5002, 0.50, 0.5001])
    sessions = FakeSessionFactory()
    original = (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8")
    loop = DetectionEffectivenessLoop(
        provider=provider,
        skill_path=temp_repo / "skills/detection.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=sessions,
        repo_path=temp_repo,
        changelog_path=str(temp_repo / "skills/CHANGELOG.md"),
        metric_override=metrics,
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    )

    outcomes = await loop.optimize(max_experiments=10)

    assert len(outcomes) == 3
    # Deltas below karpathy.min_keep_delta are noise: every patch is reverted
    # and the loop stops after three consecutive negligible deltas.
    assert not any(outcome.kept for outcome in outcomes)
    assert (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8") == original
    assert len(sessions.experiment_logs) == 3


@pytest.mark.asyncio
async def test_karpathy_loop_reverts_when_metric_declines(temp_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "description": "Bad change",
                "patch": "worse body",
                "section": "Templates",
                "reasoning": "should not help",
            }
        ]
    )
    metrics = SequencedMetric([0.60, 0.55])
    sessions = FakeSessionFactory()
    original = (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8")
    loop = DetectionEffectivenessLoop(
        provider=provider,
        skill_path=temp_repo / "skills/detection.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=sessions,
        repo_path=temp_repo,
        changelog_path=str(temp_repo / "skills/CHANGELOG.md"),
        metric_override=metrics,
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    )

    outcomes = await loop.optimize(max_experiments=1)

    assert outcomes[0].kept is False
    assert (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8") == original
    assert sessions.experiment_logs[0]["kept"] is False


@pytest.mark.asyncio
async def test_karpathy_loop_rejects_invalid_provider_json_without_mutating_skill(temp_repo: Path) -> None:
    class BrokenProvider:
        async def complete(self, prompt: str) -> str:
            return "not-json"

    original = (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8")
    loop = DetectionEffectivenessLoop(
        provider=BrokenProvider(),
        skill_path=temp_repo / "skills/detection.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(),
        repo_path=temp_repo,
        changelog_path=str(temp_repo / "skills/CHANGELOG.md"),
        metric_override=SequencedMetric([0.50]),
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="invalid JSON"):
        await loop.optimize(max_experiments=1)

    assert (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_karpathy_loop_rejects_missing_section_without_mutating_skill(temp_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "description": "Bad section",
                "patch": "body",
                "section": "Missing Section",
                "reasoning": "Should fail",
            }
        ]
    )
    original = (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8")
    loop = DetectionEffectivenessLoop(
        provider=provider,
        skill_path=temp_repo / "skills/detection.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(),
        repo_path=temp_repo,
        changelog_path=str(temp_repo / "skills/CHANGELOG.md"),
        metric_override=SequencedMetric([0.50]),
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="not found"):
        await loop.optimize(max_experiments=1)

    assert (temp_repo / "skills/detection.SKILL.md").read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_source_loop_replay_metric_responds_to_trust_changes(source_repo: Path) -> None:
    """The live metric must move when the skill file's trust score is edited.

    Labeled data: otx contributed two false positives that scored just above the
    alert threshold (70) at trust 0.90. Lowering otx trust in the skill file
    should suppress those FP alerts (risk drops by w_trust*100*delta) and raise
    the replayed F0.5 — the exact mechanism the loop optimizes.
    """
    labeled_rows = [
        # threatfox: real threats, comfortably above threshold.
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 85.0, "verdict": "confirmed"},
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 80.0, "verdict": "confirmed"},
        # otx: noisy false positives barely above the threshold at ingest trust.
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 71.0, "verdict": "false_positive"},
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 70.5, "verdict": "false_positive"},
    ]
    skill_path = source_repo / "skills/sources.SKILL.md"
    loop = SourceQualityLoop(
        provider=FakeProvider([]),
        skill_path=skill_path,
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=[], labeled_rows=labeled_rows),
        repo_path=source_repo,
        changelog_path=str(source_repo / "skills/CHANGELOG.md"),
        target_source="threatfox",
    )

    # Skill trust matches stored trust: both otx FPs still alert.
    # tp=2 fp=2 fn=0 -> precision 0.5, recall 1.0, F0.5 = 0.5556
    metric_before = await loop.measure_metric()
    assert metric_before == pytest.approx(0.5556, abs=1e-3)

    # Lower otx trust by 0.05: replayed risk drops by 0.20*100*0.05 = 1.0 point.
    content = skill_path.read_text(encoding="utf-8").replace("- otx: 0.90", "- otx: 0.85")
    skill_path.write_text(content, encoding="utf-8")

    # risk 71.0 -> 70.0 (still >= threshold, alerts), 70.5 -> 69.5 (suppressed): fp=1
    metric_middle = await loop.measure_metric()
    assert metric_middle > metric_before

    content = skill_path.read_text(encoding="utf-8").replace("- otx: 0.85", "- otx: 0.80")
    skill_path.write_text(content, encoding="utf-8")

    # risk 71.0 -> 69.0, 70.5 -> 68.5: both FPs suppressed, precision 1.0.
    metric_after = await loop.measure_metric()
    assert metric_after == pytest.approx(1.0)
    assert metric_after > metric_middle

    # Audit details captured for the experiment log.
    assert loop._last_eval_details["confusion"]["fp"] == 0
    assert loop._last_eval_details["trust_scores"]["otx"] == 0.80


@pytest.mark.asyncio
async def test_source_loop_replay_counts_low_level_true_positive_as_weighted_positive(source_repo: Path) -> None:
    skill_path = source_repo / "skills/sources.SKILL.md"
    skill_path.write_text(
        skill_path.read_text(encoding="utf-8").replace("- threatfox: 0.94", "- threatfox: 0.90"),
        encoding="utf-8",
    )
    labeled_rows = [
        {"source": "threatfox", "source_trust_stored": 0.90, "risk_score_stored": 85.0, "verdict": "confirmed"},
        {
            "source": "threatfox",
            "source_trust_stored": 0.90,
            "risk_score_stored": 69.5,
            "verdict": "low_level_true_positive",
        },
    ]
    loop = SourceQualityLoop(
        provider=FakeProvider([]),
        skill_path=skill_path,
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=[], labeled_rows=labeled_rows),
        repo_path=source_repo,
        changelog_path=str(source_repo / "skills/CHANGELOG.md"),
        target_source="threatfox",
    )

    metric_before = await loop.measure_metric()
    assert metric_before == pytest.approx(0.9091, abs=1e-3)
    assert loop._last_eval_details["confusion"]["fn"] == pytest.approx(0.5)

    skill_path.write_text(
        skill_path.read_text(encoding="utf-8").replace("- threatfox: 0.90", "- threatfox: 0.94"),
        encoding="utf-8",
    )

    metric_after = await loop.measure_metric()
    assert metric_after == pytest.approx(1.0)
    assert loop._last_eval_details["confusion"]["tp"] == pytest.approx(1.5)


@pytest.mark.asyncio
async def test_source_loop_rejects_wrong_target_source(source_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "source_name": "otx",
                "new_trust": 0.88,
                "reasoning": "Bad target",
                "expected_effect": "Should fail",
            }
        ]
    )
    loop = SourceQualityLoop(
        provider=provider,
        skill_path=source_repo / "skills/sources.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=[]),
        repo_path=source_repo,
        changelog_path=str(source_repo / "skills/CHANGELOG.md"),
        metric_override=SequencedMetric([0.5]),
        target_source="threatfox",
    )

    with pytest.raises(ValueError, match="must target 'threatfox'"):
        await loop.optimize(max_experiments=1)


@pytest.mark.asyncio
async def test_source_loop_rejects_out_of_bounds_trust_delta(source_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "source_name": "threatfox",
                "new_trust": 0.50,
                "reasoning": "Too large delta",
                "expected_effect": "Should fail",
            }
        ]
    )
    loop = SourceQualityLoop(
        provider=provider,
        skill_path=source_repo / "skills/sources.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=[]),
        repo_path=source_repo,
        changelog_path=str(source_repo / "skills/CHANGELOG.md"),
        metric_override=SequencedMetric([0.5]),
        target_source="threatfox",
    )

    with pytest.raises(ValueError, match=r"\+/- 0.05"):
        await loop.optimize(max_experiments=1)


@pytest.mark.asyncio
async def test_source_loop_keeps_positive_delta_and_records_trust_shift(source_repo: Path) -> None:
    provider = FakeProvider(
        [
            {
                "source_name": "threatfox",
                "new_trust": 0.90,
                "reasoning": "Reduce noisy source weight",
                "expected_effect": "Improve source precision",
            }
        ]
    )
    sessions = FakeSessionFactory(feedback_rows=[])
    loop = SourceQualityLoop(
        provider=provider,
        skill_path=source_repo / "skills/sources.SKILL.md",
        budget_minutes=1,
        settings=build_settings(),
        session_factory=sessions,
        repo_path=source_repo,
        changelog_path=str(source_repo / "skills/CHANGELOG.md"),
        metric_override=SequencedMetric([0.40, 0.58]),
        now_fn=lambda: datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
        target_source="threatfox",
    )

    outcomes = await loop.optimize(max_experiments=1)

    assert outcomes[0].kept is True
    assert outcomes[0].target_source == "threatfox"
    assert outcomes[0].trust_before == 0.94
    assert outcomes[0].trust_after == 0.90
    assert "- threatfox: 0.90" in (source_repo / "skills/sources.SKILL.md").read_text(encoding="utf-8")
    assert "actor=karpathy" in (source_repo / "skills/CHANGELOG.md").read_text(encoding="utf-8")

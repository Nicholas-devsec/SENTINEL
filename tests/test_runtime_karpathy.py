from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from git import Repo

from sentinel.config import SentinelSettings
from sentinel.runtime import (
    LOOP_SKILL_PATHS,
    build_karpathy_loop,
    format_karpathy_status,
    inspect_karpathy_status,
    inspect_live_karpathy_readiness,
    prepare_ephemeral_loop_workspace,
    run_live_karpathy_loop,
    run_shadow_karpathy_validation,
)


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "openai": {
                "api_key": "openai-key",
                "model": "gpt-5.4",
                "base_url": "https://api.openai.com/v1",
            },
            "git": {
                "skills_repo_path": "./skills",
                "author_name": "SENTINEL Learner",
                "author_email": "sentinel@bot",
            },
            "db": {
                "url": "sqlite+aiosqlite:///:memory:",
                "redis_url": "disabled",
            },
        }
    )


class FakeSession:
    def __init__(self, *, feedback_rows=None, iocs=None, experiment_logs=None, leases=None, labeled_rows=None) -> None:
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        self.iocs = iocs if iocs is not None else []
        self.experiment_logs = experiment_logs if experiment_logs is not None else []
        self.leases = leases if leases is not None else {}
        self.labeled_rows = labeled_rows if labeled_rows is not None else []

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakeSessionFactory:
    def __init__(self, *, feedback_rows=None, iocs=None, experiment_logs=None, leases=None, labeled_rows=None) -> None:
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        self.iocs = iocs if iocs is not None else []
        self.experiment_logs = experiment_logs if experiment_logs is not None else []
        self.leases = leases if leases is not None else {}
        self.labeled_rows = labeled_rows if labeled_rows is not None else []

    def __call__(self) -> FakeSession:
        return FakeSession(
            feedback_rows=self.feedback_rows,
            iocs=self.iocs,
            experiment_logs=self.experiment_logs,
            leases=self.leases,
            labeled_rows=self.labeled_rows,
        )


@dataclass
class FakeIOC:
    analyst_verdict: str | None = None
    sigma_rule: str | None = None


@pytest.mark.asyncio
async def test_shadow_validation_keeps_improved_patch_and_commits() -> None:
    report = await run_shadow_karpathy_validation(
        loop_type="source",
        settings=build_settings(),
        scenario="improve",
        max_experiments=1,
    )

    assert report.mode == "shadow"
    assert report.kept == 1
    assert report.reverted == 0
    assert report.commit_hashes
    assert report.affected_sections == ["Trust Scores"]


@pytest.mark.asyncio
async def test_shadow_validation_reports_invalid_json_without_commit() -> None:
    report = await run_shadow_karpathy_validation(
        loop_type="source",
        settings=build_settings(),
        scenario="invalid-json",
        max_experiments=1,
    )

    assert report.error is not None
    assert "invalid JSON" in report.error
    assert report.commit_hashes == []


@pytest.mark.asyncio
async def test_live_preflight_blocks_source_loop_without_feedback(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path = repo_path / "skills/CHANGELOG.md"
    changelog_path.write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text(
        "---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\nbody\n",
        encoding="utf-8",
    )
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    report = await inspect_live_karpathy_readiness(
        loop_type="source",
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=[]),
    )

    assert report.ready is False
    assert report.counts["feedback_rows"] == 0
    assert any(check.name == "feedback_window" and not check.passed for check in report.checks)


@pytest.mark.asyncio
async def test_live_preflight_selects_source_with_best_replay_headroom(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path = repo_path / "skills/CHANGELOG.md"
    changelog_path.write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text(
        "---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n- otx: 0.90\n",
        encoding="utf-8",
    )
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    feedback_rows = [
        {"source": "threatfox", "verdict": "false_positive"},
        {"source": "threatfox", "verdict": "false_positive"},
        {"source": "threatfox", "verdict": "false_positive"},
        {"source": "threatfox", "verdict": "confirmed"},
        {"source": "threatfox", "verdict": "confirmed"},
        {"source": "otx", "verdict": "false_positive"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
    ]
    labeled_rows = [
        # threatfox rows are far from their verdict targets, but a +/-0.05 trust
        # sweep barely changes their calibration.
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 24.0, "verdict": "false_positive"},
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 23.5, "verdict": "false_positive"},
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 23.0, "verdict": "false_positive"},
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 52.0, "verdict": "confirmed"},
        {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 50.0, "verdict": "confirmed"},
        # otx sits closer to the middle, so a bounded trust move has more
        # measurable uplift under the continuous replay score.
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 41.0, "verdict": "false_positive"},
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 42.0, "verdict": "confirmed"},
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 43.0, "verdict": "confirmed"},
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 44.0, "verdict": "confirmed"},
        {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 45.0, "verdict": "confirmed"},
    ]

    report = await inspect_live_karpathy_readiness(
        loop_type="source",
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=feedback_rows, labeled_rows=labeled_rows),
    )

    assert report.ready is True
    assert report.target_source == "otx"
    assert report.counts["target_source_feedback_rows"] == 5
    assert report.counts["target_source_headroom_bp"] > 0


@pytest.mark.asyncio
async def test_live_preflight_treats_low_level_true_positive_as_positive_feedback(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path = repo_path / "skills/CHANGELOG.md"
    changelog_path.write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text(
        "---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n- otx: 0.90\n",
        encoding="utf-8",
    )
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    feedback_rows = [
        {"source": "threatfox", "verdict": "false_positive"},
        {"source": "threatfox", "verdict": "false_positive"},
        {"source": "threatfox", "verdict": "low_level_true_positive"},
        {"source": "threatfox", "verdict": "low_level_true_positive"},
        {"source": "threatfox", "verdict": "low_level_true_positive"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "false_positive"},
    ]

    report = await inspect_live_karpathy_readiness(
        loop_type="source",
        settings=build_settings(),
        session_factory=FakeSessionFactory(
            feedback_rows=feedback_rows,
            labeled_rows=[
                {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 41.0, "verdict": "false_positive"},
                {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 42.0, "verdict": "false_positive"},
                {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 43.0, "verdict": "low_level_true_positive"},
                {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 44.0, "verdict": "low_level_true_positive"},
                {"source": "threatfox", "source_trust_stored": 0.94, "risk_score_stored": 45.0, "verdict": "low_level_true_positive"},
                {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 10.0, "verdict": "confirmed"},
                {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 11.0, "verdict": "confirmed"},
                {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 12.0, "verdict": "confirmed"},
                {"source": "otx", "source_trust_stored": 0.90, "risk_score_stored": 13.0, "verdict": "false_positive"},
            ],
        ),
    )

    assert report.ready is True
    assert report.target_source == "threatfox"
    assert report.counts["target_source_feedback_rows"] == 5


@pytest.mark.asyncio
async def test_live_preflight_blocks_scoring_and_detection_loops() -> None:
    scoring = await inspect_live_karpathy_readiness(
        loop_type="scoring",
        settings=build_settings(),
        session_factory=FakeSessionFactory(),
    )
    detection = await inspect_live_karpathy_readiness(
        loop_type="detection",
        settings=build_settings(),
        session_factory=FakeSessionFactory(),
    )

    assert scoring.ready is False
    assert detection.ready is False
    assert any(check.name == "live_supported" and not check.passed for check in scoring.checks)
    assert any(check.name == "live_supported" and not check.passed for check in detection.checks)


def test_build_karpathy_loop_uses_mitre_skill_for_scoring(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    loop = build_karpathy_loop(loop_type="scoring", settings=build_settings(), repo_path=repo_path)
    assert loop.skill_path == repo_path / "skills/mitre/SKILL.md"


def test_prepare_ephemeral_worktree_creates_branch(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    skill_path = repo_path / "skills/sources/SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    (repo_path / "skills/CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text("# Source Skill\n\n## Trust Scores\nbody\n", encoding="utf-8")
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    branch_name, worktree_path = prepare_ephemeral_loop_workspace(loop_type="source")

    assert branch_name.startswith("karpathy-source-")
    assert worktree_path.exists()
    worktree_repo = Repo(worktree_path)
    assert worktree_repo.active_branch.name == branch_name


@pytest.mark.asyncio
async def test_live_preflight_prefers_feedback_source_snapshot(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path = repo_path / "skills/CHANGELOG.md"
    changelog_path.write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text(
        "---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n- otx: 0.90\n",
        encoding="utf-8",
    )
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    feedback_rows = [
        {"source": "otx", "verdict": "false_positive"},
        {"source": "otx", "verdict": "false_positive"},
        {"source": "otx", "verdict": "false_positive"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "otx", "verdict": "confirmed"},
        {"source": "threatfox", "verdict": "confirmed"},
        {"source": "threatfox", "verdict": "confirmed"},
    ]

    report = await inspect_live_karpathy_readiness(
        loop_type="source",
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=feedback_rows),
    )

    assert report.target_source == "otx"


@pytest.mark.asyncio
async def test_run_live_karpathy_loop_merges_and_cleans_up_worktree(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    (repo_path / "skills/CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text("---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n", encoding="utf-8")
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    readiness = await inspect_live_karpathy_readiness(
        loop_type="source",
        settings=build_settings(),
        session_factory=FakeSessionFactory(
            feedback_rows=[
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "otx", "verdict": "confirmed"},
            ]
        ),
    )
    assert readiness.ready is True

    class FakeLoop:
        def __init__(self, repo_path: Path) -> None:
            self.repo_path = repo_path

        async def optimize(self, max_experiments):
            worktree_repo = Repo(self.repo_path)
            skill_file = self.repo_path / "skills/sources/SKILL.md"
            skill_file.write_text(
                "---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.89\n",
                encoding="utf-8",
            )
            worktree_repo.index.add(["skills/sources/SKILL.md"])
            worktree_repo.index.commit("karpathy: lower threatfox trust")
            return [
                type(
                    "Outcome",
                    (),
                    {
                        "metric_before": 0.4,
                        "metric_after": 0.52,
                        "kept": True,
                        "trust_before": 0.94,
                        "trust_after": 0.89,
                    },
                )()
            ]

    monkeypatch.setattr("sentinel.runtime.build_karpathy_loop", lambda **kwargs: FakeLoop(kwargs["repo_path"]))

    loop_readiness, report = await run_live_karpathy_loop(
        loop_type="source",
        settings=build_settings(),
        max_experiments=1,
        session_factory=FakeSessionFactory(
            feedback_rows=[
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "otx", "verdict": "confirmed"},
            ]
        ),
    )

    assert loop_readiness.ready is True
    assert report is not None
    assert report.commit_hashes
    assert report.merged_commit_hashes == report.commit_hashes
    assert report.cleanup_status == "merged,worktree-removed,branch-deleted"
    assert not Path(report.worktree_path).exists()
    assert "karpathy: lower threatfox trust" in Repo(repo_path).head.commit.message


@pytest.mark.asyncio
async def test_run_live_karpathy_loop_cleans_up_after_optimize_failure(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    (repo_path / "skills/CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text("---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n", encoding="utf-8")
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    class BrokenLoop:
        async def optimize(self, max_experiments):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr("sentinel.runtime.build_karpathy_loop", lambda **kwargs: BrokenLoop())

    _, report = await run_live_karpathy_loop(
        loop_type="source",
        settings=build_settings(),
        max_experiments=1,
        session_factory=FakeSessionFactory(
            feedback_rows=[
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "false_positive"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "threatfox", "verdict": "confirmed"},
                {"source": "otx", "verdict": "confirmed"},
            ]
        ),
    )

    assert report is not None
    assert report.error == "provider unavailable"
    assert report.commit_hashes == []
    assert report.merged_commit_hashes == []
    assert report.cleanup_status == "worktree-removed,branch-deleted"
    assert not Path(report.worktree_path).exists()


@pytest.mark.asyncio
async def test_run_live_karpathy_loop_skips_when_lease_is_held(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    (repo_path / "skills/CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text("---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n", encoding="utf-8")
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    session_factory = FakeSessionFactory(
        feedback_rows=[
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "confirmed"},
            {"source": "threatfox", "verdict": "confirmed"},
            {"source": "otx", "verdict": "confirmed"},
        ],
        leases={
            "karpathy:source": {
                "lease_name": "karpathy:source",
                "holder_id": "other-host:123",
                "acquired_at": __import__("datetime").datetime.now(__import__("datetime").UTC),
                "expires_at": __import__("datetime").datetime.now(__import__("datetime").UTC) + __import__("datetime").timedelta(minutes=5),
            }
        },
    )

    _, report = await run_live_karpathy_loop(
        loop_type="source",
        settings=build_settings(),
        max_experiments=1,
        session_factory=session_factory,
    )

    assert report is not None
    assert report.error == "lease-held-by:other-host:123"
    assert report.lock_status == "lease-held-by:other-host:123"
    assert report.experiments_attempted == 0


@pytest.mark.asyncio
async def test_inspect_karpathy_status_reports_lease_and_recent_runs(monkeypatch, tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    skill_path = repo_path / LOOP_SKILL_PATHS["source"]
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    (repo_path / "skills/CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    skill_path.write_text("---\nversion: 1.0.0\n---\n\n# Source Skill\n\n## Trust Scores\n- threatfox: 0.94\n", encoding="utf-8")
    (repo_path / "README.md").write_text("repo\n", encoding="utf-8")
    repo = Repo.init(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md"])
    repo.index.commit("init")
    monkeypatch.chdir(repo_path)

    now = __import__("datetime").datetime.now(__import__("datetime").UTC)
    session_factory = FakeSessionFactory(
        feedback_rows=[
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "false_positive"},
            {"source": "threatfox", "verdict": "confirmed"},
            {"source": "threatfox", "verdict": "confirmed"},
            {"source": "otx", "verdict": "confirmed"},
        ],
        experiment_logs=[
            {
                "loop_type": "source",
                "experiment_number": 1,
                "hypothesis": "Adjust trust for threatfox",
                "patch_applied": "trust_score: threatfox -> 0.89",
                "metric_before": 0.4,
                "metric_after": 0.52,
                "delta": 0.12,
                "kept": True,
                "timestamp": now,
                "eval_mode": "replay",
                "target": "threatfox",
                "details": {"keep_decision": {"reason": "delta_and_replay_guardrails_passed"}},
            }
        ],
        leases={
            "karpathy:source": {
                "lease_name": "karpathy:source",
                "holder_id": "host:lease",
                "acquired_at": now,
                "expires_at": now + __import__("datetime").timedelta(minutes=5),
            }
        },
    )

    report = await inspect_karpathy_status(
        loop_type="source",
        settings=build_settings(),
        session_factory=session_factory,
    )

    rendered = format_karpathy_status(report)
    assert report.active_lease is not None
    assert report.recent_runs
    assert "Active lease: name=karpathy:source holder=host:lease" in rendered
    assert "reason=delta_and_replay_guardrails_passed" in rendered

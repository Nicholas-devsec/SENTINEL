from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from git import Repo

from sentinel.config import SentinelSettings
from sentinel.runtime import (
    LOOP_SKILL_PATHS,
    build_karpathy_loop,
    inspect_live_karpathy_readiness,
    prepare_ephemeral_loop_workspace,
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
            "crowdstrike": {
                "enabled": False,
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
    def __init__(self, *, feedback_rows=None, iocs=None) -> None:
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        self.iocs = iocs if iocs is not None else []

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakeSessionFactory:
    def __init__(self, *, feedback_rows=None, iocs=None) -> None:
        self.feedback_rows = feedback_rows if feedback_rows is not None else []
        self.iocs = iocs if iocs is not None else []

    def __call__(self) -> FakeSession:
        return FakeSession(feedback_rows=self.feedback_rows, iocs=self.iocs)


@dataclass
class FakeIOC:
    analyst_verdict: str | None = None
    sigma_rule: str | None = None
    crowdstrike_pushed: bool = False


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

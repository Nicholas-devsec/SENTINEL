from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from git import Repo

from sentinel.agents.learner import LearnerAgent
from sentinel.config import SentinelSettings


class FakeSession:
    def __init__(self, *, feedback_rows, experiment_rows) -> None:
        self.feedback_rows = feedback_rows
        self.experiment_rows = experiment_rows

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class FakeSessionFactory:
    def __init__(self, *, feedback_rows, experiment_rows) -> None:
        self.feedback_rows = feedback_rows
        self.experiment_rows = experiment_rows

    def __call__(self) -> FakeSession:
        return FakeSession(feedback_rows=self.feedback_rows, experiment_rows=self.experiment_rows)


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "git": {
                "skills_repo_path": "./skills",
                "author_name": "SENTINEL Learner",
                "author_email": "sentinel@bot",
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo_path = tmp_path / "repo"
    skills_root = repo_path / "skills"
    (skills_root / "sources").mkdir(parents=True)
    (skills_root / "validation").mkdir(parents=True)
    (skills_root / "detection").mkdir(parents=True)
    Repo.init(repo_path)
    (repo_path / "README.md").write_text("temp repo\n", encoding="utf-8")
    (skills_root / "CHANGELOG.md").write_text("# Skills Changelog\n", encoding="utf-8")
    (skills_root / "sources" / "SKILL.md").write_text(
        "---\nversion: 1.0.0\nlast_updated: 2026-04-08\nupdated_by: human\n---\n\n# Sources Skill\n\n## Trust Scores\n- urlhaus: 0.91\n- feodotracker: 0.93\n\n## Learner Updates\n<!-- learner: append here -->\n",
        encoding="utf-8",
    )
    (skills_root / "validation" / "SKILL.md").write_text(
        "---\nversion: 1.0.0\nlast_updated: 2026-04-08\nupdated_by: human\n---\n\n# Validation Skill\n\n## False Positive Rules\n- Reject placeholders.\n\n## Learner Updates\n<!-- learner: append here -->\n",
        encoding="utf-8",
    )
    (skills_root / "detection" / "SKILL.md").write_text(
        "---\nversion: 1.0.0\nlast_updated: 2026-04-08\nupdated_by: human\n---\n\n# Detection Skill\n\n## Git Integration\n- traceable commits.\n\n## Learner Updates\n<!-- learner: append here -->\n",
        encoding="utf-8",
    )
    repo = Repo(repo_path)
    repo.index.add(["README.md", "skills/CHANGELOG.md", "skills/sources/SKILL.md", "skills/validation/SKILL.md", "skills/detection/SKILL.md"])
    repo.index.commit("init")
    return repo_path


@pytest.mark.asyncio
async def test_learner_reduces_source_trust_appends_patterns_and_detection_updates(temp_repo: Path) -> None:
    now = datetime(2026, 4, 8, 12, 0, tzinfo=UTC)
    feedback_rows = [
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "bad.example", "verdict": "false_positive", "timestamp": now - timedelta(hours=1)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "bad.example", "verdict": "false_positive", "timestamp": now - timedelta(hours=2)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "bad.example", "verdict": "false_positive", "timestamp": now - timedelta(hours=3)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "other.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=4)},
    ]
    experiment_rows = [
        {"loop_type": "detection", "hypothesis": "Prefer stable file naming", "delta": 0.12, "kept": True},
        {"loop_type": "scoring", "hypothesis": "Ignore", "delta": 0.50, "kept": True},
    ]
    agent = LearnerAgent(
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=feedback_rows, experiment_rows=experiment_rows),
        skills_root=str(temp_repo / "skills"),
        repo_path=str(temp_repo),
        now_fn=lambda: now,
    )

    changes = await agent.run()

    assert {change.skill_name for change in changes} == {"sources", "validation", "detection"}
    sources_text = (temp_repo / "skills/sources/SKILL.md").read_text(encoding="utf-8")
    validation_text = (temp_repo / "skills/validation/SKILL.md").read_text(encoding="utf-8")
    detection_text = (temp_repo / "skills/detection/SKILL.md").read_text(encoding="utf-8")
    changelog_text = (temp_repo / "skills/CHANGELOG.md").read_text(encoding="utf-8")
    assert "- urlhaus: 0.86" in sources_text
    assert "- pattern: bad.example" in validation_text
    assert "optimization: Prefer stable file naming" in detection_text
    assert "skill=sources" in changelog_text
    assert "skill=validation" in changelog_text
    assert "skill=detection" in changelog_text

    repo = Repo(temp_repo)
    assert repo.head.commit.message.startswith("learner:")


@pytest.mark.asyncio
async def test_learner_skips_changes_when_thresholds_not_met(temp_repo: Path) -> None:
    now = datetime(2026, 4, 8, 12, 0, tzinfo=UTC)
    feedback_rows = [
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "one.example", "verdict": "false_positive", "timestamp": now - timedelta(hours=1)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "two.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=2)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "three.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=3)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "four.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=4)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "five.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=5)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "six.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=6)},
        {"ioc_id": str(uuid4()), "source": "urlhaus", "value": "seven.example", "verdict": "confirmed", "timestamp": now - timedelta(hours=7)},
    ]
    experiment_rows = [
        {"loop_type": "detection", "hypothesis": "Not kept", "delta": 0.01, "kept": False},
    ]
    agent = LearnerAgent(
        settings=build_settings(),
        session_factory=FakeSessionFactory(feedback_rows=feedback_rows, experiment_rows=experiment_rows),
        skills_root=str(temp_repo / "skills"),
        repo_path=str(temp_repo),
        now_fn=lambda: now,
    )

    changes = await agent.run()

    assert changes == []
    assert "- urlhaus: 0.91" in (temp_repo / "skills/sources/SKILL.md").read_text(encoding="utf-8")
    assert "- pattern:" not in (temp_repo / "skills/validation/SKILL.md").read_text(encoding="utf-8")

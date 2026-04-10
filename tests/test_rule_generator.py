from __future__ import annotations

import json
from pathlib import Path

import pytest
from git import Repo

from sentinel.agents.rule_generator import RuleGeneratorAgent
from sentinel.config import SentinelSettings


class FakeCrowdStrikeClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def push_ioc(self, payload: dict) -> dict:
        self.payloads.append(payload)
        return {"resources": [{"id": payload["value"]}]}


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo = Repo.init(repo_path)
    (repo_path / "README.md").write_text("test repo\n", encoding="utf-8")
    repo.index.add(["README.md"])
    repo.index.commit("init")
    return repo_path


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "thresholds": {"rule_score": 50, "alert_score": 70, "karpathy_experiments": 25, "karpathy_budget_mins": 30},
            "crowdstrike": {
                "client_id": "client",
                "client_secret": "secret",
                "base_url": "https://api.crowdstrike.test",
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.mark.asyncio
async def test_rule_generator_renders_artifacts_pushes_crowdstrike_and_commits(temp_repo: Path) -> None:
    client = FakeCrowdStrikeClient()
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        crowdstrike_client=client,
        output_dir=str(temp_repo / "generated/detections"),
        repo_path=str(temp_repo),
    )

    results = await agent.run(
        [
            {
                "value": "8.8.8.8",
                "type": "ipv4",
                "source": "feed-a",
                "risk_score": 80,
                "severity": "high",
                "mitre_techniques": ["T1071"],
                "mitre_tactics": ["command and control"],
            },
            {
                "value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "type": "sha256",
                "source": "feed-a",
                "risk_score": 91,
                "severity": "critical",
                "mitre_techniques": ["T1059"],
                "mitre_tactics": ["execution"],
            },
        ]
    )

    assert len(results) == 2
    assert len(client.payloads) == 2
    sigma_path = temp_repo / "generated/detections/sigma/8-8-8-8.yml"
    crowdstrike_path = temp_repo / "generated/detections/crowdstrike/8-8-8-8.json"
    yara_path = temp_repo / "generated/detections/yara/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.yar"
    assert sigma_path.exists()
    assert crowdstrike_path.exists()
    assert yara_path.exists()
    assert "attack.t1071" in sigma_path.read_text(encoding="utf-8").lower()
    payload = json.loads(crowdstrike_path.read_text(encoding="utf-8"))
    assert payload["value"] == "8.8.8.8"

    repo = Repo(temp_repo)
    assert repo.head.commit.message.startswith("rules:")


@pytest.mark.asyncio
async def test_rule_generator_filters_below_threshold_and_skips_yara_for_non_hash(temp_repo: Path) -> None:
    client = FakeCrowdStrikeClient()
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        crowdstrike_client=client,
        output_dir=str(temp_repo / "generated/detections"),
        repo_path=str(temp_repo),
    )

    results = await agent.run(
        [
            {
                "value": "example.org",
                "type": "domain",
                "source": "feed-a",
                "risk_score": 49.9,
                "severity": "informational",
                "mitre_techniques": [],
                "mitre_tactics": [],
            },
            {
                "value": "https://evil.example/path",
                "type": "url",
                "source": "feed-a",
                "risk_score": 55,
                "severity": "medium",
                "mitre_techniques": ["T1566.001"],
                "mitre_tactics": ["initial access"],
            },
        ]
    )

    assert len(results) == 1
    assert results[0].yara_rule is None
    assert len(client.payloads) == 1
    assert not (temp_repo / "generated/detections/yara").exists()

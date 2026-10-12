from __future__ import annotations

from pathlib import Path

import pytest
from sentinel.agents.rule_generator import RuleGeneratorAgent
from sentinel.config import SentinelSettings


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    return tmp_path


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "thresholds": {"rule_score": 50, "alert_score": 70, "karpathy_experiments": 25, "karpathy_budget_mins": 30},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.mark.asyncio
async def test_rule_generator_renders_local_artifacts(temp_repo: Path) -> None:
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        output_dir=str(temp_repo / "generated/detections"),
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
    sigma_path = temp_repo / "generated/detections/sigma/8-8-8-8.yml"
    kql_path = temp_repo / "generated/detections/kql/8-8-8-8.kql"
    spl_path = temp_repo / "generated/detections/spl/8-8-8-8.spl"
    yara_path = temp_repo / "generated/detections/yara/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.yar"
    assert sigma_path.exists()
    assert kql_path.exists()
    assert spl_path.exists()
    assert yara_path.exists()
    assert not (temp_repo / "generated/detections/crowdstrike").exists()
    assert "attack.t1071" in sigma_path.read_text(encoding="utf-8").lower()



@pytest.mark.asyncio
async def test_rule_generator_filters_below_threshold_and_skips_yara_for_non_hash(temp_repo: Path) -> None:
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        output_dir=str(temp_repo / "generated/detections"),
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
    assert not (temp_repo / "generated/detections/yara").exists()
    assert not (temp_repo / "generated/detections/crowdstrike").exists()


@pytest.mark.asyncio
async def test_rule_generator_is_type_aware_per_platform(temp_repo: Path) -> None:
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        output_dir=str(temp_repo / "generated/detections"),
    )

    results = await agent.run(
        [
            {
                "value": "evil-c2.example.net",
                "type": "domain",
                "source": "feed-a",
                "risk_score": 80,
                "severity": "high",
                "mitre_techniques": ["T1071.004"],
                "mitre_tactics": ["command and control"],
            },
            {
                "value": "https://evil.example/path/gate.php",
                "type": "url",
                "source": "feed-a",
                "risk_score": 75,
                "severity": "high",
                "mitre_techniques": ["T1566.001"],
                "mitre_tactics": ["initial access"],
            },
            {
                "value": "203.0.114.7",
                "type": "ipv4",
                "source": "feed-a",
                "risk_score": 80,
                "severity": "high",
                "mitre_techniques": ["T1071"],
                "mitre_tactics": ["command and control"],
            },
            {
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "type": "md5",
                "source": "feed-a",
                "risk_score": 90,
                "severity": "critical",
                "mitre_techniques": ["T1059"],
                "mitre_tactics": ["execution"],
            },
        ]
    )

    by_type = {result.value: result for result in results}

    # Domain: DNS-query Sigma, not a network_connection on a hostname field.
    domain = by_type["evil-c2.example.net"]
    assert "dns_query" in domain.sigma_rule
    assert "QueryName|endswith" in domain.sigma_rule
    assert "DestinationHostname" not in domain.sigma_rule

    # URL: proxy Sigma plus URL-aware KQL and SPL.
    url = by_type["https://evil.example/path/gate.php"]
    assert "proxy" in url.sigma_rule
    assert "c-uri|contains" in url.sigma_rule
    assert "RemoteUrl startswith" in url.kql_query
    assert 'url="https://evil.example/path/gate.php*"' in url.spl_query

    # IP: network_connection with DestinationIp.
    ip = by_type["203.0.114.7"]
    assert "network_connection" in ip.sigma_rule
    assert 'DestinationIp: "203.0.114.7"' in ip.sigma_rule
    assert 'RemoteIP == "203.0.114.7"' in ip.kql_query

    # Hash: process_creation Sigma with algo-prefixed Hashes match, KQL against the
    # right column, YARA via the hash module instead of matching the hex string.
    md5 = by_type["d41d8cd98f00b204e9800998ecf8427e"]
    assert "process_creation" in md5.sigma_rule
    assert "MD5=d41d8cd98f00b204e9800998ecf8427e" in md5.sigma_rule
    assert "MD5 ==" in md5.kql_query
    assert md5.yara_rule is not None
    assert 'import "hash"' in md5.yara_rule
    assert 'hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"' in md5.yara_rule
    assert "strings:" not in md5.yara_rule


@pytest.mark.asyncio
async def test_rule_generator_supports_sha1_across_local_formats(temp_repo: Path) -> None:
    agent = RuleGeneratorAgent(
        settings=build_settings(),
        output_dir=str(temp_repo / "generated/detections"),
    )

    results = await agent.run(
        [
            {
                "value": "15efe7c0a510950c753a9ec1a388d699b341a2c4",
                "type": "sha1",
                "source": "feed-a",
                "risk_score": 90,
                "severity": "critical",
                "mitre_techniques": [],
                "mitre_tactics": [],
            }
        ]
    )

    assert len(results) == 1
    assert results[0].yara_rule is not None
    assert "SHA1=" in results[0].sigma_rule
    assert "SHA1 ==" in results[0].kql_query
    assert "hash.sha1(0, filesize)" in results[0].yara_rule

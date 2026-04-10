from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.agents.enricher import EnrichmentAgent


class FakeVirusTotalClient:
    def __init__(self, payload: dict | Exception) -> None:
        self.payload = payload

    async def lookup_ioc(self, ioc_type: str, value: str) -> dict:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeShodanClient:
    def __init__(self, payload: dict | Exception | None) -> None:
        self.payload = payload

    async def lookup_host(self, value: str) -> dict:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload or {}


class FakeAbuseIPDBClient:
    def __init__(self, payload: dict | Exception | None) -> None:
        self.payload = payload
        self.closed = False

    async def lookup_ip(self, value: str) -> dict:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload or {}

    async def aclose(self) -> None:
        self.closed = True


class FakeWhoisClient:
    def __init__(self, payload: dict | Exception | None, delay: float = 0.0) -> None:
        self.payload = payload
        self.delay = delay
        self.max_active = 0
        self.active = 0

    async def lookup(self, value: str) -> dict:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if isinstance(self.payload, Exception):
                raise self.payload
            return self.payload or {}
        finally:
            self.active -= 1


@pytest.fixture
def enrichment_skill(tmp_path: Path) -> Path:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(
        """---
version: 1.0.0
last_updated: 2026-04-08
updated_by: test
---

# Enrichment Skill

## Scoring Weights
- vt_ratio: 0.35
- abuse_confidence: 0.30
- source_trust: 0.20
- recency: 0.15

## Learner Updates
<!-- learner: append here -->
""",
        encoding="utf-8",
    )
    return skill_path


@pytest.mark.asyncio
async def test_enrichment_agent_merges_provider_results_and_scores(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        virustotal_client=FakeVirusTotalClient(
            {"last_analysis_stats": {"malicious": 6, "suspicious": 2, "harmless": 2, "undetected": 10}}
        ),
        shodan_client=FakeShodanClient({"ports": [80, 443]}),
        abuseipdb_client=FakeAbuseIPDBClient({"data": {"abuseConfidenceScore": 80}}),
        whois_client=FakeWhoisClient({"registrar": "Example Registrar"}),
    )

    enriched = await agent.run(
        [
            {
                "value": "8.8.8.8",
                "type": "ipv4",
                "source": "feed-a",
                "source_trust": 0.9,
                "first_seen": now - timedelta(days=1),
                "last_seen": now - timedelta(hours=1),
            }
        ]
    )

    assert len(enriched) == 1
    result = enriched[0]
    assert result.vt_detections == 8
    assert result.vt_ratio == 0.4
    assert result.shodan_ports == [80, 443]
    assert result.abuse_confidence == 80
    assert result.whois["registrar"] == "Example Registrar"
    assert result.risk_score > 60
    assert result.provider_errors == {}


@pytest.mark.asyncio
async def test_enrichment_agent_handles_partial_provider_failures(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        virustotal_client=FakeVirusTotalClient(RuntimeError("vt unavailable")),
        shodan_client=FakeShodanClient(RuntimeError("shodan unavailable")),
        abuseipdb_client=FakeAbuseIPDBClient({"data": {"abuseConfidenceScore": 20}}),
        whois_client=FakeWhoisClient({"registrar": "Fallback Registrar"}),
    )

    enriched = await agent.run(
        [
            {
                "value": "9.9.9.9",
                "type": "ipv4",
                "source": "feed-b",
                "source_trust": 0.5,
                "first_seen": now - timedelta(days=10),
                "last_seen": now - timedelta(days=2),
            }
        ]
    )

    result = enriched[0]
    assert result.vt_detections is None
    assert result.shodan_ports == []
    assert result.abuse_confidence == 20
    assert set(result.provider_errors) == {"virustotal", "shodan"}
    assert result.risk_score >= 0


@pytest.mark.asyncio
async def test_enrichment_agent_respects_provider_semaphore_limits(enrichment_skill: Path) -> None:
    whois_client = FakeWhoisClient({"registrar": "Example"}, delay=0.05)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        virustotal_client=FakeVirusTotalClient({"last_analysis_stats": {}}),
        shodan_client=FakeShodanClient(None),
        abuseipdb_client=FakeAbuseIPDBClient(None),
        whois_client=whois_client,
        semaphore_limits={"virustotal": 10, "shodan": 10, "abuseipdb": 10, "whois": 1},
    )

    await agent.run(
        [
            {
                "value": "alpha.test",
                "type": "domain",
                "source": "feed",
                "source_trust": 0.4,
                "first_seen": datetime.now(UTC),
                "last_seen": datetime.now(UTC),
            },
            {
                "value": "beta.test",
                "type": "domain",
                "source": "feed",
                "source_trust": 0.4,
                "first_seen": datetime.now(UTC),
                "last_seen": datetime.now(UTC),
            },
        ]
    )

    assert whois_client.max_active == 1

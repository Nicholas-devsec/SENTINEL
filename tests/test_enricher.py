from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.agents.enricher import EnrichmentAgent
from sentinel.config import SentinelSettings


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


def build_settings(
    *,
    enable_whois: bool = False,
    provider_timeout_seconds: int = 20,
    batch_size: int = 50,
    max_iocs_per_run: int = 250,
) -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "enrichment": {
                "virustotal_key": "vt",
                "shodan_key": "shodan",
                "abuseipdb_key": "abuse",
                "enable_whois": enable_whois,
                "provider_timeout_seconds": provider_timeout_seconds,
                "batch_size": batch_size,
                "max_iocs_per_run": max_iocs_per_run,
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )


@pytest.mark.asyncio
async def test_enrichment_agent_merges_provider_results_and_scores(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(enable_whois=True),
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
async def test_enrichment_agent_records_vt_file_hash_family(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(),
        virustotal_client=FakeVirusTotalClient(
            {
                "attributes": {
                    "md5": "8c21b2fbded2faeb6db2e7a20c513cdb",
                    "sha1": "38b837cc5fe814ca9580f9029386aa405f8e94df",
                    "sha256": "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0",
                    "last_analysis_stats": {"malicious": 66, "suspicious": 0, "harmless": 0, "undetected": 0},
                }
            }
        ),
        shodan_client=FakeShodanClient({}),
        abuseipdb_client=FakeAbuseIPDBClient({}),
        whois_client=FakeWhoisClient({}),
    )

    enriched = await agent.run(
        [
            {
                "value": "8c21b2fbded2faeb6db2e7a20c513cdb",
                "type": "md5",
                "source": "threatfox",
                "source_trust": 0.95,
                "first_seen": now,
                "last_seen": now,
            }
        ]
    )

    family = enriched[0].attributes["hash_family"]
    assert family["md5"] == "8c21b2fbded2faeb6db2e7a20c513cdb"
    assert family["sha1"] == "38b837cc5fe814ca9580f9029386aa405f8e94df"
    assert family["sha256"] == "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0"
    assert enriched[0].attributes["hash_family_key"] == family["sha256"]


@pytest.mark.asyncio
async def test_enrichment_agent_handles_partial_provider_failures(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(enable_whois=True),
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


@pytest.fixture
def default_weight_skill(tmp_path: Path) -> Path:
    """Skill file with no Scoring Weights section, so the agent uses the current
    config defaults (the rebalanced, evidence-driven weights)."""
    skill_path = tmp_path / "SKILL_default.md"
    skill_path.write_text(
        "---\nversion: 1.0.0\n---\n\n# Enrichment Skill\n\n"
        "## Enrichment Rules\n- Partial enrichment is acceptable.\n",
        encoding="utf-8",
    )
    return skill_path


def _no_evidence_agent(skill: Path) -> EnrichmentAgent:
    """Agent whose providers return nothing, so score is driven by trust/context."""
    return EnrichmentAgent(
        skill_path=str(skill),
        settings=build_settings(),
        virustotal_client=FakeVirusTotalClient({}),
        shodan_client=FakeShodanClient({}),
        abuseipdb_client=FakeAbuseIPDBClient({}),
    )


@pytest.mark.asyncio
async def test_high_trust_feed_without_evidence_stays_below_detection_bar(default_weight_skill: Path) -> None:
    """The core anti-bias guarantee: a ThreatFox-trust IOC with no VT/abuse
    evidence and no curation must NOT clear the rule threshold on trust alone."""
    now = datetime.now(UTC)
    agent = _no_evidence_agent(default_weight_skill)

    enriched = await agent.run(
        [
            {
                "value": "45.155.204.1",
                "type": "ipv4",
                "source": "threatfox",
                "source_trust": 0.94,
                "first_seen": now - timedelta(hours=1),
                "last_seen": now - timedelta(hours=1),
            }
        ]
    )

    # trust 0.10*0.94 + recency 0.10*~1.0 ~= 19, comfortably under rule_score=30.
    assert enriched[0].risk_score < 30


@pytest.mark.asyncio
async def test_curated_writeup_ioc_clears_bar_without_api_evidence(default_weight_skill: Path) -> None:
    """A writeup IOC hand-listed in an IOC section clears the rule threshold on
    curation context even though it has lower feed trust and no VT/abuse."""
    now = datetime.now(UTC)
    agent = _no_evidence_agent(default_weight_skill)

    enriched = await agent.run(
        [
            {
                "value": "malicious-c2.badcorp.top",
                "type": "domain",
                "source": "discovery:securelist.com",
                "source_trust": 0.67,
                "first_seen": now - timedelta(hours=1),
                "last_seen": now - timedelta(hours=1),
            }
        ],
        context_by_value={
            "malicious-c2.badcorp.top": {
                "provenance": "writeup",
                "extraction_mode": "ioc_section",
                "corroboration_sources": 1,
            }
        },
    )

    result = enriched[0]
    assert result.context_score == 1.0
    # 0.10*0.67 + 0.10*recency + 0.15*1.0 ~= 31, above rule_score=30.
    assert result.risk_score >= 30


@pytest.mark.asyncio
async def test_corroboration_raises_score(default_weight_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = _no_evidence_agent(default_weight_skill)
    base = {
        "value": "45.155.204.9",
        "type": "ipv4",
        "source": "threatfox",
        "source_trust": 0.94,
        "first_seen": now - timedelta(hours=1),
        "last_seen": now - timedelta(hours=1),
    }

    single = await agent.run([base], context_by_value={"45.155.204.9": {"corroboration_sources": 1}})
    multi = await agent.run([base], context_by_value={"45.155.204.9": {"corroboration_sources": 3}})

    # Three independent sources add 0.20*1.0*100 = 20 points over a single source.
    assert multi[0].corroboration_sources == 3
    assert multi[0].risk_score > single[0].risk_score
    assert round(multi[0].risk_score - single[0].risk_score, 1) == 20.0


def test_rescore_from_stored_is_deterministic_and_local(default_weight_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = _no_evidence_agent(default_weight_skill)
    weights = agent.get_scoring_weights()

    feed_no_evidence = agent.rescore_from_stored(
        weights=weights,
        vt_ratio=None,
        abuse_confidence=None,
        source_trust=0.94,
        first_seen=now,
        last_seen=now,
        context={"provenance": "feed", "corroboration_sources": 1},
    )
    curated = agent.rescore_from_stored(
        weights=weights,
        vt_ratio=None,
        abuse_confidence=None,
        source_trust=0.67,
        first_seen=now,
        last_seen=now,
        context={"provenance": "writeup", "extraction_mode": "ioc_section", "corroboration_sources": 1},
    )

    assert feed_no_evidence < 30 <= curated


@pytest.mark.asyncio
async def test_enrichment_agent_respects_provider_semaphore_limits(enrichment_skill: Path) -> None:
    whois_client = FakeWhoisClient({"registrar": "Example"}, delay=0.05)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(enable_whois=True),
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


@pytest.mark.asyncio
async def test_enrichment_agent_disables_whois_by_default(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    whois_client = FakeWhoisClient({"registrar": "Should not be used"})
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(enable_whois=False),
        virustotal_client=FakeVirusTotalClient({"last_analysis_stats": {}}),
        shodan_client=FakeShodanClient(None),
        abuseipdb_client=FakeAbuseIPDBClient(None),
        whois_client=whois_client,
    )

    enriched = await agent.run(
        [
            {
                "value": "example.test",
                "type": "domain",
                "source": "feed-a",
                "source_trust": 0.9,
                "first_seen": now - timedelta(hours=1),
                "last_seen": now,
            }
        ]
    )

    assert enriched[0].whois == {}
    assert whois_client.max_active == 0


@pytest.mark.asyncio
async def test_enrichment_agent_limits_total_iocs_per_run(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(max_iocs_per_run=1, batch_size=1),
        virustotal_client=FakeVirusTotalClient({"last_analysis_stats": {}}),
        shodan_client=FakeShodanClient(None),
        abuseipdb_client=FakeAbuseIPDBClient(None),
    )

    enriched = await agent.run(
        [
            {
                "value": "alpha.test",
                "type": "domain",
                "source": "feed-a",
                "source_trust": 0.9,
                "first_seen": now,
                "last_seen": now,
            },
            {
                "value": "beta.test",
                "type": "domain",
                "source": "feed-b",
                "source_trust": 0.8,
                "first_seen": now,
                "last_seen": now,
            },
        ]
    )

    assert [item.value for item in enriched] == ["alpha.test"]


@pytest.mark.asyncio
async def test_enrichment_agent_records_provider_timeout_as_partial_failure(enrichment_skill: Path) -> None:
    now = datetime.now(UTC)
    whois_client = FakeWhoisClient({"registrar": "Slow Registrar"}, delay=0.05)
    agent = EnrichmentAgent(
        skill_path=str(enrichment_skill),
        settings=build_settings(enable_whois=True, provider_timeout_seconds=0),
        virustotal_client=FakeVirusTotalClient({"last_analysis_stats": {}}),
        shodan_client=FakeShodanClient(None),
        abuseipdb_client=FakeAbuseIPDBClient(None),
        whois_client=whois_client,
    )

    enriched = await agent.run(
        [
            {
                "value": "slow.test",
                "type": "domain",
                "source": "feed-a",
                "source_trust": 0.7,
                "first_seen": now,
                "last_seen": now,
            }
        ]
    )

    assert "whois" in enriched[0].provider_errors

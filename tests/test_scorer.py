from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.agents.enricher import EnrichedIOC
from sentinel.agents.scorer import ScoringAgent
from sentinel.integrations.mitre_attack import MitreAttackRepository, TechniqueEntry


def build_repository() -> MitreAttackRepository:
    return MitreAttackRepository(
        techniques=[
            TechniqueEntry(
                attack_id="T1566.001",
                stix_id="attack-pattern--phishing",
                name="Spearphishing Attachment",
                description="Malicious attachment delivery through phishing email and inbox lures.",
                tactics=["initial access"],
                document="Spearphishing Attachment malicious attachment phishing email inbox lure",
            ),
            TechniqueEntry(
                attack_id="T1059",
                stix_id="attack-pattern--shell",
                name="Command and Scripting Interpreter",
                description="PowerShell and shell execution for malicious command scripting.",
                tactics=["execution"],
                document="Command and Scripting Interpreter powershell shell execution command scripting",
            ),
            TechniqueEntry(
                attack_id="T1071",
                stix_id="attack-pattern--c2",
                name="Application Layer Protocol",
                description="Command and control traffic over HTTP, HTTPS, and DNS.",
                tactics=["command and control"],
                document="Application Layer Protocol command control http https dns",
            ),
        ]
    )


@pytest.mark.asyncio
async def test_scoring_agent_maps_context_to_top_techniques() -> None:
    scorer = ScoringAgent(mitre_repository=build_repository())
    enriched = EnrichedIOC(
        value="https://phish.example/login",
        type="url",
        source="feed-a",
        source_trust=0.9,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        risk_score=76.5,
        enrichment_text="Phishing email delivered a malicious attachment and HTTP callback.",
    )

    results = await scorer.run([enriched])

    assert len(results) == 1
    scored = results[0]
    assert scored.severity == "high"
    assert scored.mitre_techniques[0] == "T1566.001"
    assert "initial access" in scored.mitre_tactics
    assert len(scored.mitre_techniques) == 3


@pytest.mark.asyncio
async def test_scoring_agent_applies_severity_thresholds() -> None:
    scorer = ScoringAgent(mitre_repository=build_repository())

    results = await scorer.run(
        [
            {"value": "a", "type": "domain", "source": "s", "risk_score": 95, "enrichment_text": "powershell"},
            {"value": "b", "type": "domain", "source": "s", "risk_score": 70, "enrichment_text": "http c2"},
            {"value": "c", "type": "domain", "source": "s", "risk_score": 50, "enrichment_text": "phishing"},
            {"value": "d", "type": "domain", "source": "s", "risk_score": 49.9, "enrichment_text": "dns"},
        ]
    )

    assert [result.severity for result in results] == [
        "critical",
        "high",
        "medium",
        "informational",
    ]


@pytest.mark.asyncio
async def test_scoring_agent_builds_external_links_for_detected_sources() -> None:
    scorer = ScoringAgent(mitre_repository=build_repository())

    results = await scorer.run(
        [
            {
                "value": "198.51.100.25",
                "type": "ipv4",
                "source": "otx",
                "risk_score": 42.0,
                "enrichment_text": "vt=12 abuse=80 shodan=443",
                "vt_detections": 12,
                "abuse_confidence": 80,
                "shodan_ports": [443, 8080],
            }
        ]
    )

    links = results[0].external_links
    assert links["VirusTotal"] == "https://www.virustotal.com/gui/ip-address/198.51.100.25"
    assert "AbuseIPDB" in links
    assert "Shodan" in links
    assert "OTX" in links


@pytest.mark.asyncio
async def test_scoring_agent_builds_ip_links_even_without_positive_hits() -> None:
    scorer = ScoringAgent(mitre_repository=build_repository())

    results = await scorer.run(
        [
            {
                "value": "162.243.103.246",
                "type": "ipv4",
                "source": "feodotracker",
                "risk_score": 24.0,
                "enrichment_text": "",
                "vt_detections": None,
                "abuse_confidence": 0,
                "shodan_ports": [],
            }
        ]
    )

    links = results[0].external_links
    assert links["VirusTotal"] == "https://www.virustotal.com/gui/ip-address/162.243.103.246"
    assert links["AbuseIPDB"] == "https://www.abuseipdb.com/check/162.243.103.246"
    assert links["Shodan"] == "https://www.shodan.io/host/162.243.103.246"


@pytest.mark.asyncio
async def test_scoring_agent_builds_virustotal_url_object_link() -> None:
    scorer = ScoringAgent(mitre_repository=build_repository())
    value = "https://mansfieldpediatrics.com/gate?buildtxd=b2955c54eb0c047463993b379e015e737aab"

    results = await scorer.run(
        [
            {
                "value": value,
                "type": "url",
                "source": "otx",
                "risk_score": 40.0,
                "enrichment_text": "vt=21",
                "vt_detections": 21,
            }
        ]
    )

    expected_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")
    assert results[0].external_links["VirusTotal"] == f"https://www.virustotal.com/gui/url/{expected_id}"


def test_mitre_repository_loads_attack_stix_data_style_bundle(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--1234",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--1",
                "name": "Spearphishing Attachment",
                "description": "Malicious attachment delivery via phishing email.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.001"}
                ],
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--2",
                "name": "Command and Scripting Interpreter",
                "description": "PowerShell execution and scripting.",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
            },
        ],
    }
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle), encoding="utf-8")

    repository = MitreAttackRepository(stix_path=stix_path)
    matches = repository.search("phishing email attachment", limit=1)

    assert len(repository.techniques) == 2
    assert repository.techniques[0].attack_id == "T1566.001"
    assert matches[0].attack_id == "T1566.001"

from __future__ import annotations

import pytest

from sentinel.config import SentinelSettings
from sentinel.pipeline import PipelineResult, build_agents, run_pipeline_once


class FakeAgent:
    def __init__(self, result):
        self.result = result
        self.closed = False
        self.calls = []

    async def run(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return self.result

    async def aclose(self):
        self.closed = True


@pytest.mark.asyncio
async def test_pipeline_result_dataclass_shape() -> None:
    result = PipelineResult(
        scraped=3,
        validated=2,
        enriched=2,
        scored=2,
        generated=1,
        immediate_alerts=1,
        digest_candidates=2,
    )

    assert result.generated == 1
    assert result.immediate_alerts == 1


def test_build_agents_requires_mitre_stix_path() -> None:
    settings = SentinelSettings.model_validate(
        {
            "mitre": {"stix_path": "${MITRE_STIX_PATH}"},
            "db": {"url": "postgresql+asyncpg://test:test@localhost/test", "redis_url": "redis://localhost:6379/0"},
        }
    )

    with pytest.raises(ValueError, match="MITRE_STIX_PATH"):
        build_agents(settings)


@pytest.mark.asyncio
async def test_run_pipeline_once_orchestrates_agents(monkeypatch) -> None:
    scraped = [{"value": "1.1.1.1"}]
    validated_row = type("Row", (), {"id": "ioc-1", "last_seen": "2026-04-08T12:00:00+00:00"})
    enriched = [type("Enriched", (), {"value": "1.1.1.1"})]
    scored = [
        {
            "value": "1.1.1.1",
            "type": "ipv4",
            "source": "feed-a",
            "risk_score": 80.0,
            "severity": "high",
            "mitre_techniques": ["T1071"],
            "mitre_tactics": ["command and control"],
        }
    ]
    generated = [type("Generated", (), {"value": "1.1.1.1", "crowdstrike_response": {"ok": True}, "sigma_rule": "rule"})]
    delivery = type("DeliveryResult", (), {"immediate_alerts": 1, "digest_candidates": 1})()

    agents = {
        "scraper": FakeAgent(scraped),
        "validator": FakeAgent([validated_row]),
        "enricher": FakeAgent(enriched),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent(generated),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=[validated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=[validated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    result = await run_pipeline_once(
        SentinelSettings.model_validate(
            {
                "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
                "db": {"url": "postgresql+asyncpg://test:test@localhost/test", "redis_url": "redis://localhost:6379/0"},
            }
        )
    )

    assert result == PipelineResult(
        scraped=1,
        validated=1,
        enriched=1,
        scored=1,
        generated=1,
        immediate_alerts=1,
        digest_candidates=1,
    )
    assert agents["scraper"].closed is True
    assert agents["enricher"].closed is True
    assert agents["rule_generator"].closed is True
    assert agents["delivery"].closed is True


@pytest.mark.asyncio
async def test_run_pipeline_once_preserves_ip_and_hash_payload_fields(monkeypatch) -> None:
    validated_rows = [
        type("Row", (), {"id": "ioc-ip", "last_seen": "2026-04-08T12:00:00+00:00"}),
        type("Row", (), {"id": "ioc-hash", "last_seen": "2026-04-08T12:00:00+00:00"}),
    ]
    enriched = [
        type(
            "Enriched",
            (),
            {
                "value": "8.8.8.8",
                "type": "ipv4",
                "source": "feed-a",
                "risk_score": 72.0,
                "vt_detections": 8,
                "abuse_confidence": 90,
                "shodan_ports": [443, 8080],
                "provider_results": {},
                "enrichment_text": "ip evidence",
            },
        ),
        type(
            "Enriched",
            (),
            {
                "value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "type": "sha256",
                "source": "feed-b",
                "risk_score": 91.0,
                "vt_detections": 15,
                "abuse_confidence": None,
                "shodan_ports": [],
                "provider_results": {},
                "enrichment_text": "hash evidence",
            },
        ),
    ]
    scored = [
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "source": "feed-a",
            "risk_score": 72.0,
            "severity": "high",
            "vt_detections": 8,
            "abuse_confidence": 90,
            "shodan_ports": [443, 8080],
            "external_links": {"Shodan": "https://www.shodan.io/host/8.8.8.8"},
            "mitre_techniques": ["T1071"],
            "mitre_tactics": ["command and control"],
        },
        {
            "value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "type": "sha256",
            "source": "feed-b",
            "risk_score": 91.0,
            "severity": "critical",
            "vt_detections": 15,
            "abuse_confidence": None,
            "shodan_ports": [],
            "external_links": {"VirusTotal": "https://www.virustotal.com/gui/file/deadbeef"},
            "mitre_techniques": ["T1059"],
            "mitre_tactics": ["execution"],
        },
    ]
    generated = [
        type("Generated", (), {"value": "8.8.8.8", "crowdstrike_response": None, "sigma_rule": "rule-ip"}),
        type("Generated", (), {"value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "crowdstrike_response": None, "sigma_rule": "rule-hash"}),
    ]
    delivery = type("DeliveryResult", (), {"immediate_alerts": 2, "digest_candidates": 2})()

    agents = {
        "scraper": FakeAgent([{"value": "8.8.8.8"}, {"value": "deadbeef"}]),
        "validator": FakeAgent(validated_rows),
        "enricher": FakeAgent(enriched),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent(generated),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=validated_rows))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=validated_rows))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    await run_pipeline_once(
        SentinelSettings.model_validate(
            {
                "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
                "db": {"url": "sqlite+aiosqlite:///./data/test.db", "redis_url": "disabled"},
            }
        )
    )

    delivery_payload = agents["delivery"].calls[0]["args"][0]
    assert len(delivery_payload) == 2
    ip_payload = next(item for item in delivery_payload if item["type"] == "ipv4")
    hash_payload = next(item for item in delivery_payload if item["type"] == "sha256")
    assert ip_payload["vt_detections"] == 8
    assert ip_payload["abuse_confidence"] == 90
    assert ip_payload["shodan_ports"] == [443, 8080]
    assert "Shodan" in ip_payload["external_links"]
    assert hash_payload["vt_detections"] == 15
    assert hash_payload["external_links"]["VirusTotal"].startswith("https://www.virustotal.com/gui/file/")
    assert agents["rule_generator"].calls[0]["args"][0][1]["type"] == "sha256"

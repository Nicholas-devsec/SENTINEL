from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.agents.enricher import EnrichedIOC
from sentinel.agents.scraper import RawIOC, ScrapeReport
from sentinel.agents.validator import ValidationReport
from sentinel.config import SentinelSettings
from sentinel.pipeline import (
    PipelineResult,
    _apply_workflow_limits,
    _dedupe_enriched_hash_families,
    build_agents,
    run_daily_digest,
    run_pipeline_once,
)


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


class FakeScraperAgent(FakeAgent):
    async def run_with_diagnostics(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return ScrapeReport(items=self.result, diagnostics=[], writeups=[])


class FakeValidatorAgent(FakeAgent):
    async def run_with_report(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return ValidationReport(new_iocs=self.result, corroborated_iocs=[], sightings_recorded=len(self.result))


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


def test_pipeline_dedupes_enriched_file_hash_families_to_first_seen() -> None:
    now = datetime.now(UTC)
    family = {
        "md5": "8c21b2fbded2faeb6db2e7a20c513cdb",
        "sha1": "38b837cc5fe814ca9580f9029386aa405f8e94df",
        "sha256": "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0",
    }

    def make_hash(value: str, ioc_type: str) -> EnrichedIOC:
        return EnrichedIOC(
            value=value,
            type=ioc_type,
            source="threatfox",
            source_trust=0.95,
            first_seen=now,
            last_seen=now,
            risk_score=90.0,
            attributes={"hash_family": family, "hash_family_key": family["sha256"]},
        )

    kept, suppressed = _dedupe_enriched_hash_families(
        [
            make_hash(family["md5"], "md5"),
            make_hash(family["sha1"], "sha1"),
            make_hash(family["sha256"], "sha256"),
            EnrichedIOC(
                value="137.184.135.42",
                type="ipv4",
                source="threatfox",
                source_trust=0.95,
                first_seen=now,
                last_seen=now,
                risk_score=50.0,
            ),
        ]
    )

    assert [(item.type, item.value) for item in kept] == [
        ("md5", family["md5"]),
        ("ipv4", "137.184.135.42"),
    ]
    assert {item.type for item in suppressed} == {"sha1", "sha256"}


def test_workflow_feed_limit_refills_after_hash_family_dedupe() -> None:
    now = datetime.now(UTC)
    settings = SentinelSettings.model_validate(
        {
            "workflow": {
                "feed_ioc_store_limit_per_run": 3,
                "article_store_limit_per_run": 0,
                "telegram_feed_alert_limit_per_run": 3,
                "telegram_article_alert_limit_per_run": 0,
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
        }
    )
    shared = {
        "reference_url_original": "https://vendor.example/sample-report",
        "threat_type": "payload",
        "malware": "sample-family",
        "reporter": "abuse_ch",
    }
    raw_items = [
        RawIOC("a" * 32, "md5", "threatfox", 0.94, now, now, attributes=shared),
        RawIOC("b" * 40, "sha1", "threatfox", 0.94, now, now, attributes=shared),
        RawIOC("c" * 64, "sha256", "threatfox", 0.94, now, now, attributes=shared),
        RawIOC("1.1.1.1", "ipv4", "threatfox", 0.94, now, now),
        RawIOC("2.2.2.2", "ipv4", "urlhaus", 0.91, now, now),
    ]

    limited, _ = _apply_workflow_limits(settings, raw_items=raw_items, writeups=[])

    assert [(item.type, item.value) for item in limited] == [
        ("md5", "a" * 32),
        ("ipv4", "1.1.1.1"),
        ("ipv4", "2.2.2.2"),
    ]


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
    validated_row = type(
        "Row",
        (),
        {"id": "ioc-1", "value": "1.1.1.1", "type": "ipv4", "source": "feed-a", "last_seen": "2026-04-08T12:00:00+00:00"},
    )
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
        "scraper": FakeScraperAgent(scraped),
        "validator": FakeValidatorAgent([validated_row]),
        "enricher": FakeAgent(enriched),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent(generated),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_writeups", lambda writeups, raw_items=None: __import__("asyncio").sleep(0, result={}))
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=[validated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=[validated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    async def fake_corroboration(session, ioc_ids):
        return {}

    monkeypatch.setattr("sentinel.pipeline.get_corroboration", fake_corroboration)

    async def fake_scoring_context(session, ioc_ids):
        return {}

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    class NullSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: NullSession())

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
        writeups=0,
        sightings=1,
        corroborated=0,
    )
    assert agents["scraper"].closed is True
    assert agents["enricher"].closed is True
    assert agents["rule_generator"].closed is True
    assert agents["delivery"].closed is True


@pytest.mark.asyncio
async def test_run_pipeline_once_reprocesses_corroborated_iocs(monkeypatch) -> None:
    corroborated_row = type(
        "Row",
        (),
        {
            "id": "ioc-2",
            "value": "repeat.example",
            "type": "domain",
            "source": "feed-a",
            "last_seen": "2026-04-08T12:00:00+00:00",
        },
    )
    enriched = [type("Enriched", (), {"value": "repeat.example", "type": "domain", "source": "feed-a"})]
    scored = [
        {
            "value": "repeat.example",
            "type": "domain",
            "source": "feed-a",
            "risk_score": 72.0,
            "severity": "high",
            "mitre_techniques": [],
            "mitre_tactics": [],
        }
    ]
    generated = [type("Generated", (), {"value": "repeat.example", "crowdstrike_response": None, "sigma_rule": "rule"})]
    delivery = type("DeliveryResult", (), {"immediate_alerts": 1, "digest_candidates": 1})()

    class CorroboratedValidatorAgent(FakeAgent):
        async def run_with_report(self, *args, **kwargs):
            self.calls.append({"args": args, "kwargs": kwargs})
            return ValidationReport(new_iocs=[], corroborated_iocs=[corroborated_row], sightings_recorded=1)

    agents = {
        "scraper": FakeScraperAgent([{"value": "repeat.example"}]),
        "validator": CorroboratedValidatorAgent(None),
        "enricher": FakeAgent(enriched),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent(generated),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_writeups", lambda writeups, raw_items=None: __import__("asyncio").sleep(0, result={}))
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=[corroborated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=[corroborated_row]))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    async def fake_corroboration(session, ioc_ids):
        return {"ioc-2": 2}

    monkeypatch.setattr("sentinel.pipeline.get_corroboration", fake_corroboration)

    async def fake_scoring_context(session, ioc_ids):
        return {"ioc-2": {"provenance": "feed", "corroboration_sources": 2}}

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    class NullSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: NullSession())

    result = await run_pipeline_once(
        SentinelSettings.model_validate(
            {
                "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
                "db": {"url": "postgresql+asyncpg://test:test@localhost/test", "redis_url": "redis://localhost:6379/0"},
            }
        )
    )

    assert result.validated == 0
    assert result.corroborated == 1
    assert agents["enricher"].calls[0]["args"][0] == [corroborated_row]
    assert agents["delivery"].calls[0]["args"][0][0]["corroboration_sources"] == 2


@pytest.mark.asyncio
async def test_run_pipeline_once_preserves_ip_and_hash_payload_fields(monkeypatch) -> None:
    validated_rows = [
        type("Row", (), {"id": "ioc-ip", "value": "8.8.8.8", "type": "ipv4", "source": "feed-a", "last_seen": "2026-04-08T12:00:00+00:00"}),
        type(
            "Row",
            (),
            {
                "id": "ioc-hash",
                "value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "type": "sha256",
                "source": "feed-b",
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
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
        "scraper": FakeScraperAgent([{"value": "8.8.8.8"}, {"value": "deadbeef"}]),
        "validator": FakeValidatorAgent(validated_rows),
        "enricher": FakeAgent(enriched),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent(generated),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_writeups", lambda writeups, raw_items=None: __import__("asyncio").sleep(0, result={}))
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=validated_rows))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=validated_rows))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    async def fake_corroboration(session, ioc_ids):
        return {}

    monkeypatch.setattr("sentinel.pipeline.get_corroboration", fake_corroboration)

    async def fake_scoring_context(session, ioc_ids):
        return {}

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    class NullSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: NullSession())

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


@pytest.mark.asyncio
async def test_run_pipeline_once_aligns_delivery_payload_by_ioc_identity(monkeypatch) -> None:
    validated_rows = [
        type("Row", (), {"id": "ioc-ip", "value": "8.8.8.8", "type": "ipv4", "source": "feed-a", "last_seen": "2026-04-08T12:00:00+00:00"}),
        type("Row", (), {"id": "ioc-domain", "value": "bad.example", "type": "domain", "source": "feed-b", "last_seen": "2026-04-08T13:00:00+00:00"}),
    ]
    scored = [
        {
            "value": "8.8.8.8",
            "type": "ipv4",
            "source": "feed-a",
            "risk_score": 72.0,
            "severity": "high",
            "mitre_techniques": [],
            "mitre_tactics": [],
        },
        {
            "value": "bad.example",
            "type": "domain",
            "source": "feed-b",
            "risk_score": 91.0,
            "severity": "critical",
            "mitre_techniques": [],
            "mitre_tactics": [],
        },
    ]
    persisted_rows_reordered = [validated_rows[1], validated_rows[0]]
    delivery = type("DeliveryResult", (), {"immediate_alerts": 2, "digest_candidates": 2})()
    agents = {
        "scraper": FakeScraperAgent([{"value": "8.8.8.8"}, {"value": "bad.example"}]),
        "validator": FakeValidatorAgent(validated_rows),
        "enricher": FakeAgent([type("Enriched", (), {"value": row.value}) for row in validated_rows]),
        "scorer": FakeAgent(scored),
        "rule_generator": FakeAgent([]),
        "delivery": FakeAgent(delivery),
    }

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))
    monkeypatch.setattr("sentinel.pipeline.build_agents", lambda settings=None: agents)
    monkeypatch.setattr("sentinel.pipeline._persist_writeups", lambda writeups, raw_items=None: __import__("asyncio").sleep(0, result={}))
    monkeypatch.setattr("sentinel.pipeline._persist_enrichment", lambda enriched_items: __import__("asyncio").sleep(0, result=validated_rows))
    monkeypatch.setattr("sentinel.pipeline._persist_scoring", lambda scored_items: __import__("asyncio").sleep(0, result=persisted_rows_reordered))
    monkeypatch.setattr("sentinel.pipeline._persist_generated", lambda generated_items: __import__("asyncio").sleep(0))

    async def fake_corroboration(session, ioc_ids):
        return {"ioc-ip": 2, "ioc-domain": 3}

    monkeypatch.setattr("sentinel.pipeline.get_corroboration", fake_corroboration)

    async def fake_scoring_context(session, ioc_ids):
        return {}

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    class NullSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: NullSession())

    await run_pipeline_once(
        SentinelSettings.model_validate(
            {
                "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
                "db": {"url": "sqlite+aiosqlite:///./data/test.db", "redis_url": "disabled"},
            }
        )
    )

    delivery_payload = agents["delivery"].calls[0]["args"][0]
    assert [item["id"] for item in delivery_payload] == ["ioc-ip", "ioc-domain"]
    assert next(item for item in delivery_payload if item["value"] == "8.8.8.8")["corroboration_sources"] == 2
    assert next(item for item in delivery_payload if item["value"] == "bad.example")["corroboration_sources"] == 3


@pytest.mark.asyncio
async def test_run_daily_digest_uses_same_digest_policy_as_delivery(monkeypatch) -> None:
    rows = [
        type(
            "Row",
            (),
            {
                "id": "ioc-low",
                "value": "low.example",
                "type": "domain",
                "source": "feed-a",
                "risk_score": 12.0,
                "severity": "informational",
                "source_title": None,
                "reference_url": None,
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
        type(
            "Row",
            (),
            {
                "id": "ioc-discovery",
                "value": "publisher.example/mal",
                "type": "url",
                "source": "discovery:publisher.example",
                "risk_score": 5.0,
                "severity": "informational",
                "source_title": "Publisher writeup",
                "reference_url": "https://publisher.example/post",
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
        type(
            "Row",
            (),
            {
                "id": "ioc-high",
                "value": "high.example",
                "type": "domain",
                "source": "feed-b",
                "risk_score": 80.0,
                "severity": "high",
                "source_title": None,
                "reference_url": None,
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
    ]

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))

    class ScalarResult:
        def all(self):
            return rows

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def scalars(self, query):
            return ScalarResult()

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: FakeSession())

    async def fake_scoring_context(session, ioc_ids):
        return {
            "ioc-low": {"provenance": "feed", "extraction_mode": "feed", "corroboration_sources": 1},
            "ioc-discovery": {"provenance": "discovery", "extraction_mode": "fallback", "corroboration_sources": 1},
            "ioc-high": {"provenance": "feed", "extraction_mode": "feed", "corroboration_sources": 1},
        }

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    captured: dict[str, list[dict]] = {}

    class FakeDeliveryAgent:
        def __init__(self, *args, **kwargs):
            return None

        async def daily_digest(self, items):
            captured["items"] = items
            return {"count": len(items)}

        async def aclose(self):
            return None

        def _select_digest_candidates(self, items):
            from sentinel.agents.delivery import DeliveryAgent

            agent = DeliveryAgent.__new__(DeliveryAgent)
            agent.settings = settings
            agent._within_last_24_hours = lambda value: True
            agent._is_web_discovery_item = DeliveryAgent._is_web_discovery_item.__get__(agent, DeliveryAgent)
            agent._alert_policy = DeliveryAgent._alert_policy.__get__(agent, DeliveryAgent)
            return DeliveryAgent._select_digest_candidates(agent, items)

    settings = SentinelSettings.model_validate(
        {
            "delivery": {"telegram_token": "token", "telegram_chat_id": "chat"},
            "db": {"url": "sqlite+aiosqlite:///./data/test.db", "redis_url": "disabled"},
        }
    )
    monkeypatch.setattr("sentinel.pipeline.DeliveryAgent", FakeDeliveryAgent)
    monkeypatch.setattr("sentinel.pipeline._build_telegram_bot", lambda settings: None)

    result = await run_daily_digest(settings)

    assert result == {"count": 1}
    assert {item["id"] for item in captured["items"]} == {"ioc-high"}


@pytest.mark.asyncio
async def test_run_daily_digest_uses_candidate_pool_before_policy_filter(monkeypatch) -> None:
    rows = [
        type(
            "Row",
            (),
            {
                "id": "ioc-high",
                "value": "high.example",
                "type": "domain",
                "source": "feed-a",
                "risk_score": 90.0,
                "severity": "critical",
                "source_title": None,
                "reference_url": None,
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
        type(
            "Row",
            (),
            {
                "id": "ioc-medium",
                "value": "medium.example",
                "type": "domain",
                "source": "feed-b",
                "risk_score": 60.0,
                "severity": "medium",
                "source_title": None,
                "reference_url": None,
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
        type(
            "Row",
            (),
            {
                "id": "ioc-discovery",
                "value": "publisher.example/mal",
                "type": "url",
                "source": "discovery:publisher.example",
                "risk_score": 5.0,
                "severity": "informational",
                "source_title": "Publisher writeup",
                "reference_url": "https://publisher.example/post",
                "related_cves": [],
                "vt_detections": None,
                "abuse_confidence": None,
                "shodan_ports": [],
                "mitre_techniques": [],
                "mitre_tactics": [],
                "last_seen": "2026-04-08T12:00:00+00:00",
            },
        ),
    ]

    monkeypatch.setattr("sentinel.pipeline.init_db", lambda: __import__("asyncio").sleep(0))

    class ScalarResult:
        def __init__(self, selected_rows):
            self._rows = selected_rows

        def all(self):
            return self._rows

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def scalars(self, query):
            limit_clause = getattr(query, "_limit_clause", None)
            limit = int(limit_clause.value) if limit_clause is not None else len(rows)
            return ScalarResult(rows[:limit])

    monkeypatch.setattr("sentinel.pipeline.AsyncSessionFactory", lambda: FakeSession())

    async def fake_scoring_context(session, ioc_ids):
        return {
            "ioc-high": {"provenance": "feed", "extraction_mode": "feed", "corroboration_sources": 1},
            "ioc-medium": {"provenance": "writeup", "extraction_mode": "ioc_section", "corroboration_sources": 1},
            "ioc-discovery": {"provenance": "discovery", "extraction_mode": "fallback", "corroboration_sources": 1},
        }

    monkeypatch.setattr("sentinel.pipeline.get_scoring_context", fake_scoring_context)

    captured: dict[str, list[dict]] = {}

    class FakeDeliveryAgent:
        def __init__(self, *args, **kwargs):
            return None

        async def daily_digest(self, items):
            captured["items"] = items
            return {"count": len(items)}

        async def aclose(self):
            return None

        def _select_digest_candidates(self, items):
            from sentinel.agents.delivery import DeliveryAgent

            agent = DeliveryAgent.__new__(DeliveryAgent)
            agent.settings = settings
            agent._within_last_24_hours = lambda value: True
            agent._is_web_discovery_item = DeliveryAgent._is_web_discovery_item.__get__(agent, DeliveryAgent)
            agent._alert_policy = DeliveryAgent._alert_policy.__get__(agent, DeliveryAgent)
            return DeliveryAgent._select_digest_candidates(agent, items)

    settings = SentinelSettings.model_validate(
        {
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "chat",
                "telegram_daily_digest_limit": 1,
                "telegram_digest_candidate_pool_size": 3,
            },
            "db": {"url": "sqlite+aiosqlite:///./data/test.db", "redis_url": "disabled"},
        }
    )
    monkeypatch.setattr("sentinel.pipeline.DeliveryAgent", FakeDeliveryAgent)
    monkeypatch.setattr("sentinel.pipeline._build_telegram_bot", lambda settings: None)

    result = await run_daily_digest(settings)

    assert result == {"count": 2}
    assert {item["id"] for item in captured["items"]} == {"ioc-high", "ioc-medium"}

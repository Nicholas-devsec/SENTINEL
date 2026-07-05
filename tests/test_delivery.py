from __future__ import annotations
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import SentinelSettings
from sentinel.db.models import FeedbackRecord
from sentinel.delivery.email_digest import render_daily_digest
from sentinel.delivery.telegram_bot import format_daily_digest_intro, format_daily_digest_message


class FakeTelegramBot:
    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.shutdown_called = False

    async def send_message(self, **kwargs) -> None:
        self.messages.append(kwargs)

    async def shutdown(self) -> None:
        self.shutdown_called = True


class FakeSendGridClient:
    def __init__(self) -> None:
        self.sent_messages = []

    def send(self, message):
        self.sent_messages.append(message)
        return {"status_code": 202}


class FakeSession:
    def __init__(self, storage: list[FeedbackRecord]) -> None:
        self.storage = storage

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def add(self, record: FeedbackRecord) -> None:
        self.storage.append(record)

    async def commit(self) -> None:
        return None


class FakeSessionFactory:
    def __init__(self) -> None:
        self.storage: list[FeedbackRecord] = []

    def __call__(self) -> FakeSession:
        return FakeSession(self.storage)


class FakeQuery:
    def __init__(self, data: str, user_id: str) -> None:
        self.data = data
        self.from_user = type("User", (), {"id": user_id})
        self.answered = False
        self.answer_text = None
        self.show_alert = None

    async def answer(self, text: str | None = None, show_alert: bool | None = None) -> None:
        self.answered = True
        self.answer_text = text
        self.show_alert = show_alert


class BrokenSessionFactory:
    def __call__(self):
        raise RuntimeError("db unavailable")


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "thresholds": {"alert_score": 70, "rule_score": 50, "karpathy_experiments": 25, "karpathy_budget_mins": 30},
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "12345",
                "enable_telegram_immediate_alerts": True,
                "telegram_max_alerts_per_run": 3,
                "enable_email": False,
                "sendgrid_key": "key",
                "email_from": "sentinel@example.com",
                "email_to": ["analyst@example.com"],
            },
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "redis://localhost:6379/0"},
        }
    )


@pytest.mark.asyncio
async def test_delivery_agent_sends_immediate_alerts_and_counts_digest_candidates() -> None:
    telegram_bot = FakeTelegramBot()
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    now = datetime.now(UTC)
    items = [
        {
            "id": str(uuid4()),
            "value": "8.8.8.8",
            "type": "ipv4",
            "source": "feed-a",
            "risk_score": 80,
            "severity": "high",
            "mitre_techniques": ["T1071"],
            "mitre_tactics": ["command and control"],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "example.org",
            "type": "domain",
            "source": "feed-b",
            "risk_score": 55,
            "severity": "medium",
            "mitre_techniques": ["T1566.001"],
            "mitre_tactics": ["initial access"],
            "last_seen": now - timedelta(hours=2),
        },
        {
            "id": str(uuid4()),
            "value": "old.example",
            "type": "domain",
            "source": "feed-c",
            "risk_score": 60,
            "severity": "medium",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now - timedelta(days=2),
        },
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert result.digest_candidates == 2
    assert len(telegram_bot.messages) == 1
    assert "SENTINEL Alert" in telegram_bot.messages[0]["text"]
    assert "Intel Links:" in telegram_bot.messages[0]["text"]
    assert telegram_bot.messages[0]["reply_markup"] is not None


@pytest.mark.asyncio
async def test_delivery_agent_limits_telegram_alert_burst() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 35
    settings.delivery.telegram_max_alerts_per_run = 2
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    items = [
        {"id": str(uuid4()), "value": "a.example", "type": "domain", "source": "feed-a", "risk_score": 40, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
        {"id": str(uuid4()), "value": "b.example", "type": "domain", "source": "feed-a", "risk_score": 39, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
        {"id": str(uuid4()), "value": "c.example", "type": "domain", "source": "feed-a", "risk_score": 38, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 2
    assert len(telegram_bot.messages) == 2


@pytest.mark.asyncio
async def test_delivery_agent_groups_same_writeup_into_one_immediate_alert() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 35
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {
            "id": str(uuid4()),
            "value": "c559cc68986933200fd5d9e4388e2f58",
            "type": "md5",
            "source": "crimeware-fresh",
            "risk_score": 84,
            "severity": "high",
            "reference_url": "https://cyberpress.org/sharkloader-in-memory-beacon-attack/",
            "source_title": "CyberPress SharkLoader in-memory beacon attack",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "b3352b42432dedc4a519f011dc8b5d5a",
            "type": "md5",
            "source": "crimeware-fresh",
            "risk_score": 84,
            "severity": "high",
            "reference_url": "https://cyberpress.org/sharkloader-in-memory-beacon-attack/",
            "source_title": "CyberPress SharkLoader in-memory beacon attack",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert len(telegram_bot.messages) == 1
    assert "CyberPress SharkLoader in-memory beacon attack" in telegram_bot.messages[0]["text"]
    assert "HIGH | Score 84.00 | 2 IOC(s)" in telegram_bot.messages[0]["text"]
    assert "[md5] c559cc68986933200fd5d9e4388e2f58" in telegram_bot.messages[0]["text"]
    assert "[md5] b3352b42432dedc4a519f011dc8b5d5a" in telegram_bot.messages[0]["text"]
    assert "malware artifact hash" in telegram_bot.messages[0]["text"]
    assert telegram_bot.messages[0]["reply_markup"] is not None


@pytest.mark.asyncio
async def test_delivery_agent_can_disable_immediate_telegram_alerts() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 35
    settings.delivery.enable_telegram_immediate_alerts = False
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    items = [
        {"id": str(uuid4()), "value": "a.example", "type": "domain", "source": "feed-a", "risk_score": 40, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
        {"id": str(uuid4()), "value": "b.example", "type": "domain", "source": "feed-a", "risk_score": 39, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 0
    assert len(telegram_bot.messages) == 0


@pytest.mark.asyncio
async def test_delivery_agent_records_feedback_from_callback() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())
    query = FakeQuery(data=f"false_positive:{ioc_id}", user_id="42")

    record = await agent.handle_callback_query(query)

    assert query.answered is True
    assert query.answer_text == "Recorded: false positive"
    assert query.show_alert is True
    assert str(record.ioc_id) == ioc_id
    assert record.verdict == "false_positive"
    assert session_factory.storage[0].analyst_id == "42"


@pytest.mark.asyncio
async def test_delivery_agent_acknowledges_duplicate_feedback_without_duplicating_row() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())

    first = FakeQuery(data=f"confirmed:{ioc_id}", user_id="42")
    second = FakeQuery(data=f"confirmed:{ioc_id}", user_id="42")

    await agent.handle_callback_query(first)
    record = await agent.handle_callback_query(second)

    assert first.answer_text == "Recorded: confirmed"
    assert first.show_alert is True
    assert second.answer_text == "Already recorded: confirmed"
    assert second.show_alert is True
    assert len(session_factory.storage) == 1
    assert record.verdict == "confirmed"


@pytest.mark.asyncio
async def test_delivery_agent_acknowledges_callback_failure() -> None:
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=BrokenSessionFactory(),
    )
    query = FakeQuery(data=f"confirmed:{uuid4()}", user_id="42")

    with pytest.raises(RuntimeError, match="db unavailable"):
        await agent.handle_callback_query(query)

    assert query.answered is True
    assert query.answer_text == "Failed to record feedback"
    assert query.show_alert is True


@pytest.mark.asyncio
async def test_delivery_agent_renders_and_sends_daily_digest() -> None:
    settings = build_settings().model_copy(deep=True)
    settings.delivery.enable_email = True
    sendgrid_client = FakeSendGridClient()
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=sendgrid_client,
        session_factory=FakeSessionFactory(),
    )
    digest_items = [
        asdict(
            ScoredIOC(
                value="8.8.4.4",
                type="ipv4",
                source="feed-a",
                risk_score=72.0,
                severity="high",
                mitre_techniques=["T1071"],
                mitre_tactics=["command and control"],
            )
        )
    ]

    response = await agent.daily_digest(digest_items)

    assert response["telegram"]["status"] == "sent"
    assert response["email"]["status"] == "sent"
    assert len(sendgrid_client.sent_messages) == 1
    assert len(telegram_bot.messages) == 2
    assert "SENTINEL Daily Digest" in telegram_bot.messages[0]["text"]
    assert "SENTINEL Daily Digest 1/1" in telegram_bot.messages[1]["text"]
    payload = sendgrid_client.sent_messages[0].get()
    assert payload["subject"] == "SENTINEL Daily Digest"
    assert "8.8.4.4" in payload["content"][0]["value"]


@pytest.mark.asyncio
async def test_delivery_agent_skips_daily_digest_when_email_disabled() -> None:
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )

    response = await agent.daily_digest([])

    assert response["telegram"]["status"] == "sent"
    assert response["email"]["status"] == "disabled"
    assert "No qualifying IOC activity" in telegram_bot.messages[0]["text"]
    assert len(telegram_bot.messages) == 1


@pytest.mark.asyncio
async def test_delivery_agent_aclose_shuts_down_telegram_bot() -> None:
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )

    await agent.aclose()

    assert telegram_bot.shutdown_called is True


@pytest.mark.asyncio
async def test_delivery_agent_daily_digest_sends_top_5_by_risk_score() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.delivery.telegram_daily_digest_limit = 5
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    items = [
        {
            "value": f"ioc-{index}",
            "type": "domain",
            "source": "otx",
            "risk_score": float(index),
            "severity": "informational",
            "related_cves": [],
            "external_links": {},
        }
        for index in range(12)
    ]

    response = await agent.daily_digest(items)

    assert response["count"] == 5
    assert len(telegram_bot.messages) == 6
    assert "Delivering 5 analyst-ready IOC card(s)" in telegram_bot.messages[0]["text"]
    assert "SENTINEL Daily Digest 1/5" in telegram_bot.messages[1]["text"]
    assert "IOC: ioc-11" in telegram_bot.messages[1]["text"]
    assert "SENTINEL Daily Digest 5/5" in telegram_bot.messages[5]["text"]
    assert "IOC: ioc-7" in telegram_bot.messages[5]["text"]
    joined = "\n".join(message["text"] for message in telegram_bot.messages)
    assert "IOC: ioc-0\n" not in joined
    assert "IOC: ioc-1\n" not in joined
    assert "IOC: ioc-6\n" not in joined


def test_format_daily_digest_intro_for_non_empty_and_empty_digest() -> None:
    rendered = format_daily_digest_intro(generated_at="2026-04-11T05:21:51+00:00", count=10, limit=5)
    assert "Delivering 5 analyst-ready IOC card(s)" in rendered

    empty = format_daily_digest_intro(generated_at="2026-04-11T05:21:51+00:00", count=0, limit=5)
    assert "No qualifying IOC activity" in empty


def test_render_daily_digest_includes_ioc_rows() -> None:
    html = render_daily_digest(
        [
            {
                "value": "example.org",
                "type": "domain",
                "source": "feed-a",
                "risk_score": 55.0,
                "severity": "medium",
                "mitre_techniques": ["T1566.001"],
            }
        ],
        generated_at="2026-04-08T12:00:00+00:00",
    )

    assert "example.org" in html
    assert "T1566.001" in html


def test_format_daily_digest_message_limits_and_shows_cves_and_links() -> None:
    rendered = format_daily_digest_message(
        items=[
            {
                "value": "bad.example",
                "type": "domain",
                "source": "otx",
                "risk_score": 82.3,
                "severity": "high",
                "source_title": "OTX Pulse Example",
                "related_cves": ["CVE-2026-1234"],
                "external_links": {
                    "VirusTotal": "https://www.virustotal.com/gui/domain/bad.example",
                    "OTX": "https://otx.alienvault.com/browse/global/pulses?q=bad.example",
                },
            }
        ],
        generated_at="2026-04-09T07:00:00+00:00",
        limit=10,
    )

    assert "SENTINEL Daily Digest" in rendered
    assert "OTX Pulse Example" in rendered
    assert "CVE-2026-1234" in rendered
    assert "VirusTotal:" in rendered


def test_format_daily_digest_message_stays_within_telegram_limit() -> None:
    items = [
        {
            "value": f"very-long-ioc-value-{index}-" + ("x" * 120),
            "type": "domain",
            "source": "otx",
            "risk_score": 90 - index,
            "severity": "high",
            "source_title": "Very long source intel title " + ("y" * 120),
            "related_cves": [f"CVE-2026-{1000 + index}"],
            "external_links": {
                "VirusTotal": "https://www.virustotal.com/gui/domain/" + ("z" * 180),
                "OTX": "https://otx.alienvault.com/browse/global/pulses?q=" + ("q" * 180),
            },
        }
        for index in range(10)
    ]

    rendered = format_daily_digest_message(
        items=items,
        generated_at="2026-04-10T20:30:00+00:00",
        limit=10,
    )

    assert len(rendered) <= 3500
    assert "Omitted" in rendered or "10. " in rendered


def test_format_alert_message_shows_ip_enrichment_placeholders() -> None:
    from sentinel.delivery.telegram_bot import format_alert_message

    rendered = format_alert_message(
        value="162.243.103.246",
        ioc_type="ipv4",
        source="feodotracker",
        risk_score=24.19,
        severity="informational",
        last_seen="2026-04-15T07:30:00+00:00",
        source_title="Feodo IP Blocklist",
        reference_url="https://feodotracker.abuse.ch/",
        related_cves=["CVE-2026-12345"],
        vt_detections=None,
        abuse_confidence=0,
        shodan_ports=[],
        external_links={
            "VirusTotal": "https://www.virustotal.com/gui/ip-address/162.243.103.246",
            "AbuseIPDB": "https://www.abuseipdb.com/check/162.243.103.246",
            "Shodan": "https://www.shodan.io/host/162.243.103.246",
        },
        mitre_techniques=[],
        mitre_tactics=[],
    )

    assert "AbuseIPDB confidence: 0%" in rendered
    assert "Shodan ports: none reported" in rendered
    assert "https://www.shodan.io/host/162.243.103.246" in rendered
    assert "Observed In Feed: 2026-04-15 07:30 UTC" in rendered
    assert "Source Intel: Feodo IP Blocklist" in rendered
    assert "Source Link: https://feodotracker.abuse.ch/" in rendered
    assert "Related CVEs: CVE-2026-12345" in rendered


def test_format_alert_message_shows_hash_intel_links() -> None:
    from sentinel.delivery.telegram_bot import format_alert_message

    rendered = format_alert_message(
        value="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ioc_type="sha256",
        source="otx",
        risk_score=91.0,
        severity="critical",
        last_seen="2026-04-15T08:15:00+00:00",
        source_title="Stealer Campaign Impacting SLTT macOS Users",
        reference_url="https://otx.alienvault.com/pulse/69d7ed2e323d7edb856fa161",
        related_cves=[],
        vt_detections=18,
        abuse_confidence=None,
        shodan_ports=[],
        external_links={
            "VirusTotal": "https://www.virustotal.com/gui/file/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "OTX": "https://otx.alienvault.com/browse/global/pulses?q=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        },
        mitre_techniques=["T1059"],
        mitre_tactics=["execution"],
    )

    assert "VirusTotal detections: 18" in rendered
    assert "https://www.virustotal.com/gui/file/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "https://otx.alienvault.com/browse/global/pulses?q=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "Observed In Feed: 2026-04-15 08:15 UTC" in rendered
    assert "Source Intel: Stealer Campaign Impacting SLTT macOS Users" in rendered


def test_grouped_alert_message_renders_clean_sections_and_ioc_summaries() -> None:
    from sentinel.delivery.telegram_bot import format_grouped_alert_message

    rendered = format_grouped_alert_message(
        source="discovery:arcticwolf.com",
        risk_score=78.0,
        severity="high",
        iocs=[
            {"type": "url", "value": "https://github.com/antivirus-free-bitdefender"},
            {"type": "domain", "value": "bentleyvazquezpvey.github.io"},
            {"type": "sha256", "value": "a" * 64},
        ],
        last_seen="2026-07-05T00:58:00+00:00",
        source_title="Security Bulletin: GitHub Impersonation Deploys Information Stealer - Arctic Wolf",
        reference_url="https://arcticwolf.com/resources/blog/security-bulletin-github-impersonation-deploys-information-stealer/",
        related_cves=[],
        corroboration_sources=1,
        mitre_techniques=["T1583.001"],
        mitre_tactics=["resource development"],
    )

    assert "HIGH | Score 78.00 | 3 IOC(s)" in rendered
    assert "Observed 2026-07-05 00:58 UTC | Corroboration 1 source(s)" in rendered
    assert "Article https://arcticwolf.com/resources/blog/security-bulletin-github-impersonation-deploys-information-stealer/" in rendered
    assert "\nIOCs\n" in rendered
    assert "- [url] https://github.com/antivirus-free-bitdefender" in rendered
    assert "GitHub repo or path used by attacker" in rendered
    assert "- [domain] bentleyvazquezpvey.github.io" in rendered
    assert "domain hosting attacker-controlled content" in rendered
    assert "- [sha256] " in rendered
    assert "malware artifact hash" in rendered
    assert "\nContext\n" in rendered

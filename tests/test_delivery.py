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
    def __init__(self, storage: list[FeedbackRecord], removed_iocs: set[str] | None = None) -> None:
        self.storage = storage
        self.removed_iocs = removed_iocs if removed_iocs is not None else set()

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def add(self, record: FeedbackRecord) -> None:
        self.storage.append(record)

    async def commit(self) -> None:
        return None

    async def remove_ioc(self, ioc_id) -> bool:
        normalized = str(ioc_id)
        if normalized in self.removed_iocs:
            return False
        self.removed_iocs.add(normalized)
        return True


class FakeSessionFactory:
    def __init__(self) -> None:
        self.storage: list[FeedbackRecord] = []
        self.removed_iocs: set[str] = set()

    def __call__(self) -> FakeSession:
        return FakeSession(self.storage, self.removed_iocs)


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
    assert "\nIntel Links\n" in telegram_bot.messages[0]["text"]
    assert telegram_bot.messages[0]["reply_markup"] is not None


@pytest.mark.asyncio
async def test_delivery_agent_limits_telegram_alert_burst() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.delivery.telegram_max_alerts_per_run = 2
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    items = [
        {"id": str(uuid4()), "value": "a.example", "type": "domain", "source": "feed-a", "risk_score": 80, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
        {"id": str(uuid4()), "value": "b.example", "type": "domain", "source": "feed-a", "risk_score": 79, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
        {"id": str(uuid4()), "value": "c.example", "type": "domain", "source": "feed-a", "risk_score": 78, "severity": "high", "mitre_techniques": [], "mitre_tactics": [], "last_seen": datetime.now(UTC)},
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
async def test_delivery_agent_includes_lower_score_sibling_iocs_from_same_article() -> None:
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
            "source": "discovery:cyberpress.org",
            "risk_score": 74.0,
            "severity": "high",
            "reference_url": "https://cyberpress.org/sharkloader-in-memory-beacon-attack/",
            "source_title": "SharkLoader Malware Deploys Cobalt Strike Beacon Through Stealthy In-Memory Execution - cyberpress.org",
            "mitre_techniques": ["T1593.002"],
            "mitre_tactics": ["reconnaissance"],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "b3352b42432dedc4a519f011dc8b5d5a",
            "type": "md5",
            "source": "discovery:cyberpress.org",
            "risk_score": 31.0,
            "severity": "informational",
            "reference_url": "https://cyberpress.org/sharkloader-in-memory-beacon-attack/",
            "source_title": "SharkLoader Malware Deploys Cobalt Strike Beacon Through Stealthy In-Memory Execution - cyberpress.org",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert len(telegram_bot.messages) == 1
    assert "HIGH | Score 74.00 | 2 IOC(s)" in telegram_bot.messages[0]["text"]
    assert "[md5] c559cc68986933200fd5d9e4388e2f58" in telegram_bot.messages[0]["text"]
    assert "[md5] b3352b42432dedc4a519f011dc8b5d5a" in telegram_bot.messages[0]["text"]


@pytest.mark.asyncio
async def test_delivery_agent_allows_curated_ioc_section_items_below_global_immediate_threshold() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 70
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
            "value": "loader-cdn.badcorp.top",
            "type": "domain",
            "source": "discovery:publisher.example",
            "risk_score": 62.0,
            "severity": "medium",
            "reference_url": "https://publisher.example/report",
            "source_title": "Publisher report with IOCs",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
            "provenance": "discovery",
            "extraction_mode": "ioc_section",
            "corroboration_sources": 1,
            "attributes": {"provenance": "discovery", "extraction_mode": "ioc_section"},
        }
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert result.digest_candidates == 1
    assert len(telegram_bot.messages) == 1
    assert "Publisher report with IOCs" in telegram_bot.messages[0]["text"]


@pytest.mark.asyncio
async def test_delivery_agent_allows_corroborated_curated_context_at_intermediate_threshold() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 70
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    items = [
        {
            "id": str(uuid4()),
            "value": "https://bad.example/dropper",
            "type": "url",
            "source": "securelist_blog",
            "risk_score": 66.0,
            "severity": "medium",
            "reference_url": "https://securelist.example/report",
            "source_title": "Writeup with corroborated infrastructure",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": datetime.now(UTC),
            "provenance": "writeup",
            "extraction_mode": "fallback",
            "corroboration_sources": 2,
            "attributes": {"provenance": "writeup", "extraction_mode": "fallback"},
        }
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert len(telegram_bot.messages) == 1


@pytest.mark.asyncio
async def test_delivery_agent_does_not_bypass_thresholds_for_low_score_web_discovery() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 70
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=FakeSendGridClient(),
        session_factory=FakeSessionFactory(),
    )
    items = [
        {
            "id": str(uuid4()),
            "value": "publisher.example/bad",
            "type": "url",
            "source": "discovery:publisher.example",
            "risk_score": 12.0,
            "severity": "informational",
            "reference_url": "https://publisher.example/post",
            "source_title": "Publisher writeup",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": datetime.now(UTC),
            "provenance": "discovery",
            "extraction_mode": "fallback",
            "corroboration_sources": 1,
            "attributes": {"provenance": "discovery", "extraction_mode": "fallback"},
        }
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 0
    assert result.digest_candidates == 0
    assert len(telegram_bot.messages) == 0


@pytest.mark.asyncio
async def test_delivery_agent_uses_recent_medium_score_fallback_for_digest_when_policy_qualifies_none() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 60
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
            "value": "weak.example",
            "type": "domain",
            "source": "discovery:publisher.example",
            "risk_score": 12.0,
            "severity": "informational",
            "last_seen": now,
            "provenance": "discovery",
            "extraction_mode": "fallback",
            "attributes": {"provenance": "discovery", "extraction_mode": "fallback"},
        },
        {
            "id": str(uuid4()),
            "value": "medium.example",
            "type": "domain",
            "source": "feed-a",
            "risk_score": 31.0,
            "severity": "informational",
            "last_seen": now,
            "provenance": "feed",
            "extraction_mode": "feed",
            "attributes": {"provenance": "feed", "extraction_mode": "feed"},
        },
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 0
    assert result.digest_candidates == 1


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
async def test_delivery_agent_removes_ioc_from_database_via_callback() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())
    query = FakeQuery(data=f"remove_ioc:{ioc_id}", user_id="42")

    removed = await agent.handle_callback_query(query)

    assert removed is True
    assert query.answered is True
    assert query.answer_text == "Removed IOC from database"
    assert query.show_alert is True
    assert ioc_id in session_factory.removed_iocs


@pytest.mark.asyncio
async def test_delivery_agent_acknowledges_repeated_ioc_removal() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())

    first = FakeQuery(data=f"remove_ioc:{ioc_id}", user_id="42")
    second = FakeQuery(data=f"remove_ioc:{ioc_id}", user_id="42")

    assert await agent.handle_callback_query(first) is True
    assert await agent.handle_callback_query(second) is False
    assert first.answer_text == "Removed IOC from database"
    assert second.answer_text == "IOC was already absent"


@pytest.mark.asyncio
async def test_delivery_agent_appends_retriage_feedback_event() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())

    first = FakeQuery(data=f"confirmed:{ioc_id}", user_id="42")
    second = FakeQuery(data=f"false_positive:{ioc_id}", user_id="42")

    await agent.handle_callback_query(first)
    record = await agent.handle_callback_query(second)

    assert len(session_factory.storage) == 2
    assert [item.verdict for item in session_factory.storage] == ["confirmed", "false_positive"]
    assert second.answer_text == "Recorded: false positive"
    assert record.verdict == "false_positive"


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
    assert "- [domain] ioc-11" in telegram_bot.messages[1]["text"]
    assert "SENTINEL Daily Digest 5/5" in telegram_bot.messages[5]["text"]
    assert "- [domain] ioc-7" in telegram_bot.messages[5]["text"]
    joined = "\n".join(message["text"] for message in telegram_bot.messages)
    assert "- [domain] ioc-0" not in joined
    assert "- [domain] ioc-2" not in joined
    assert "- [domain] ioc-6" not in joined


@pytest.mark.asyncio
async def test_delivery_agent_daily_digest_groups_all_iocs_from_same_article() -> None:
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {
            "id": str(uuid4()),
            "value": "alpha.bad.example",
            "type": "domain",
            "source": "securelist_blog",
            "risk_score": 44.0,
            "severity": "informational",
            "source_title": "Same article with multiple IOCs",
            "reference_url": "https://securelist.example/report",
            "related_cves": [],
            "external_links": {},
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "beta.bad.example",
            "type": "domain",
            "source": "securelist_blog",
            "risk_score": 43.0,
            "severity": "informational",
            "source_title": "Same article with multiple IOCs",
            "reference_url": "https://securelist.example/report",
            "related_cves": [],
            "external_links": {},
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
    ]

    response = await agent.daily_digest(items)

    assert response["count"] == 1
    assert len(telegram_bot.messages) == 2
    assert "SENTINEL Daily Digest 1/1" in telegram_bot.messages[1]["text"]
    assert "2 IOC(s)" in telegram_bot.messages[1]["text"]
    assert "alpha.bad.example" in telegram_bot.messages[1]["text"]
    assert "beta.bad.example" in telegram_bot.messages[1]["text"]


@pytest.mark.asyncio
async def test_delivery_agent_daily_digest_merges_same_campaign_across_duplicate_writeups() -> None:
    telegram_bot = FakeTelegramBot()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {
            "id": str(uuid4()),
            "value": "goserpent-a.bad.example",
            "type": "domain",
            "source": "securelist_blog",
            "risk_score": 36.48,
            "severity": "informational",
            "source_title": "GoSerpent: a persistent threat evolves with sophisticated data collection and exfiltration",
            "reference_url": "https://securelist.example/goserpent",
            "related_cves": [],
            "external_links": {},
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "goserpent-b.bad.example",
            "type": "domain",
            "source": "gbhackers_blog",
            "risk_score": 36.39,
            "severity": "informational",
            "source_title": "GoSerpent Silently Steals Government Files for Weeks Before Sending Them to Hackers",
            "reference_url": "https://gbhackers.com/goserpent-steals-government-files/",
            "related_cves": [],
            "external_links": {},
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
    ]

    response = await agent.daily_digest(items)

    assert response["count"] == 1
    assert len(telegram_bot.messages) == 2
    assert "1/1" in telegram_bot.messages[1]["text"]
    assert "2 IOC(s)" in telegram_bot.messages[1]["text"]
    assert "goserpent-a.bad.example" in telegram_bot.messages[1]["text"]
    assert "goserpent-b.bad.example" in telegram_bot.messages[1]["text"]


@pytest.mark.asyncio
async def test_delivery_agent_requires_digest_threshold_for_web_discovery() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {
            "value": "low-score-discovery.example",
            "type": "domain",
            "source": "discovery:publisher.example",
            "risk_score": 5.0,
            "severity": "informational",
            "related_cves": [],
            "external_links": {},
            "last_seen": now,
            "provenance": "discovery",
            "extraction_mode": "fallback",
            "attributes": {"provenance": "discovery", "extraction_mode": "fallback"},
        },
        {
            "value": "stale-discovery.example",
            "type": "domain",
            "source": "discovery:publisher.example",
            "risk_score": 5.0,
            "severity": "informational",
            "related_cves": [],
            "external_links": {},
            "last_seen": now - timedelta(days=2),
            "provenance": "discovery",
            "extraction_mode": "fallback",
            "attributes": {"provenance": "discovery", "extraction_mode": "fallback"},
        },
    ]

    result = await agent.run(items)

    assert result.digest_candidates == 0


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

    assert "INFORMATIONAL | Score 24.19 | 1 IOC" in rendered
    assert "Source feodotracker" in rendered
    assert "AbuseIPDB confidence: 0%" in rendered
    assert "Shodan ports: none reported" in rendered
    assert "https://www.shodan.io/host/162.243.103.246" in rendered
    assert "Observed 2026-04-15 07:30 UTC | Corroboration 1 source(s)" in rendered
    assert "Feodo IP Blocklist" in rendered
    assert "Article https://feodotracker.abuse.ch/" in rendered
    assert "CVEs CVE-2026-12345" in rendered
    assert "\nIOC\n" in rendered
    assert "- [ipv4] 162.243.103.246" in rendered
    assert "IPv4 infrastructure indicator" in rendered


def test_format_grouped_alert_message_shows_ioc_section_labels() -> None:
    from sentinel.delivery.telegram_bot import format_grouped_alert_message

    rendered = format_grouped_alert_message(
        source="securelist_blog",
        risk_score=37.14,
        severity="informational",
        source_title="HelloNet campaign",
        reference_url="https://securelist.example/hellonet",
        iocs=[
            {"type": "md5", "value": "16c211c96735f2fae9361b89bd7a31bf", "section_label": "HelloBackdoor"},
            {"type": "md5", "value": "6001829a128fe264b4403138700c11a8", "section_label": "HelloBackdoor Droppers"},
            {"type": "ipv4", "value": "5.39.253.206", "section_label": "wtsapi32.dll"},
        ],
        mitre_techniques=[],
        mitre_tactics=[],
    )

    assert "HelloBackdoor" in rendered
    assert "HelloBackdoor Droppers" in rendered
    assert "wtsapi32.dll" in rendered
    assert "[md5] 16c211c96735f2fae9361b89bd7a31bf" in rendered
    assert "[ipv4] 5.39.253.206" in rendered


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

    assert "CRITICAL | Score 91.00 | 1 IOC" in rendered
    assert "VirusTotal detections: 18" in rendered
    assert "https://www.virustotal.com/gui/file/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "https://otx.alienvault.com/browse/global/pulses?q=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "Observed 2026-04-15 08:15 UTC | Corroboration 1 source(s)" in rendered
    assert "Stealer Campaign Impacting SLTT macOS Users" in rendered
    assert "- [sha256] deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "malware artifact hash" in rendered


def test_format_alert_message_uses_threatfox_metadata_for_single_ioc_summary() -> None:
    from sentinel.delivery.telegram_bot import format_alert_message

    rendered = format_alert_message(
        value="94.154.43.12",
        ioc_type="ipv4",
        source="threatfox",
        risk_score=63.8,
        severity="medium",
        last_seen="2026-07-05T02:18:00+00:00",
        source_title="Indicator that identifies a botnet command&control server (C&C)",
        reference_url="https://threatfox.abuse.ch/ioc/1844378/",
        related_cves=[],
        vt_detections=None,
        abuse_confidence=100,
        shodan_ports=[80],
        external_links={
            "VirusTotal": "https://www.virustotal.com/gui/ip-address/94.154.43.12",
            "AbuseIPDB": "https://www.abuseipdb.com/check/94.154.43.12",
            "Shodan": "https://www.shodan.io/host/94.154.43.12",
        },
        mitre_techniques=["T1559.001"],
        mitre_tactics=["execution"],
        attributes={
            "threat_type": "botnet_cc",
            "malware": "Katana",
            "malware_printable": "Mirai",
        },
    )

    assert "MEDIUM | Score 63.80 | 1 IOC" in rendered
    assert "Source ThreatFox | botnet_cc | Mirai (Katana)" in rendered
    assert "- [ipv4] 94.154.43.12" in rendered
    assert "botnet C2 IP tied to Mirai" in rendered


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

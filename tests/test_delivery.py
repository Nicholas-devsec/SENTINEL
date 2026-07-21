from __future__ import annotations
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import FeedConfig, SentinelSettings
from sentinel.db.models import FeedbackRecord
from sentinel.delivery.email_digest import render_daily_digest
from sentinel.delivery.telegram_bot import build_feedback_markup, format_daily_digest_intro, format_daily_digest_message


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
        self.message = FakeCallbackMessage()

    async def answer(self, text: str | None = None, show_alert: bool | None = None) -> None:
        self.answered = True
        self.answer_text = text
        self.show_alert = show_alert


class FakeCallbackMessage:
    def __init__(self, text: str = "SENTINEL Alert") -> None:
        self.text = text
        self.html_text = text
        self.caption = None
        self.html_caption = None
        self.edited_text: str | None = None
        self.edited_caption: str | None = None
        self.parse_mode: str | None = None
        self.reply_markup = object()
        self.replies: list[dict] = []

    async def edit_text(self, text: str, parse_mode=None, reply_markup=None) -> None:
        self.text = text
        self.html_text = text
        self.edited_text = text
        self.parse_mode = parse_mode
        self.reply_markup = reply_markup

    async def edit_caption(self, caption: str, parse_mode=None, reply_markup=None) -> None:
        self.caption = caption
        self.html_caption = caption
        self.edited_caption = caption
        self.parse_mode = parse_mode
        self.reply_markup = reply_markup

    async def edit_reply_markup(self, reply_markup=None) -> None:
        self.reply_markup = reply_markup

    async def reply_text(self, text: str, **kwargs) -> None:
        self.replies.append({"text": text, **kwargs})


class BrokenEditCallbackMessage(FakeCallbackMessage):
    async def edit_text(self, text: str, parse_mode=None, reply_markup=None) -> None:
        raise RuntimeError("edit rejected")


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


def test_feedback_markup_uses_true_positive_and_false_positive_labels() -> None:
    markup = build_feedback_markup("ioc-123")
    buttons = markup.inline_keyboard[0]

    assert buttons[0].text == "True Positive"
    assert buttons[0].callback_data == "confirmed:ioc-123"
    assert buttons[1].text == "False Positive"
    assert buttons[1].callback_data == "false_positive:ioc-123"


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
    assert "<b>Evidence</b>:" in telegram_bot.messages[0]["text"]
    assert telegram_bot.messages[0]["parse_mode"] == "HTML"
    assert telegram_bot.messages[0]["reply_markup"] is not None


@pytest.mark.asyncio
async def test_delivery_agent_limits_telegram_alert_burst() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.workflow.telegram_feed_alert_limit_per_run = 2
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
    assert "<b>HIGH</b> · Score 84.00" in telegram_bot.messages[0]["text"]
    assert "<b>IOCs (2)</b>" in telegram_bot.messages[0]["text"]
    assert "<code>c559cc68986933200fd5d9e4388e2f58</code> [md5]" in telegram_bot.messages[0]["text"]
    assert "<code>b3352b42432dedc4a519f011dc8b5d5a</code> [md5]" in telegram_bot.messages[0]["text"]
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
    assert "<b>HIGH</b> · Score 74.00" in telegram_bot.messages[0]["text"]
    assert "<b>IOCs (2)</b>" in telegram_bot.messages[0]["text"]
    assert "<code>c559cc68986933200fd5d9e4388e2f58</code> [md5]" in telegram_bot.messages[0]["text"]
    assert "<code>b3352b42432dedc4a519f011dc8b5d5a</code> [md5]" in telegram_bot.messages[0]["text"]


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
async def test_delivery_agent_promotes_fresh_trusted_feed_feedback_candidate_when_no_immediate_alerts() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.thresholds.alert_score = 70
    settings.thresholds.feedback_candidate_score = 19
    settings.workflow.telegram_feed_alert_limit_per_run = 2
    settings.delivery.telegram_max_alerts_per_run = 2
    settings.sources.feeds = [
        FeedConfig(name="threatfox", url="https://threatfox.example/api", trust=0.94, enabled=True),
        FeedConfig(name="weak-feed", url="https://weak.example/feed", trust=0.50, enabled=True),
    ]
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
            "value": "137.184.135.42",
            "type": "ipv4",
            "source": "threatfox",
            "risk_score": 24.0,
            "severity": "informational",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
        {
            "id": str(uuid4()),
            "value": "low.example",
            "type": "domain",
            "source": "weak-feed",
            "risk_score": 24.0,
            "severity": "informational",
            "mitre_techniques": [],
            "mitre_tactics": [],
            "last_seen": now,
        },
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    assert len(telegram_bot.messages) == 1
    assert "SENTINEL Feedback Candidate" in telegram_bot.messages[0]["text"]


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
    assert query.answer_text == "Recorded FP and suppressed 1 IOC(s)"
    assert query.show_alert is True
    assert query.message.edited_text is not None
    assert "Feedback recorded: False Positive" in query.message.text
    assert query.message.parse_mode == "HTML"
    assert query.message.reply_markup is None
    assert "suppressed" in query.answer_text
    assert record == 1
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
    assert "Feedback recorded: True Positive" in first.message.text
    assert second.answer_text == "Already recorded: confirmed"
    assert second.show_alert is True
    assert "Feedback already recorded: True Positive" in second.message.text
    assert len(session_factory.storage) == 1
    assert record.verdict == "confirmed"


@pytest.mark.asyncio
async def test_delivery_agent_confirms_needs_review_callback() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())
    query = FakeQuery(data=f"needs_review:{ioc_id}", user_id="42")

    record = await agent.handle_callback_query(query)

    assert query.answer_text == "Recorded: needs review"
    assert query.show_alert is True
    assert "Feedback recorded: Needs Review" in query.message.text
    assert query.message.reply_markup is None
    assert record.verdict == "needs_review"


@pytest.mark.asyncio
async def test_delivery_agent_sends_confirmation_reply_when_message_edit_fails() -> None:
    session_factory = FakeSessionFactory()
    agent = DeliveryAgent(
        settings=build_settings(),
        telegram_bot=FakeTelegramBot(),
        sendgrid_client=FakeSendGridClient(),
        session_factory=session_factory,
    )
    ioc_id = str(uuid4())
    query = FakeQuery(data=f"confirmed:{ioc_id}", user_id="42")
    query.message = BrokenEditCallbackMessage()

    record = await agent.handle_callback_query(query)

    assert query.answer_text == "Recorded: confirmed"
    assert query.show_alert is True
    assert query.message.replies == [
        {
            "text": "Feedback confirmation: Feedback recorded: True Positive",
            "disable_notification": True,
        }
    ]
    assert record.verdict == "confirmed"


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
    assert second.answer_text == "Recorded FP and suppressed 1 IOC(s)"
    assert "Feedback recorded: False Positive" in second.message.text
    assert record == 1


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
    settings.workflow.telegram_feed_alert_limit_per_run = 5
    settings.workflow.telegram_article_alert_limit_per_run = 0
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
    assert "<code>ioc-11</code> [domain]" in telegram_bot.messages[1]["text"]
    assert "SENTINEL Daily Digest 5/5" in telegram_bot.messages[5]["text"]
    assert "<code>ioc-7</code> [domain]" in telegram_bot.messages[5]["text"]
    joined = "\n".join(message["text"] for message in telegram_bot.messages)
    assert "<code>ioc-0</code>" not in joined
    assert "<code>ioc-2</code>" not in joined
    assert "<code>ioc-6</code>" not in joined


@pytest.mark.asyncio
async def test_delivery_agent_applies_separate_article_and_feed_limits() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.delivery.telegram_daily_digest_limit = 10
    settings.workflow.telegram_feed_alert_limit_per_run = 2
    settings.workflow.telegram_article_alert_limit_per_run = 1
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {"id": str(uuid4()), "value": "feed-1", "type": "domain", "source": "threatfox", "risk_score": 90.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "feed-2", "type": "domain", "source": "threatfox", "risk_score": 89.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "feed-3", "type": "domain", "source": "threatfox", "risk_score": 88.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "art-1-a", "type": "domain", "source": "securelist_blog", "risk_score": 87.0, "severity": "high", "last_seen": now, "reference_url": "https://a.example/report", "source_title": "Article A", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "art-1-b", "type": "ipv4", "source": "securelist_blog", "risk_score": 86.0, "severity": "high", "last_seen": now, "reference_url": "https://a.example/report", "source_title": "Article A", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "art-2-a", "type": "domain", "source": "gbhackers_blog", "risk_score": 85.0, "severity": "high", "last_seen": now, "reference_url": "https://b.example/report", "source_title": "Article B", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
    ]

    response = await agent.daily_digest(items)

    assert response["count"] == 3
    rendered = "\n".join(message["text"] for message in telegram_bot.messages)
    assert "feed-1" in rendered
    assert "feed-2" in rendered
    assert "feed-3" not in rendered
    assert "Article A" in rendered
    assert "Article B" not in rendered


def test_delivery_agent_applies_split_feed_and_discovery_article_limits() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.delivery.telegram_daily_digest_limit = 10
    settings.workflow.telegram_feed_alert_limit_per_run = 1
    settings.workflow.telegram_feed_article_alert_limit_per_run = 1
    settings.workflow.telegram_discovery_article_alert_limit_per_run = 1
    settings.workflow.telegram_article_alert_limit_per_run = 0
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    cards = [
        {"id": str(uuid4()), "value": "feed-ioc.example", "type": "domain", "source": "threatfox", "risk_score": 90.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "feed-article.example", "type": "domain", "source": "rapid7_blog", "risk_score": 89.0, "severity": "high", "last_seen": now, "reference_url": "https://rapid7.example/report", "source_title": "Configured Feed Article", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "feed-article-skip.example", "type": "domain", "source": "securelist_blog", "risk_score": 88.0, "severity": "high", "last_seen": now, "reference_url": "https://securelist.example/report", "source_title": "Second Feed Article", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "discovery-article.example", "type": "domain", "source": "discovery:publisher.example", "risk_score": 87.0, "severity": "high", "last_seen": now, "reference_url": "https://publisher.example/report", "source_title": "Open Discovery Article", "attributes": {"provenance": "discovery"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "discovery-article-skip.example", "type": "domain", "source": "discovery:other.example", "risk_score": 86.0, "severity": "high", "last_seen": now, "reference_url": "https://other.example/report", "source_title": "Second Discovery Article", "attributes": {"provenance": "discovery"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
    ]

    selected = agent._apply_delivery_limits(cards, apply_burst_cap=False)

    assert [card["source_title"] for card in selected if card.get("source_title")] == [
        "Configured Feed Article",
        "Open Discovery Article",
    ]
    assert [card["value"] for card in selected if not card.get("source_title")] == ["feed-ioc.example"]


@pytest.mark.asyncio
async def test_delivery_agent_applies_feed_type_alert_limits() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings().model_copy(deep=True)
    settings.delivery.telegram_daily_digest_limit = 10
    settings.workflow.telegram_feed_alert_limit_per_run = 10
    settings.workflow.telegram_article_alert_limit_per_run = 1
    settings.workflow.telegram_type_limits_per_run = {"ipv4": 2, "domain": 1, "hash": 1}
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    items = [
        {"id": str(uuid4()), "value": "1.1.1.1", "type": "ipv4", "source": "threatfox", "risk_score": 90.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "2.2.2.2", "type": "ipv4", "source": "threatfox", "risk_score": 89.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "3.3.3.3", "type": "ipv4", "source": "threatfox", "risk_score": 88.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "first.example", "type": "domain", "source": "urlhaus", "risk_score": 87.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "second.example", "type": "domain", "source": "urlhaus", "risk_score": 86.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "a" * 32, "type": "md5", "source": "threatfox", "risk_score": 85.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "b" * 64, "type": "sha256", "source": "threatfox", "risk_score": 84.0, "severity": "high", "last_seen": now, "attributes": {"provenance": "feed"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
        {"id": str(uuid4()), "value": "article.example", "type": "domain", "source": "securelist_blog", "risk_score": 83.0, "severity": "high", "last_seen": now, "reference_url": "https://a.example/report", "source_title": "Article A", "attributes": {"provenance": "writeup"}, "related_cves": [], "external_links": {}, "mitre_techniques": [], "mitre_tactics": []},
    ]

    response = await agent.daily_digest(items)

    assert response["count"] == 5
    rendered = "\n".join(message["text"] for message in telegram_bot.messages)
    assert "1[.]1[.]1[.]1" in rendered
    assert "2[.]2[.]2[.]2" in rendered
    assert "3[.]3[.]3[.]3" not in rendered
    assert "first[.]example" in rendered
    assert "second[.]example" not in rendered
    assert "a" * 32 in rendered
    assert "b" * 64 not in rendered
    assert "Article A" in rendered


@pytest.mark.asyncio
async def test_delivery_agent_suppresses_duplicate_file_hash_variants() -> None:
    telegram_bot = FakeTelegramBot()
    settings = build_settings()
    settings.delivery.telegram_max_alerts_per_run = 5
    agent = DeliveryAgent(
        settings=settings,
        telegram_bot=telegram_bot,
        sendgrid_client=None,
        session_factory=FakeSessionFactory(),
    )
    now = datetime.now(UTC)
    family = {
        "md5": "8c21b2fbded2faeb6db2e7a20c513cdb",
        "sha1": "38b837cc5fe814ca9580f9029386aa405f8e94df",
        "sha256": "b59653f1e2b8dae784ca4211199d2887ea676d27e7af9d057a625cf9281c17e0",
    }
    base = {
        "source": "threatfox",
        "risk_score": 90.0,
        "severity": "high",
        "source_title": "Indicator that identifies a malware sample",
        "last_seen": now,
        "attributes": {"provenance": "feed", "hash_family": family, "hash_family_key": family["sha256"]},
        "related_cves": [],
        "external_links": {},
        "mitre_techniques": [],
        "mitre_tactics": [],
    }
    items = [
        {**base, "id": str(uuid4()), "value": family["md5"], "type": "md5"},
        {**base, "id": str(uuid4()), "value": family["sha256"], "type": "sha256"},
        {**base, "id": str(uuid4()), "value": family["sha1"], "type": "sha1"},
    ]

    result = await agent.run(items)

    assert result.immediate_alerts == 1
    rendered = "\n".join(message["text"] for message in telegram_bot.messages)
    assert family["md5"] in rendered
    assert family["sha256"] not in rendered
    assert family["sha1"] not in rendered


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
    assert "<b>IOCs (2)</b>" in telegram_bot.messages[1]["text"]
    assert "alpha[.]bad[.]example" in telegram_bot.messages[1]["text"]
    assert "beta[.]bad[.]example" in telegram_bot.messages[1]["text"]


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
    assert "<b>IOCs (2)</b>" in telegram_bot.messages[1]["text"]
    assert "goserpent-a[.]bad[.]example" in telegram_bot.messages[1]["text"]
    assert "goserpent-b[.]bad[.]example" in telegram_bot.messages[1]["text"]


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

    assert "🔵 <b>INFORMATIONAL</b> · Score 24.19" in rendered
    assert "<i>feodotracker</i>" in rendered
    assert "AbuseIPDB confidence: 0%" in rendered
    assert "Shodan ports: none reported" in rendered
    assert '<a href="https://www.shodan.io/host/162.243.103.246">Shodan</a>' in rendered
    assert "Observed 2026-04-15 07:30 UTC · Corroboration 1 source(s)" in rendered
    assert "Feodo IP Blocklist" in rendered
    assert '<a href="https://feodotracker.abuse.ch/">Article</a>' in rendered
    assert "CVEs: CVE-2026-12345" in rendered
    # The indicator itself is defanged so chat clients cannot auto-link it.
    assert "<code>162[.]243[.]103[.]246</code> [ipv4]" in rendered
    assert "IPv4 infrastructure indicator" in rendered


def test_format_grouped_alert_message_shows_ioc_section_labels() -> None:
    from sentinel.delivery.telegram_bot import format_grouped_alert_message

    rendered = format_grouped_alert_message(
        source="securelist_blog",
        risk_score=37.14,
        severity="informational",
        source_title="HelloNet campaign",
        reference_url="https://securelist.example/hellonet",
        attributes={"article_ioc_count": 14},
        iocs=[
            {"type": "md5", "value": "16c211c96735f2fae9361b89bd7a31bf", "section_label": "HelloBackdoor"},
            {"type": "md5", "value": "6001829a128fe264b4403138700c11a8", "section_label": "HelloBackdoor Droppers"},
            {"type": "ipv4", "value": "5.39.253.206", "section_label": "wtsapi32.dll"},
        ],
        mitre_techniques=[],
        mitre_tactics=[],
    )

    assert "<u>HelloBackdoor</u>" in rendered
    assert "<u>HelloBackdoor Droppers</u>" in rendered
    assert "<u>wtsapi32.dll</u>" in rendered
    assert "More IOCs can be found in the article/writeup (14 extracted total)." in rendered
    assert "<code>16c211c96735f2fae9361b89bd7a31bf</code> [md5]" in rendered
    assert "<code>5[.]39[.]253[.]206</code> [ipv4]" in rendered


def test_grouped_alert_message_notes_more_iocs_at_article_display_cap() -> None:
    from sentinel.delivery.telegram_bot import format_grouped_alert_message

    rendered = format_grouped_alert_message(
        source="rapid7_blog",
        risk_score=36.0,
        severity="informational",
        source_title="Rapid7 article with IOC section",
        reference_url="https://www.rapid7.com/blog/post/example",
        last_seen=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        attributes={"article_ioc_count": 5},
        iocs=[
            {"type": "domain", "value": "one.example"},
            {"type": "domain", "value": "two.example"},
            {"type": "ipv4", "value": "77.110.127.205"},
            {"type": "sha256", "value": "a" * 64},
            {"type": "url", "value": "https://gobf.mx"},
        ],
        mitre_techniques=[],
        mitre_tactics=[],
    )

    assert "<b>IOCs (5)</b>" in rendered
    assert "More IOCs can be found in the article/writeup (5 extracted total)." in rendered


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

    assert "🔴 <b>CRITICAL</b> · Score 91.00" in rendered
    assert "VirusTotal detections: 18" in rendered
    assert "https://www.virustotal.com/gui/file/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "https://otx.alienvault.com/browse/global/pulses?q=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in rendered
    assert "Observed 2026-04-15 08:15 UTC · Corroboration 1 source(s)" in rendered
    assert "Stealer Campaign Impacting SLTT macOS Users" in rendered
    assert "<code>deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef</code> [sha256]" in rendered
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

    assert "🟡 <b>MEDIUM</b> · Score 63.80" in rendered
    assert "<i>ThreatFox | botnet_cc | Mirai (Katana)</i>" in rendered
    assert "<code>94[.]154[.]43[.]12</code> [ipv4]" in rendered
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

    assert "🟠 <b>HIGH</b> · Score 78.00" in rendered
    assert "Observed 2026-07-05 00:58 UTC · Corroboration 1 source(s)" in rendered
    assert (
        '<a href="https://arcticwolf.com/resources/blog/security-bulletin-github-impersonation-deploys-information-stealer/">Article</a>'
        in rendered
    )
    assert "<b>IOCs (3)</b>" in rendered
    assert "<code>hxxps://github[.]com/antivirus-free-bitdefender</code> [url]" in rendered
    assert "GitHub repo or path used by attacker" in rendered
    assert "<code>bentleyvazquezpvey[.]github[.]io</code> [domain]" in rendered
    assert "domain hosting attacker-controlled content" in rendered
    assert f"<code>{'a' * 64}</code> [sha256]" in rendered
    assert "malware artifact hash" in rendered


def test_format_alert_message_refangs_domains_and_urls_and_notes_article_ioc_count() -> None:
    from sentinel.delivery.telegram_bot import format_alert_message

    rendered = format_alert_message(
        value="evil[.]example",
        ioc_type="domain",
        source="discovery:example.com",
        risk_score=41.2,
        severity="informational",
        last_seen="2026-07-18T08:15:00+00:00",
        source_title="Discovery writeup",
        reference_url="hxxps://example[.]com/report",
        related_cves=[],
        external_links={"VirusTotal": "https://www.virustotal.com/gui/domain/evil.example"},
        mitre_techniques=[],
        mitre_tactics=[],
        attributes={"article_ioc_count": 12},
    )

    # Article links are refanged into clickable anchors; the IOC itself stays
    # defanged so the alert never contains a live malicious link.
    assert '<a href="https://example.com/report">Article</a>' in rendered
    assert "<code>evil[.]example</code> [domain]" in rendered
    assert "More IOCs can be found in the article/writeup (12 extracted total)." in rendered

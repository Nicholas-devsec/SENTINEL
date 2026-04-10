from __future__ import annotations

import asyncio

import pytest

from sentinel.config import SentinelSettings
from sentinel.delivery.telegram_listener import run_telegram_listener


class FakeUpdater:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.allowed_updates = None

    async def start_polling(self, *, allowed_updates, drop_pending_updates: bool) -> None:
        self.started = True
        self.allowed_updates = allowed_updates

    async def stop(self) -> None:
        self.stopped = True


class FakeApplication:
    def __init__(self) -> None:
        self.initialized = False
        self.started = False
        self.stopped = False
        self.shutdown_called = False
        self.updater = FakeUpdater()

    async def initialize(self) -> None:
        self.initialized = True

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def shutdown(self) -> None:
        self.shutdown_called = True


class FakeDeliveryAgent:
    async def handle_callback_query(self, query) -> None:
        return None


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "-100123",
            },
            "db": {
                "url": "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel",
                "redis_url": "redis://redis:6379/0",
            },
            "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
        }
    )


@pytest.mark.asyncio
async def test_telegram_listener_boots_and_stops_cleanly() -> None:
    stop_event = asyncio.Event()
    fake_app = FakeApplication()

    async def fake_builder(token: str, callback_handler):
        assert token == "token"
        assert callback_handler is not None
        return fake_app

    task = asyncio.create_task(
        run_telegram_listener(
            settings=build_settings(),
            delivery_agent=FakeDeliveryAgent(),
            application_builder=fake_builder,
            stop_event=stop_event,
        )
    )

    await asyncio.sleep(0)
    stop_event.set()
    await task

    assert fake_app.initialized is True
    assert fake_app.started is True
    assert fake_app.updater.started is True
    assert fake_app.updater.stopped is True
    assert fake_app.shutdown_called is True

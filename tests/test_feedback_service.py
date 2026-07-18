from __future__ import annotations

import asyncio

import pytest

from sentinel.config import SentinelSettings
from sentinel.services import feedback_service


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "schedule": {
                "enable_karpathy_job": True,
                "karpathy_loop_type": "source",
            },
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "-100123",
            },
            "db": {
                "url": "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel",
                "redis_url": "redis://redis:6379/0",
            },
            "openai": {"api_key": "openai-key"},
            "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
        }
    )


@pytest.mark.asyncio
async def test_feedback_service_runs_listener_and_karpathy_together(monkeypatch) -> None:
    settings = build_settings()
    stop_event = asyncio.Event()
    seen: list[str] = []

    async def fake_run_telegram_listener(*, settings, stop_event):
        seen.append(f"listener:{settings.delivery.telegram_chat_id}")
        await stop_event.wait()

    async def fake_karpathy_main(*, settings, stop_event):
        seen.append(f"karpathy:{settings.schedule.karpathy_loop_type}")
        await stop_event.wait()

    monkeypatch.setattr(feedback_service, "run_telegram_listener", fake_run_telegram_listener)
    monkeypatch.setattr(feedback_service, "karpathy_main", fake_karpathy_main)

    task = asyncio.create_task(feedback_service.run_feedback_service(settings=settings, stop_event=stop_event))
    await asyncio.sleep(0)
    stop_event.set()
    await task

    assert seen == ["listener:-100123", "karpathy:source"]

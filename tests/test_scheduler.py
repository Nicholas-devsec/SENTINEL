from __future__ import annotations

from apscheduler.schedulers import SchedulerNotRunningError

from sentinel.config import SentinelSettings
from sentinel.scheduler import cron


def build_settings() -> SentinelSettings:
    return SentinelSettings.model_validate(
        {
            "schedule": {
                "scrape_interval_hours": 4,
                "daily_digest_time": "07:00",
                "timezone": "America/Vancouver",
                "enable_karpathy_job": False,
                "karpathy_loop_day": "sunday",
                "karpathy_loop_type": "source",
            },
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "-100123",
                "telegram_daily_digest_limit": 10,
            },
            "mitre": {"stix_path": "/tmp/enterprise-attack.json"},
            "db": {"url": "sqlite+aiosqlite:///:memory:", "redis_url": "disabled"},
            "openai": {"api_key": "openai-key"},
        }
    )


def test_build_scheduler_uses_configured_timezone_and_7am_digest(monkeypatch) -> None:
    monkeypatch.setattr(cron, "get_settings", build_settings)
    scheduler = cron.build_scheduler()
    try:
        assert str(scheduler.timezone) == "America/Vancouver"
        digest_job = scheduler.get_job("daily-digest")
        assert digest_job is not None
        assert str(digest_job.trigger.timezone) == "America/Vancouver"
        fields = {field.name: str(field) for field in digest_job.trigger.fields}
        assert fields["hour"] == "7"
        assert fields["minute"] == "0"
    finally:
        try:
            scheduler.shutdown(wait=False)
        except SchedulerNotRunningError:
            pass


def test_build_karpathy_scheduler_registers_only_karpathy_job(monkeypatch) -> None:
    settings = build_settings().model_copy(deep=True)
    settings.schedule.enable_karpathy_job = True
    monkeypatch.setattr(cron, "get_settings", lambda: settings)
    scheduler = cron.build_karpathy_scheduler()
    try:
        assert scheduler.get_job("karpathy-loop") is not None
        assert scheduler.get_job("daily-digest") is None
        assert scheduler.get_job("scrape-pipeline") is None
    finally:
        try:
            scheduler.shutdown(wait=False)
        except SchedulerNotRunningError:
            pass


import pytest


@pytest.mark.asyncio
async def test_daily_digest_job_runs_pipeline_before_digest(monkeypatch) -> None:
    settings = build_settings()
    calls: list[str] = []

    async def fake_run_pipeline_once(*, settings):
        calls.append("pipeline")
        return {"ok": True}

    async def fake_run_daily_digest(*, settings):
        calls.append("digest")
        return {"sent": True}

    monkeypatch.setattr(cron, "get_settings", lambda: settings)
    monkeypatch.setattr(cron, "validate_runtime_settings", lambda settings, command: None)
    monkeypatch.setattr(cron, "run_pipeline_once", fake_run_pipeline_once)
    monkeypatch.setattr(cron, "run_daily_digest", fake_run_daily_digest)

    await cron.daily_digest_job()

    assert calls == ["pipeline", "digest"]

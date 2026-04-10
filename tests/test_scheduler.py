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

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
from string import Template
from typing import Any

import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, Field


class ScheduleSettings(BaseModel):
    scrape_interval_hours: int = 4
    daily_digest_time: str = "08:00"
    karpathy_loop_day: str = "sunday"
    enable_karpathy_job: bool = False
    karpathy_loop_type: str = "source"


class ThresholdSettings(BaseModel):
    alert_score: int = 70
    rule_score: int = 50
    karpathy_experiments: int = 25
    karpathy_budget_mins: int = 30


class FeedConfig(BaseModel):
    name: str
    url: str
    trust: float
    enabled: bool = True


class SourceSettings(BaseModel):
    otx_api_key: str = "${OTX_API_KEY}"
    max_item_age_days: int = 30
    feeds: list[FeedConfig] = Field(default_factory=list)


class WeightSettings(BaseModel):
    vt_ratio: float = 0.35
    abuse_confidence: float = 0.30
    source_trust: float = 0.20
    recency: float = 0.15


class EnrichmentSettings(BaseModel):
    virustotal_key: str = "${VT_API_KEY}"
    shodan_key: str = "${SHODAN_API_KEY}"
    abuseipdb_key: str = "${ABUSEIPDB_API_KEY}"
    weights: WeightSettings = Field(default_factory=WeightSettings)


class CrowdStrikeSettings(BaseModel):
    enabled: bool = False
    client_id: str = "${CS_CLIENT_ID}"
    client_secret: str = "${CS_CLIENT_SECRET}"
    base_url: str = "https://api.crowdstrike.com"


class DeliverySettings(BaseModel):
    telegram_token: str = "${TELEGRAM_BOT_TOKEN}"
    telegram_chat_id: str = "${TELEGRAM_CHAT_ID}"
    telegram_max_alerts_per_run: int = 3
    enable_email: bool = False
    sendgrid_key: str = "${SENDGRID_API_KEY}"
    email_from: str = "sentinel@yourdomain.com"
    email_to: list[str] = Field(default_factory=lambda: ["analyst@yourdomain.com"])


class AnthropicSettings(BaseModel):
    api_key: str = "${ANTHROPIC_API_KEY}"
    model: str = "claude-sonnet-4-20250514"


class OpenAISettings(BaseModel):
    api_key: str = "${OPENAI_API_KEY}"
    model: str = "gpt-5.4"
    base_url: str | None = None


class MitreSettings(BaseModel):
    stix_path: str = "${MITRE_STIX_PATH}"


class DatabaseSettings(BaseModel):
    url: str = "${DATABASE_URL}"
    redis_url: str = "${REDIS_URL}"


class GitSettings(BaseModel):
    skills_repo_path: str = "./skills"
    author_name: str = "SENTINEL Learner"
    author_email: str = "sentinel@bot"


class SentinelSettings(BaseModel):
    schedule: ScheduleSettings = Field(default_factory=ScheduleSettings)
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)
    sources: SourceSettings = Field(default_factory=SourceSettings)
    enrichment: EnrichmentSettings = Field(default_factory=EnrichmentSettings)
    crowdstrike: CrowdStrikeSettings = Field(default_factory=CrowdStrikeSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    mitre: MitreSettings = Field(default_factory=MitreSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    git: GitSettings = Field(default_factory=GitSettings)


def _is_missing_secret(value: str | None) -> bool:
    if value is None:
        return True
    stripped = value.strip()
    return not stripped or stripped.startswith("${")


def _is_disabled_value(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower() in {"disabled", "none", "off"}


def _validate_required_value(name: str, value: str | None) -> None:
    if _is_missing_secret(value):
        raise ValueError(f"{name} must be configured for this command.")


def validate_runtime_settings(settings: SentinelSettings, *, command: str) -> None:
    commands = {command}
    if command == "scheduler":
        commands.update({"run-once", "telegram-listen"})

    if commands & {"run-once", "daily-digest", "scheduler", "telegram-listen", "send-real-samples"}:
        _validate_required_value("DATABASE_URL", settings.db.url)
        _validate_required_value("TELEGRAM_BOT_TOKEN", settings.delivery.telegram_token)
        _validate_required_value("TELEGRAM_CHAT_ID", settings.delivery.telegram_chat_id)

    if commands & {"run-once", "scheduler"}:
        _validate_required_value("MITRE_STIX_PATH", settings.mitre.stix_path)
        mitre_path = Path(settings.mitre.stix_path)
        if not mitre_path.exists():
            raise ValueError(f"MITRE_STIX_PATH does not exist: {mitre_path}")

    if commands & {"telegram-chat-id"}:
        _validate_required_value("TELEGRAM_BOT_TOKEN", settings.delivery.telegram_token)

    if commands & {"karpathy-run"}:
        _validate_required_value("DATABASE_URL", settings.db.url)
        _validate_required_value("OPENAI_API_KEY", settings.openai.api_key)


def _interpolate_env(data: Any, env: dict[str, str]) -> Any:
    if isinstance(data, dict):
        return {key: _interpolate_env(value, env) for key, value in data.items()}
    if isinstance(data, list):
        return [_interpolate_env(item, env) for item in data]
    if isinstance(data, str):
        return Template(data).safe_substitute(env)
    return data


@lru_cache(maxsize=1)
def get_settings(config_path: str | Path = "config.yaml", env_path: str | Path = ".env") -> SentinelSettings:
    config_file = Path(config_path)
    env = {
        **{k: str(v) for k, v in dotenv_values(env_path).items() if v is not None},
        **{k: str(v) for k, v in os.environ.items()},
    }
    with config_file.open("r", encoding="utf-8") as handle:
        raw_config = yaml.safe_load(handle) or {}
    resolved = _interpolate_env(raw_config, env)
    return SentinelSettings.model_validate(resolved)

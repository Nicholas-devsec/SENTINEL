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
    pipeline_cron: str | None = None
    daily_digest_time: str = "07:00"
    daily_digest_cron: str | None = None
    timezone: str = "America/Vancouver"
    karpathy_loop_day: str = "sunday"
    karpathy_loop_cron: str | None = None
    enable_karpathy_job: bool = False
    karpathy_loop_type: str = "source"


class WorkflowSettings(BaseModel):
    feed_ioc_store_limit_per_run: int = 250
    feed_article_store_limit_per_run: int | None = None
    discovery_article_store_limit_per_run: int | None = None
    article_store_limit_per_run: int = 5
    telegram_feed_alert_limit_per_run: int = 5
    telegram_feed_article_alert_limit_per_run: int | None = None
    telegram_discovery_article_alert_limit_per_run: int | None = None
    telegram_article_alert_limit_per_run: int = 2
    telegram_type_limits_per_run: dict[str, int] = Field(default_factory=dict)
    store_type_limits_per_run: dict[str, int] = Field(default_factory=dict)


class ThresholdSettings(BaseModel):
    alert_score: int = 38
    feedback_candidate_score: int = 19
    digest_score: int = 25
    digest_backfill_score: int = 20
    curated_immediate_score: int = 28
    corroborated_immediate_score: int = 32
    curated_digest_score: int = 20
    rule_score: int = 50
    karpathy_experiments: int = 25
    karpathy_budget_mins: int = 30


class FeedConfig(BaseModel):
    name: str
    url: str
    trust: float
    enabled: bool = True


class WriteupSearchSettings(BaseModel):
    enabled: bool = True
    terms: list[str] = Field(
        default_factory=lambda: [
            "phishing",
            "malware",
            "stealer",
            "ransomware",
            "loader",
            "backdoor",
            "campaign",
            "c2",
            "ioc",
            "iocs",
            "indicator",
            "indicators",
            "hash",
            "payload",
        ]
    )
    max_candidates_per_source: int = 5
    fetch_budget_seconds: int = 60
    max_iocs_per_article_ioc_section: int = 50
    max_iocs_per_article_fallback: int = 15


class SourceMixSettings(BaseModel):
    enabled: bool = True
    max_items_per_source: int = 150


class SourceSettings(BaseModel):
    otx_api_key: str = "${OTX_API_KEY}"
    threatfox_api_key: str = "${THREATFOX_API_KEY}"
    malwarebazaar_api_key: str = "${MALWAREBAZAAR_API_KEY}"
    phishtank_app_key: str = "${PHISHTANK_APP_KEY}"
    max_item_age_hours: int = 24
    writeup_max_item_age_hours: int = 72
    http_timeout_seconds: int = 60
    mix: SourceMixSettings = Field(default_factory=SourceMixSettings)
    writeup_search: WriteupSearchSettings = Field(default_factory=WriteupSearchSettings)
    feeds: list[FeedConfig] = Field(default_factory=list)


class DiscoverySearchProvider(BaseModel):
    """Optional open-web candidate source layered beside RSS discovery."""

    name: str
    enabled: bool = True
    provider: str = "gdelt_doc"
    base_url: str = "https://api.gdeltproject.org/api/v2/doc/doc"
    query_terms: list[str] = Field(default_factory=list)
    max_queries: int = 4
    max_records: int = 20
    sort: str = "datedesc"
    language: str | None = "English"
    source_country: str | None = None


class DiscoveryProfile(BaseModel):
    """One bounded search-and-curation pass: what to look for, where, how hard."""

    name: str
    enabled: bool = True
    keywords: list[str] = Field(default_factory=list)
    feeds: list[str] = Field(default_factory=list)
    search_providers: list[DiscoverySearchProvider] = Field(default_factory=list)
    freshness_hours: int = 72
    max_candidates_per_source: int = 15
    max_pages_per_run: int = 6
    max_iocs_per_page_ioc_section: int = 40
    max_iocs_per_page_fallback: int = 15
    time_budget_seconds: int = 90
    per_page_timeout_seconds: int = 20
    # Strict profiles skip pages without an explicit IOC/indicators section;
    # lenient ones fall back to whole-body precision extraction.
    require_ioc_section: bool = True
    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    source_trust: float = 0.55


class DiscoverySettings(BaseModel):
    # Off by default: the discovery stage only joins run_pipeline_once when
    # explicitly enabled. `sentinel discover` can always run it standalone.
    enabled: bool = False
    blocked_article_false_positive_threshold: int = 1
    blocked_host_false_positive_threshold: int = 2
    blocked_host_max_score: float = 0.35
    profiles: list[DiscoveryProfile] = Field(default_factory=list)


class WeightSettings(BaseModel):
    # Evidence-driven weighting. Trust and recency are deliberately small so a
    # feed's configured trust can no longer clear the detection threshold on its
    # own — that behaviour let ThreatFox (trust 0.94) auto-generate detections
    # for indicators with no corroborating evidence while analyst-curated
    # writeup IOCs (trust ~0.67) never passed. `context` rewards indicators
    # pulled from an explicit writeup IOC section; `corroboration` rewards
    # indicators seen by multiple independent sources.
    vt_ratio: float = 0.20
    abuse_confidence: float = 0.20
    source_trust: float = 0.05
    recency: float = 0.05
    context: float = 0.30
    corroboration: float = 0.20


class EnrichmentSettings(BaseModel):
    virustotal_key: str = "${VT_API_KEY}"
    shodan_key: str = "${SHODAN_API_KEY}"
    abuseipdb_key: str = "${ABUSEIPDB_API_KEY}"
    enable_whois: bool = False
    provider_timeout_seconds: int = 20
    batch_size: int = 50
    max_iocs_per_run: int = 250
    weights: WeightSettings = Field(default_factory=WeightSettings)


class CrowdStrikeSettings(BaseModel):
    enabled: bool = False
    client_id: str = "${CS_CLIENT_ID}"
    client_secret: str = "${CS_CLIENT_SECRET}"
    base_url: str = "https://api.crowdstrike.com"


class DeliverySettings(BaseModel):
    telegram_token: str = "${TELEGRAM_BOT_TOKEN}"
    telegram_chat_id: str = "${TELEGRAM_CHAT_ID}"
    enable_telegram_immediate_alerts: bool = True
    telegram_max_alerts_per_run: int = 5
    # Suppression window: an IOC that has already been alerted (immediate or
    # digest) is not re-sent on any channel until this many hours have passed.
    alert_resend_after_hours: int = 72
    telegram_daily_digest_limit: int = 10
    telegram_digest_candidate_pool_size: int = 250
    enable_email: bool = False
    sendgrid_key: str = "${SENDGRID_API_KEY}"
    email_from: str = "sentinel@yourdomain.com"
    email_to: list[str] = Field(default_factory=lambda: ["analyst@yourdomain.com"])


class RetentionSettings(BaseModel):
    enabled: bool = True
    prune_on_cron: bool = True
    unalerted_feed_ioc_ttl_days: int = 5
    alerted_ioc_ttl_days: int = 90
    article_ioc_ttl_days: int = 30
    feedback_ioc_ttl_days: int = 180
    source_material_ttl_days: int = 30
    keep_feedback_labeled: bool = True


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
    pool_pre_ping: bool = True
    pool_recycle_seconds: int = 1800
    pool_size: int = 10
    max_overflow: int = 20


class GitSettings(BaseModel):
    skills_repo_path: str = "./skills"
    author_name: str = "SENTINEL Learner"
    author_email: str = "sentinel@bot"


class KarpathySettings(BaseModel):
    # Proper-score improvements tend to be small in absolute terms because the
    # Brier objective is an average squared error on [0, 1]. Keep a small but
    # non-zero floor here; uncertainty and behavioral guardrails are enforced
    # separately via min_labeled_samples and TP/FP replay checks.
    min_keep_delta: float = 0.001
    max_false_positive_increase: int = 0
    max_true_positive_drop: int = 0
    lease_ttl_seconds: int = 1800
    replay_window_hours: int = 14 * 24
    status_history_limit: int = 5
    # Fail closed when the labeled replay window is too small for a metric
    # delta to mean anything: below this many labeled IOCs no patch is kept.
    min_labeled_samples: int = 20


class SentinelSettings(BaseModel):
    schedule: ScheduleSettings = Field(default_factory=ScheduleSettings)
    workflow: WorkflowSettings = Field(default_factory=WorkflowSettings)
    thresholds: ThresholdSettings = Field(default_factory=ThresholdSettings)
    sources: SourceSettings = Field(default_factory=SourceSettings)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    enrichment: EnrichmentSettings = Field(default_factory=EnrichmentSettings)
    crowdstrike: CrowdStrikeSettings = Field(default_factory=CrowdStrikeSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    mitre: MitreSettings = Field(default_factory=MitreSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    git: GitSettings = Field(default_factory=GitSettings)
    karpathy: KarpathySettings = Field(default_factory=KarpathySettings)


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
    if command == "feedback-service":
        commands.update({"telegram-listen", "karpathy-run"})
    if command == "cron-run":
        commands.add("run-once")
    if command == "karpathy-service":
        commands.add("karpathy-run")
    if command == "karpathy-status":
        commands.add("karpathy-run")

    if commands & {
        "run-once",
        "daily-digest",
        "scheduler",
        "telegram-listen",
        "send-real-samples",
        "send-discovery-samples",
        "send-needs-review",
        "tweetfeed-alert",
    }:
        _validate_required_value("DATABASE_URL", settings.db.url)
        _validate_required_value("TELEGRAM_BOT_TOKEN", settings.delivery.telegram_token)
        _validate_required_value("TELEGRAM_CHAT_ID", settings.delivery.telegram_chat_id)

    if commands & {"run-once", "scheduler", "tweetfeed-alert"}:
        _validate_required_value("MITRE_STIX_PATH", settings.mitre.stix_path)
        mitre_path = Path(settings.mitre.stix_path)
        if not mitre_path.exists():
            raise ValueError(f"MITRE_STIX_PATH does not exist: {mitre_path}")

    if commands & {"telegram-chat-id"}:
        _validate_required_value("TELEGRAM_BOT_TOKEN", settings.delivery.telegram_token)

    if commands & {"karpathy-run"}:
        _validate_required_value("DATABASE_URL", settings.db.url)
        _validate_required_value("OPENAI_API_KEY", settings.openai.api_key)

    if commands & {"discovery-memory", "rescore", "status"}:
        _validate_required_value("DATABASE_URL", settings.db.url)


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

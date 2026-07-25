from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from sentinel import cli
from sentinel.agents.scraper import ScrapeReport, SourceScrapeDiagnostic
from sentinel.config import SentinelSettings, validate_runtime_settings
from sentinel.db.models import IOC, IOCSighting, SourceMaterial
from sentinel.runtime import _build_needs_review_cards, _diversify_ioc_samples, load_real_sample_iocs


def build_settings(tmp_path: Path) -> SentinelSettings:
    mitre_path = tmp_path / "enterprise-attack.json"
    mitre_path.write_text('{"objects": []}', encoding="utf-8")
    return SentinelSettings.model_validate(
        {
            "delivery": {
                "telegram_token": "token",
                "telegram_chat_id": "-100123",
                "enable_email": False,
            },
            "openai": {
                "api_key": "openai-key",
                "model": "gpt-5.4",
                "base_url": "https://api.openai.com/v1",
            },
            "mitre": {"stix_path": str(mitre_path)},
            "db": {
                "url": "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel",
                "redis_url": "redis://redis:6379/0",
            },
        }
    )


def test_validate_runtime_settings_fails_fast_for_missing_telegram_chat_id(tmp_path: Path) -> None:
    settings = build_settings(tmp_path).model_copy(deep=True)
    settings.delivery.telegram_chat_id = "${TELEGRAM_CHAT_ID}"

    with pytest.raises(ValueError, match="TELEGRAM_CHAT_ID"):
        validate_runtime_settings(settings, command="run-once")


def test_validate_runtime_settings_allows_disabled_redis_for_run_once(tmp_path: Path) -> None:
    settings = build_settings(tmp_path).model_copy(deep=True)
    settings.db.redis_url = "disabled"

    validate_runtime_settings(settings, command="run-once")


def test_cli_main_configures_logging(monkeypatch) -> None:
    seen: list[str] = []

    monkeypatch.setattr(cli, "build_parser", lambda: SimpleNamespace(parse_args=lambda: SimpleNamespace(command="telegram-listen")))
    monkeypatch.setattr(cli, "configure_logging", lambda: seen.append("configured"))
    monkeypatch.setattr(cli.asyncio, "run", lambda coro: (coro.close(), None)[1])

    cli.main()

    assert seen == ["configured"]


@pytest.mark.asyncio
async def test_cli_dispatch_runs_karpathy_loop_and_prints_summary(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        cli,
        "run_live_karpathy_loop",
        lambda **kwargs: __import__("asyncio").sleep(
            0,
            result=(
                SimpleNamespace(
                    loop_type="source",
                    ready=True,
                    skill_path="/tmp/skills/sources/SKILL.md",
                    changelog_path="/tmp/skills/CHANGELOG.md",
                    current_branch="dev",
                    counts={"feedback_rows": 8, "distinct_sources": 2},
                    checks=[SimpleNamespace(name="feedback_window", passed=True, detail="ok")],
                ),
                SimpleNamespace(
                    loop_type="source",
                    mode="live",
                    experiments_attempted=1,
                    kept=1,
                    reverted=0,
                    metric_before=0.4,
                    metric_after=0.52,
                    affected_sections=["Trust Scores"],
                    commit_hashes=["abc123"],
                    branch_name="karpathy-source-123",
                    worktree_path="/tmp/worktree",
                    error=None,
                    scenario=None,
                    outcomes=[
                        SimpleNamespace(
                            experiment_number=1,
                            kept=True,
                            delta=0.12,
                            hypothesis="Improve source trust thresholds",
                        )
                    ],
                ),
            ),
        ),
    )

    await cli._dispatch("karpathy-run", loop="source", max_experiments=2)

    output = capsys.readouterr().out
    assert "Karpathy preflight for source" in output
    assert "Karpathy live report:" in output
    assert "Improve source trust thresholds" in output


@pytest.mark.asyncio
async def test_cli_dispatch_starts_telegram_listener(monkeypatch, tmp_path: Path) -> None:
    settings = build_settings(tmp_path)
    seen: list[str] = []

    async def fake_run_telegram_listener(*, settings):
        seen.append(settings.delivery.telegram_chat_id)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "run_telegram_listener", fake_run_telegram_listener)

    await cli._dispatch("telegram-listen")

    assert seen == ["-100123"]


@pytest.mark.asyncio
async def test_cli_dispatch_runs_cron_run_pipeline_once(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        cli,
        "run_pipeline_once",
        lambda **kwargs: __import__("asyncio").sleep(0, result={"scraped": 10, "alerts": 2}),
    )

    await cli._dispatch("cron-run")

    assert "{'scraped': 10, 'alerts': 2}" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_dispatch_starts_karpathy_service(monkeypatch, tmp_path: Path) -> None:
    settings = build_settings(tmp_path)
    seen: list[str] = []

    async def fake_karpathy_scheduler_main():
        seen.append("started")

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "karpathy_scheduler_main", fake_karpathy_scheduler_main)

    await cli._dispatch("karpathy-service")

    assert seen == ["started"]


@pytest.mark.asyncio
async def test_cli_dispatch_starts_feedback_service(monkeypatch, tmp_path: Path) -> None:
    settings = build_settings(tmp_path)
    seen: list[str] = []

    async def fake_run_feedback_service(*, settings):
        seen.append(settings.delivery.telegram_chat_id)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "run_feedback_service", fake_run_feedback_service)

    await cli._dispatch("feedback-service")

    assert seen == ["-100123"]


@pytest.mark.asyncio
async def test_cli_dispatch_prints_karpathy_status(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        cli,
        "inspect_karpathy_status",
        lambda **kwargs: __import__("asyncio").sleep(
            0,
            result=SimpleNamespace(
                readiness=SimpleNamespace(
                    loop_type="source",
                    ready=True,
                    skill_path="/tmp/skills/sources/SKILL.md",
                    changelog_path="/tmp/skills/CHANGELOG.md",
                    checks=[],
                    counts={},
                    current_branch="main",
                    target_source="threatfox",
                ),
                active_lease={"lease_name": "karpathy:source", "holder_id": "host:lease", "expires_at": "2026-07-12T10:00:00+00:00"},
                recent_runs=[],
            ),
        ),
    )
    monkeypatch.setattr(cli, "format_karpathy_status", lambda report: "Karpathy status rendered")

    await cli._dispatch("karpathy-status", loop="source")

    assert "Karpathy status rendered" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_dispatch_reports_when_no_real_samples_found(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "load_real_sample_iocs", lambda **kwargs: __import__("asyncio").sleep(0, result=[]))

    await cli._dispatch("send-real-samples", types=["sha256"], limit=1)

    assert "No matching real IOC samples found" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_dispatch_prints_scraper_diagnostics(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    class FakeScraperAgent:
        def __init__(self, *, settings):
            self.settings = settings

        async def run_with_diagnostics(self):
            return ScrapeReport(
                items=[{"value": "example.test"}],
                diagnostics=[
                    SourceScrapeDiagnostic(
                        source="urlhaus",
                        fetched=5,
                        pre_balance_kept=3,
                        kept=2,
                        stale_dropped=2,
                        balance_dropped=1,
                        error=None,
                    ),
                    SourceScrapeDiagnostic(source="otx", fetched=0, kept=0, stale_dropped=0, error="ReadTimeout: timed out"),
                ],
            )

        async def aclose(self):
            return None

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "ScraperAgent", FakeScraperAgent)

    await cli._dispatch("scraper-diagnose")

    output = capsys.readouterr().out
    assert "Scrape diagnostics: pre_balance_kept_total=3 final_kept_total=1 balance_dropped_total=1" in output
    assert "source=urlhaus fetched=5 pre_balance_kept=3 kept=2 stale_dropped=2 balance_dropped=1 error=none" in output
    assert "source=otx fetched=0 pre_balance_kept=0 kept=0 stale_dropped=0 balance_dropped=0 error=ReadTimeout: timed out" in output


@pytest.mark.asyncio
async def test_cli_dispatch_runs_karpathy_validation_scenario(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        cli,
        "run_shadow_karpathy_validation",
        lambda **kwargs: __import__("asyncio").sleep(
            0,
            result=SimpleNamespace(
                loop_type="source",
                mode="shadow",
                scenario="improve",
                experiments_attempted=1,
                kept=1,
                reverted=0,
                metric_before=0.4,
                metric_after=0.58,
                affected_sections=["Trust Scores"],
                commit_hashes=["abc123"],
                branch_name=None,
                worktree_path="/tmp/shadow",
                error=None,
                outcomes=[],
            ),
        ),
    )

    await cli._dispatch("karpathy-validate", loop="source", scenario="improve", max_experiments=1)

    output = capsys.readouterr().out
    assert "Karpathy shadow report:" in output
    assert "scenario=improve" in output


@pytest.mark.asyncio
async def test_cli_dispatch_sends_real_samples_from_database(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    class FakeDeliveryAgent:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def send_immediate_alert(self, item):
            assert item["type"] == "ipv4"
            return True

        async def send_immediate_alerts(self, items):
            assert items[0]["type"] == "ipv4"
            return 1

    sample_items = [
        {
            "id": "ioc-1",
            "value": "162.243.103.246",
            "type": "ipv4",
            "source": "feodotracker",
            "risk_score": 24.19,
            "severity": "informational",
            "external_links": {"Shodan": "https://www.shodan.io/host/162.243.103.246"},
        }
    ]

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "load_real_sample_iocs", lambda **kwargs: __import__("asyncio").sleep(0, result=sample_items))
    monkeypatch.setattr(cli, "DeliveryAgent", FakeDeliveryAgent)
    monkeypatch.setattr(cli, "_build_telegram_bot", lambda settings: object())

    await cli._dispatch("send-real-samples", types=["ipv4"], limit=1)

    assert "Sent 1 real sample alerts" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_dispatch_sends_discovery_samples_from_database(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    class FakeDeliveryAgent:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def send_immediate_alerts(self, items):
            assert items[0]["type"] == "url"
            return 1

    sample_items = [
        {
            "id": "ioc-1",
            "value": "https://github.com/owner/repo",
            "type": "url",
            "source": "discovery:arcticwolf.com",
            "risk_score": 82.0,
            "severity": "high",
            "external_links": {},
        }
    ]

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(
        cli,
        "load_real_sample_iocs",
        lambda **kwargs: __import__("asyncio").sleep(0, result=sample_items),
    )
    monkeypatch.setattr(cli, "DeliveryAgent", FakeDeliveryAgent)
    monkeypatch.setattr(cli, "_build_telegram_bot", lambda settings: object())

    await cli._dispatch("send-discovery-samples", types=["url"], limit=1)

    assert "Sent 1 discovery sample alerts" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_cli_dispatch_resends_needs_review_alerts(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)
    sent_items: list[dict] = []

    class FakeDeliveryAgent:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def send_immediate_alert(self, item):
            sent_items.append(item)
            return True

    review_items = [
        {
            "id": "ioc-review-1",
            "value": "review.example",
            "type": "domain",
            "source": "otx",
            "risk_score": 50.0,
            "severity": "informational",
            "attributes": {"delivery_reason": "needs_review_retriage"},
        }
    ]

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "load_needs_review_iocs", lambda **kwargs: __import__("asyncio").sleep(0, result=review_items))
    monkeypatch.setattr(cli, "DeliveryAgent", FakeDeliveryAgent)
    monkeypatch.setattr(cli, "_build_telegram_bot", lambda settings: object())

    await cli._dispatch("send-needs-review", count="3", limit=None, all=False)

    assert sent_items == review_items
    assert "Sent 1 Needs Review alert(s)" in capsys.readouterr().out


def test_resolve_needs_review_limit_supports_counts_and_all() -> None:
    assert cli._resolve_needs_review_limit(count="3", limit=None, all_items=False) == 3
    assert cli._resolve_needs_review_limit(count="all", limit=None, all_items=False) is None
    assert cli._resolve_needs_review_limit(count=None, limit=5, all_items=False) == 5
    assert cli._resolve_needs_review_limit(count=None, limit=5, all_items=True) is None
    assert cli._resolve_needs_review_limit(count=None, limit=None, all_items=False) == 5


@pytest.mark.asyncio
async def test_load_real_sample_iocs_uses_discovery_sighting_metadata(
    monkeypatch,
    db_session_factory,
) -> None:
    now = datetime(2026, 7, 5, 1, 18, tzinfo=UTC)
    article_url = "https://arcticwolf.com/resources/blog/security-bulletin-github-impersonation-deploys-information-stealer/"

    monkeypatch.setattr("sentinel.runtime.AsyncSessionFactory", lambda: db_session_factory())

    async with db_session_factory() as session:
        material = SourceMaterial(
            source="discovery:arcticwolf.com",
            url=article_url,
            title="Security Bulletin: GitHub Impersonation Deploys Information Stealer - Arctic Wolf",
            published_at=now,
            fetched_at=now,
            content_text="stub",
            extraction_status="complete",
            extracted_ioc_count=6,
            metadata_json={},
        )
        session.add(material)
        await session.flush()

        ioc = IOC(
            id=uuid.uuid4(),
            value="https://github.com/Arctic-Wolf-Security",
            dedupe_hash="dedupe-1",
            type="url",
            source="otx",
            source_trust=0.6,
            first_seen=now,
            last_seen=now,
            source_title="AlienVault pulse",
            reference_url="https://otx.alienvault.com/pulse/example",
            related_cves=[],
            risk_score=82.0,
            severity="high",
            vt_detections=0,
            shodan_ports=[],
            abuse_confidence=None,
            mitre_techniques=[],
            mitre_tactics=[],
            sigma_rule=None,
            crowdstrike_pushed=False,
            analyst_verdict=None,
            campaign_id=None,
            vt_ratio=None,
        )
        session.add(ioc)
        await session.flush()

        session.add(
            IOCSighting(
                ioc_id=ioc.id,
                source="discovery:arcticwolf.com",
                source_trust=0.9,
                provenance="discovery",
                reference_url=article_url,
                source_material_id=material.id,
                first_seen=now,
                last_seen=now,
                sighting_count=1,
                lineage_hash="lineage-1",
                attributes={},
            )
        )
        await session.commit()

    items = await load_real_sample_iocs(ioc_types=["url"], limit=10, provenance="discovery")

    assert len(items) == 1
    assert items[0]["value"] == "https://github.com/Arctic-Wolf-Security"
    assert items[0]["source"] == "discovery:arcticwolf.com"
    assert items[0]["reference_url"] == article_url
    assert items[0]["source_title"] == material.title


def test_diversify_ioc_samples_prefers_different_pulses_before_siblings() -> None:
    pulse_a = "https://otx.alienvault.com/pulse/6a6120390f602b6ee56739c3"
    pulse_b = "https://otx.alienvault.com/pulse/b"
    pulse_c = "https://otx.alienvault.com/pulse/c"
    items = [
        {"id": "a", "value": "a" * 64, "type": "sha256", "source": "otx", "source_title": "TrickBot Variant Using DNS Tunneling for C2", "reference_url": pulse_a},
        {"id": "b", "value": "b" * 64, "type": "sha256", "source": "otx", "source_title": "TrickBot Variant Using DNS Tunneling for C2", "reference_url": pulse_a},
        {"id": "c", "value": "c" * 64, "type": "sha256", "source": "otx", "source_title": "TrickBot Variant Using DNS Tunneling for C2", "reference_url": pulse_a},
        {"id": "d", "value": "d" * 64, "type": "sha256", "source": "otx", "source_title": "Other Pulse", "reference_url": pulse_b},
        {"id": "e", "value": "e" * 64, "type": "sha256", "source": "otx", "source_title": "Third Pulse", "reference_url": pulse_c},
    ]

    selected = _diversify_ioc_samples(items, limit=3)

    assert [item["reference_url"] for item in selected] == [pulse_a, pulse_b, pulse_c]


def test_build_needs_review_cards_groups_article_siblings() -> None:
    now = datetime(2026, 7, 24, 13, 4, tzinfo=UTC)
    article_url = "https://gbhackers.com/cl0p-targets-internet-exposed-windchill/"
    values = ["216.152.148.54", "216.152.151.204", "104.243.35.63", "5.180.41.35"]
    material = SimpleNamespace(
        title="Cl0p Targets Internet-Exposed Windchill Servers in Global Engineering Data-Theft Campaign",
        extracted_ioc_count=4,
    )
    iocs = [
        SimpleNamespace(
            id=uuid.uuid4(),
            value=value,
            type="ipv4",
            source="gbhackers_blog",
            risk_score=33.0 + index,
            severity="informational",
            source_title=material.title,
            reference_url=article_url,
            related_cves=[],
            vt_detections=7,
            shodan_ports=[],
            abuse_confidence=0,
            mitre_techniques=["T1557.001"],
            mitre_tactics=["credential access"],
            last_seen=now,
            score_breakdown={},
        )
        for index, value in enumerate(values)
    ]
    target = iocs[-1]
    target_sighting = SimpleNamespace(
        ioc_id=target.id,
        source="gbhackers_blog",
        provenance="writeup",
        reference_url=article_url,
        last_seen=now,
        attributes={"extraction_mode": "ioc_section"},
    )
    siblings = [
        (
            SimpleNamespace(
                source="gbhackers_blog",
                provenance="writeup",
                reference_url=article_url,
                last_seen=now,
                attributes={"extraction_mode": "ioc_section"},
            ),
            ioc,
            material,
        )
        for ioc in iocs
    ]

    items = _build_needs_review_cards(
        target_rows=[target],
        article_context={target.id: (target_sighting, material)},
        sibling_rows_by_reference={article_url: siblings},
        limit=5,
    )

    assert len(items) == 1
    assert items[0]["reference_url"] == article_url
    assert items[0]["source_title"] == material.title
    assert items[0]["attributes"]["article_ioc_count"] == 4
    assert {entry["value"] for entry in items[0]["grouped_iocs"]} == set(values)

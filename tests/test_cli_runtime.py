from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel import cli
from sentinel.config import SentinelSettings, validate_runtime_settings


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
async def test_cli_dispatch_reports_when_no_real_samples_found(monkeypatch, tmp_path: Path, capsys) -> None:
    settings = build_settings(tmp_path)

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "load_real_sample_iocs", lambda **kwargs: __import__("asyncio").sleep(0, result=[]))

    await cli._dispatch("send-real-samples", types=["sha256"], limit=1)

    assert "No matching real IOC samples found" in capsys.readouterr().out


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

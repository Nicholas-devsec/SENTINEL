from __future__ import annotations

import argparse
import asyncio

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.scraper import ScraperAgent
from sentinel.config import get_settings, validate_runtime_settings
from sentinel.delivery.telegram_listener import run_telegram_listener
from sentinel.delivery.telegram_bot import fetch_chat_candidates, format_chat_candidates
from sentinel.logging_utils import configure_logging
from sentinel.pipeline import _build_telegram_bot, rescore_existing_iocs, run_daily_digest, run_pipeline_once
from sentinel.runtime import (
    format_karpathy_status,
    format_karpathy_readiness,
    format_karpathy_report,
    inspect_karpathy_status,
    load_real_sample_iocs,
    run_live_karpathy_loop,
    run_shadow_karpathy_validation,
)
from sentinel.scheduler.cron import karpathy_main as karpathy_scheduler_main
from sentinel.scheduler.cron import main as scheduler_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run SENTINEL MVP commands")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("run-once", help="Run the full live MVP pipeline once")
    subcommands.add_parser("cron-run", help="Cron-friendly one-shot pipeline: scrape -> store -> enrich -> Telegram")
    subcommands.add_parser("scraper-diagnose", help="Fetch live sources and print per-feed scrape diagnostics")
    subcommands.add_parser("daily-digest", help="Send the daily digest for the last 24 hours")
    subcommands.add_parser(
        "rescore",
        help="Re-level every stored IOC under current scoring weights + context (no API calls)",
    )
    subcommands.add_parser("scheduler", help="Run the APScheduler service loop")
    subcommands.add_parser("karpathy-service", help="Run only the long-lived scheduled Karpathy loop service")
    subcommands.add_parser("telegram-listen", help="Start Telegram polling to capture analyst callback feedback")
    telegram_parser = subcommands.add_parser(
        "telegram-chat-id",
        help="Inspect recent Telegram bot updates and print discovered chat or channel IDs",
    )
    telegram_parser.add_argument("--limit", type=int, default=20, help="Maximum number of recent updates to inspect")
    karpathy_parser = subcommands.add_parser(
        "karpathy-run",
        help="Run a bounded Karpathy optimization loop against one skill file",
    )
    karpathy_parser.add_argument("--loop", choices=["source", "scoring", "detection"], default="source")
    karpathy_parser.add_argument("--max-experiments", type=int, default=None)
    karpathy_status_parser = subcommands.add_parser(
        "karpathy-status",
        help="Inspect Karpathy readiness, active lease, and recent experiment history",
    )
    karpathy_status_parser.add_argument("--loop", choices=["source", "scoring", "detection"], default="source")
    karpathy_status_parser.add_argument("--limit", type=int, default=None)
    validation_parser = subcommands.add_parser(
        "karpathy-validate",
        help="Run a shadow-mode Karpathy validation scenario without touching the live repo",
    )
    validation_parser.add_argument("--loop", choices=["source", "scoring", "detection"], default="source")
    validation_parser.add_argument(
        "--scenario",
        choices=["improve", "decline", "invalid-json", "missing-section", "tiny-deltas"],
        default="improve",
    )
    validation_parser.add_argument("--max-experiments", type=int, default=None)
    samples_parser = subcommands.add_parser(
        "send-real-samples",
        help="Send Telegram alerts using real stored IOC rows from the database",
    )
    samples_parser.add_argument("--types", nargs="+", default=["ipv4"], help="IOC types to sample, e.g. ipv4 sha256")
    samples_parser.add_argument("--limit", type=int, default=2, help="Maximum number of real alerts to send")
    discovery_samples_parser = subcommands.add_parser(
        "send-discovery-samples",
        help="Send Telegram alerts using stored discovery-origin IOC rows from the database",
    )
    discovery_samples_parser.add_argument(
        "--types",
        nargs="+",
        default=["domain", "url", "md5", "sha1", "sha256", "ipv4", "ipv6"],
        help="IOC types to sample, e.g. domain url md5",
    )
    discovery_samples_parser.add_argument("--limit", type=int, default=10, help="Maximum number of discovery alerts to send")
    discover_parser = subcommands.add_parser(
        "discover",
        help="Run the bounded writeup discovery profiles standalone and print triage/extraction diagnostics",
    )
    discover_parser.add_argument("--profile", nargs="+", default=None, help="Only run the named discovery profile(s)")
    memory_parser = subcommands.add_parser(
        "discovery-memory",
        help="Show what discovery has learned from analyst feedback (optionally resync first)",
    )
    memory_parser.add_argument("--sync", action="store_true", help="Recompute memory from feedback before printing")
    return parser


async def _dispatch(command: str, **kwargs) -> None:
    settings = get_settings()
    if command != "scraper-diagnose":
        validate_runtime_settings(settings, command=command)
    if command in {"run-once", "cron-run"}:
        result = await run_pipeline_once(settings=settings)
        print(result)
        return
    if command == "scraper-diagnose":
        scraper = ScraperAgent(settings=settings)
        try:
            report = await scraper.run_with_diagnostics()
        finally:
            await scraper.aclose()
        balance_dropped_total = sum(diagnostic.balance_dropped for diagnostic in report.diagnostics)
        print(f"Scrape diagnostics: kept_total={len(report.items)} balance_dropped_total={balance_dropped_total}")
        for diagnostic in report.diagnostics:
            error = diagnostic.error or "none"
            print(
                f"- source={diagnostic.source} fetched={diagnostic.fetched} kept={diagnostic.kept} "
                f"stale_dropped={diagnostic.stale_dropped} balance_dropped={diagnostic.balance_dropped} error={error}"
            )
        return
    if command == "daily-digest":
        result = await run_daily_digest(settings=settings)
        print(result)
        return
    if command == "rescore":
        result = await rescore_existing_iocs(settings=settings)
        print(f"Rescored {result.rescored} IOC(s); {result.changed} changed.")
        print("Average risk_score by source (before -> after):")
        for source in sorted({*result.by_source_before, *result.by_source_after}):
            before = result.by_source_before.get(source, 0.0)
            after = result.by_source_after.get(source, 0.0)
            print(f"  {source:32s} {before:6.2f} -> {after:6.2f}")
        return
    if command == "scheduler":
        await scheduler_main()
        return
    if command == "karpathy-service":
        await karpathy_scheduler_main()
        return
    if command == "telegram-listen":
        await run_telegram_listener(settings=settings)
        return
    if command == "telegram-chat-id":
        token = settings.delivery.telegram_token.strip()
        candidates = await fetch_chat_candidates(token, limit=int(kwargs.get("limit", 20)))
        print(format_chat_candidates(candidates))
        return
    if command == "karpathy-run":
        max_experiments = kwargs.get("max_experiments") or settings.thresholds.karpathy_experiments
        readiness, report = await run_live_karpathy_loop(
            loop_type=str(kwargs.get("loop", "source")),
            settings=settings,
            max_experiments=int(max_experiments),
        )
        print(format_karpathy_readiness(readiness))
        if report is None:
            return
        print()
        print(format_karpathy_report(report))
        return
    if command == "karpathy-status":
        report = await inspect_karpathy_status(
            loop_type=str(kwargs.get("loop", "source")),
            settings=settings,
            limit=kwargs.get("limit"),
        )
        print(format_karpathy_status(report))
        return
    if command == "karpathy-validate":
        report = await run_shadow_karpathy_validation(
            loop_type=str(kwargs.get("loop", "source")),
            settings=settings,
            scenario=str(kwargs.get("scenario", "improve")),
            max_experiments=kwargs.get("max_experiments"),
        )
        print(format_karpathy_report(report))
        return
    if command == "discover":
        from sentinel.agents.discovery import DiscoveryAgent, format_discovery_report

        agent = DiscoveryAgent(settings=settings)
        try:
            report = await agent.run_with_report(profile_names=kwargs.get("profile"))
        finally:
            await agent.aclose()
        print(format_discovery_report(report))
        return
    if command == "discovery-memory":
        from sentinel.agents.discovery import DiscoveryMemoryStore, format_memory_rows
        from sentinel.db.session import AsyncSessionFactory
        from sentinel.pipeline import init_db

        await init_db()
        store = DiscoveryMemoryStore(AsyncSessionFactory)
        if kwargs.get("sync"):
            written = await store.sync()
            print(f"Synced {written} discovery memory row(s) from analyst feedback.")
        print(format_memory_rows(await store.all_rows()))
        return
    if command == "send-real-samples":
        sample_items = await load_real_sample_iocs(
            ioc_types=list(kwargs.get("types", ["ipv4"])),
            limit=int(kwargs.get("limit", 2)),
        )
        if not sample_items:
            print("No matching real IOC samples found in the database.")
            return
        delivery = DeliveryAgent(settings=settings, telegram_bot=_build_telegram_bot(settings))
        sender = getattr(delivery, "send_immediate_alerts", None)
        if sender is not None:
            sent = await sender(sample_items)
        else:
            sent = 0
            for item in sample_items:
                if await delivery.send_immediate_alert(item):
                    sent += 1
        print(f"Sent {sent} real sample alerts from stored IOC rows.")
        return
    if command == "send-discovery-samples":
        sample_items = await load_real_sample_iocs(
            ioc_types=list(kwargs.get("types", ["domain", "url", "md5", "sha1", "sha256", "ipv4", "ipv6"])),
            limit=int(kwargs.get("limit", 10)),
            provenance="discovery",
        )
        if not sample_items:
            print("No matching discovery IOC samples found in the database.")
            return
        delivery = DeliveryAgent(settings=settings, telegram_bot=_build_telegram_bot(settings))
        sender = getattr(delivery, "send_immediate_alerts", None)
        if sender is not None:
            sent = await sender(sample_items)
        else:
            sent = 0
            for item in sample_items:
                if await delivery.send_immediate_alert(item):
                    sent += 1
        print(f"Sent {sent} discovery sample alerts from stored IOC rows.")
        return
    raise ValueError(f"Unknown command: {command}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    payload = vars(args).copy()
    command = payload.pop("command")
    configure_logging()
    asyncio.run(_dispatch(command, **payload))


if __name__ == "__main__":
    main()

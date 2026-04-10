from __future__ import annotations

import argparse
import asyncio

from sentinel.agents.delivery import DeliveryAgent
from sentinel.config import get_settings, validate_runtime_settings
from sentinel.delivery.telegram_listener import run_telegram_listener
from sentinel.delivery.telegram_bot import fetch_chat_candidates, format_chat_candidates
from sentinel.pipeline import _build_telegram_bot, run_daily_digest, run_pipeline_once
from sentinel.runtime import (
    format_karpathy_readiness,
    format_karpathy_report,
    load_real_sample_iocs,
    run_live_karpathy_loop,
    run_shadow_karpathy_validation,
)
from sentinel.scheduler.cron import main as scheduler_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run SENTINEL MVP commands")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("run-once", help="Run the full live MVP pipeline once")
    subcommands.add_parser("daily-digest", help="Send the daily digest for the last 24 hours")
    subcommands.add_parser("scheduler", help="Run the APScheduler service loop")
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
    return parser


async def _dispatch(command: str, **kwargs) -> None:
    settings = get_settings()
    validate_runtime_settings(settings, command=command)
    if command == "run-once":
        result = await run_pipeline_once(settings=settings)
        print(result)
        return
    if command == "daily-digest":
        result = await run_daily_digest(settings=settings)
        print(result)
        return
    if command == "scheduler":
        await scheduler_main()
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
    if command == "karpathy-validate":
        report = await run_shadow_karpathy_validation(
            loop_type=str(kwargs.get("loop", "source")),
            settings=settings,
            scenario=str(kwargs.get("scenario", "improve")),
            max_experiments=kwargs.get("max_experiments"),
        )
        print(format_karpathy_report(report))
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
        sent = 0
        for item in sample_items:
            if await delivery.send_immediate_alert(item):
                sent += 1
        print(f"Sent {sent} real sample alerts from stored IOC rows.")
        return
    raise ValueError(f"Unknown command: {command}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    payload = vars(args).copy()
    command = payload.pop("command")
    asyncio.run(_dispatch(command, **payload))


if __name__ == "__main__":
    main()

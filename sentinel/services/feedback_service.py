from __future__ import annotations

import asyncio
import logging

from sentinel.config import SentinelSettings, get_settings
from sentinel.delivery.telegram_listener import run_telegram_listener
from sentinel.scheduler.cron import karpathy_main


logger = logging.getLogger(__name__)


async def run_feedback_service(
    *,
    settings: SentinelSettings | None = None,
    stop_event: asyncio.Event | None = None,
) -> None:
    settings = settings or get_settings()
    stop_event = stop_event or asyncio.Event()
    logger.info("Starting feedback service for chat_id=%s loop_type=%s", settings.delivery.telegram_chat_id, settings.schedule.karpathy_loop_type)
    async with asyncio.TaskGroup() as task_group:
        task_group.create_task(run_telegram_listener(settings=settings, stop_event=stop_event))
        task_group.create_task(karpathy_main(settings=settings, stop_event=stop_event))
    logger.info("Feedback service stopped")

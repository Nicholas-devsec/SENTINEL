from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from sentinel.config import get_settings, validate_runtime_settings
from sentinel.pipeline import run_daily_digest, run_pipeline_once
from sentinel.runtime import build_karpathy_loop

logger = logging.getLogger(__name__)


async def scrape_pipeline() -> None:
    settings = get_settings()
    validate_runtime_settings(settings, command="run-once")
    result = await run_pipeline_once(settings=settings)
    logger.info("Scheduled scrape pipeline finished: %s", result)


async def daily_digest_job() -> None:
    settings = get_settings()
    validate_runtime_settings(settings, command="run-once")
    pipeline_result = await run_pipeline_once(settings=settings)
    logger.info("Scheduled pre-digest pipeline finished: %s", pipeline_result)
    digest_result = await run_daily_digest(settings=settings)
    logger.info("Scheduled daily digest finished: %s", digest_result)


async def karpathy_loop_job() -> None:
    settings = get_settings()
    if not settings.schedule.enable_karpathy_job:
        return
    validate_runtime_settings(settings, command="karpathy-run")
    loop = build_karpathy_loop(loop_type=settings.schedule.karpathy_loop_type, settings=settings)
    await loop.optimize(max_experiments=settings.thresholds.karpathy_experiments)


def build_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone=settings.schedule.timezone)
    scheduler.add_job(
        scrape_pipeline,
        IntervalTrigger(hours=settings.schedule.scrape_interval_hours),
        id="scrape-pipeline",
        replace_existing=True,
    )
    hour, minute = settings.schedule.daily_digest_time.split(":")
    scheduler.add_job(
        daily_digest_job,
        CronTrigger(hour=int(hour), minute=int(minute), timezone=settings.schedule.timezone),
        id="daily-digest",
        replace_existing=True,
    )
    if settings.schedule.enable_karpathy_job:
        scheduler.add_job(
            karpathy_loop_job,
            CronTrigger(
                day_of_week=settings.schedule.karpathy_loop_day,
                hour=3,
                minute=0,
                timezone=settings.schedule.timezone,
            ),
            id="karpathy-loop",
            replace_existing=True,
        )
    for job in scheduler.get_jobs():
        logger.info("Registered scheduler job %s next_run=%s", job.id, getattr(job, "next_run_time", None))
    return scheduler


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    scheduler = build_scheduler()
    scheduler.start()
    for job in scheduler.get_jobs():
        logger.info("Scheduler started job %s next_run=%s", job.id, getattr(job, "next_run_time", None))
    try:
        while True:
            await __import__("asyncio").sleep(3600)
    finally:
        scheduler.shutdown()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

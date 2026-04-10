from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from sentinel.agents.delivery import DeliveryAgent
from sentinel.config import SentinelSettings, get_settings
from sentinel.delivery.telegram_bot import build_telegram_application


async def run_telegram_listener(
    *,
    settings: SentinelSettings | None = None,
    delivery_agent: DeliveryAgent | None = None,
    application_builder: Callable[[str, Callable[[object], Awaitable[object]]], Awaitable[object]] = build_telegram_application,
    stop_event: asyncio.Event | None = None,
) -> None:
    settings = settings or get_settings()
    stop_event = stop_event or asyncio.Event()
    agent = delivery_agent or DeliveryAgent(settings=settings)
    application = await application_builder(settings.delivery.telegram_token, agent.handle_callback_query)

    await application.initialize()
    await application.start()
    if application.updater is None:
        raise RuntimeError("Telegram application updater is unavailable.")
    await application.updater.start_polling(
        allowed_updates=["callback_query"],
        drop_pending_updates=False,
    )
    try:
        await stop_event.wait()
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()

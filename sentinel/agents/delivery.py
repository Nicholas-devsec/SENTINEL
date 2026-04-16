from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sendgrid import SendGridAPIClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from telegram.error import TelegramError
from telegram import InlineKeyboardMarkup

from sentinel.agents.base import BaseAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.db.models import FeedbackRecord, IOC
from sentinel.delivery.email_digest import render_daily_digest, send_daily_digest
from sentinel.delivery.telegram_bot import (
    build_feedback_markup,
    format_alert_message,
    format_daily_digest_intro,
)


@dataclass(slots=True)
class DeliveryResult:
    immediate_alerts: int
    digest_candidates: int


class DeliveryAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/delivery/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        telegram_bot: Any | None = None,
        sendgrid_client: SendGridAPIClient | Any | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        self.telegram_bot = telegram_bot
        self.sendgrid_client = sendgrid_client
        if self.sendgrid_client is None and self.settings.delivery.enable_email and not _is_missing_secret(self.settings.delivery.sendgrid_key):
            self.sendgrid_client = SendGridAPIClient(self.settings.delivery.sendgrid_key)
        if session_factory is None:
            from sentinel.db.session import AsyncSessionFactory

            self.session_factory = AsyncSessionFactory
        else:
            self.session_factory = session_factory

    def _coerce_ioc(self, item: ScoredIOC | dict[str, Any]) -> dict[str, Any]:
        if isinstance(item, ScoredIOC):
            return asdict(item)
        return {
            "id": item.get("id"),
            "value": item["value"],
            "type": item["type"],
            "source": item["source"],
            "risk_score": float(item["risk_score"]),
            "severity": item["severity"],
            "source_title": item.get("source_title"),
            "reference_url": item.get("reference_url"),
            "related_cves": list(item.get("related_cves", [])),
            "vt_detections": item.get("vt_detections"),
            "abuse_confidence": item.get("abuse_confidence"),
            "shodan_ports": list(item.get("shodan_ports", [])),
            "external_links": dict(item.get("external_links", {})),
            "mitre_techniques": list(item.get("mitre_techniques", [])),
            "mitre_tactics": list(item.get("mitre_tactics", [])),
            "last_seen": item.get("last_seen"),
        }

    def _within_last_24_hours(self, value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value >= datetime.now(UTC) - timedelta(hours=24)

    def _build_markup(self, ioc_id: str | None) -> InlineKeyboardMarkup | None:
        if not ioc_id:
            return None
        return build_feedback_markup(str(ioc_id))

    async def send_immediate_alert(self, item: dict[str, Any]) -> bool:
        if self.telegram_bot is None:
            return False
        message = format_alert_message(
            value=item["value"],
            ioc_type=item["type"],
            source=item["source"],
            risk_score=item["risk_score"],
            severity=item["severity"],
            last_seen=item.get("last_seen"),
            source_title=item.get("source_title"),
            reference_url=item.get("reference_url"),
            related_cves=item.get("related_cves", []),
            vt_detections=item.get("vt_detections"),
            abuse_confidence=item.get("abuse_confidence"),
            shodan_ports=item.get("shodan_ports", []),
            external_links=item.get("external_links", {}),
            mitre_techniques=item.get("mitre_techniques", []),
            mitre_tactics=item.get("mitre_tactics", []),
        )
        try:
            await self.telegram_bot.send_message(
                chat_id=self.settings.delivery.telegram_chat_id,
                text=message,
                reply_markup=self._build_markup(item.get("id")),
            )
            return True
        except TelegramError as exc:
            self.logger.warning("Telegram alert delivery failed for %s: %s", item["value"], type(exc).__name__)
            return False

    async def record_feedback(self, *, ioc_id: str, analyst_id: str, verdict: str, channel: str = "telegram") -> FeedbackRecord:
        normalized = {
            "confirm_threat": "confirmed",
            "confirmed": "confirmed",
            "false_positive": "false_positive",
            "needs_review": "needs_review",
        }.get(verdict, verdict)
        try:
            parsed_ioc_id: UUID | str = UUID(str(ioc_id))
        except ValueError:
            parsed_ioc_id = ioc_id
        async with self.session_factory() as session:
            record = FeedbackRecord(
                ioc_id=parsed_ioc_id,
                analyst_id=analyst_id,
                verdict=normalized,
                timestamp=datetime.now(UTC),
                channel=channel,
            )
            session.add(record)
            getter = getattr(session, "get", None)
            if getter is not None and isinstance(parsed_ioc_id, UUID):
                row = await getter(IOC, parsed_ioc_id)
                if row is not None:
                    row.analyst_verdict = normalized
            await session.commit()
            return record

    async def handle_callback_query(self, query: Any) -> FeedbackRecord:
        verdict, ioc_id = query.data.split(":", 1)
        await query.answer()
        return await self.record_feedback(
            ioc_id=ioc_id,
            analyst_id=str(query.from_user.id),
            verdict=verdict,
            channel="telegram",
        )

    async def daily_digest(self, items: list[dict[str, Any]]) -> Any:
        sorted_items = sorted(items, key=lambda item: float(item.get("risk_score", 0.0)), reverse=True)
        top_items = sorted_items[: self.settings.delivery.telegram_daily_digest_limit]
        result: dict[str, Any] = {
            "telegram": {"status": "disabled", "sent": False},
            "email": {"status": "disabled"},
            "count": len(top_items),
        }
        if self.telegram_bot is not None:
            generated_at = datetime.now(UTC).isoformat()
            try:
                await self.telegram_bot.send_message(
                    chat_id=self.settings.delivery.telegram_chat_id,
                    text=format_daily_digest_intro(
                        generated_at=generated_at,
                        count=len(top_items),
                        limit=self.settings.delivery.telegram_daily_digest_limit,
                    ),
                )
                for index, item in enumerate(top_items, start=1):
                    message = format_alert_message(
                        heading=f"SENTINEL Daily Digest {index}/{len(top_items)}",
                        value=item["value"],
                        ioc_type=item["type"],
                        source=item["source"],
                        risk_score=float(item["risk_score"]),
                        severity=item["severity"],
                        last_seen=item.get("last_seen"),
                        source_title=item.get("source_title"),
                        reference_url=item.get("reference_url"),
                        related_cves=item.get("related_cves", []),
                        vt_detections=item.get("vt_detections"),
                        abuse_confidence=item.get("abuse_confidence"),
                        shodan_ports=item.get("shodan_ports", []),
                        external_links=item.get("external_links", {}),
                        mitre_techniques=item.get("mitre_techniques", []),
                        mitre_tactics=item.get("mitre_tactics", []),
                    )
                    await self.telegram_bot.send_message(
                        chat_id=self.settings.delivery.telegram_chat_id,
                        text=message,
                        reply_markup=self._build_markup(item.get("id")),
                    )
                    if index < len(top_items):
                        await asyncio.sleep(0.75)
                result["telegram"] = {"status": "sent", "sent": True}
            except TelegramError as exc:
                self.logger.warning("Telegram daily digest delivery failed: %s", type(exc).__name__)
                result["telegram"] = {"status": "failed", "sent": False, "error": type(exc).__name__}
        if self.settings.delivery.enable_email and self.sendgrid_client is not None:
            html = render_daily_digest(top_items, generated_at=datetime.now(UTC).isoformat())
            response = await send_daily_digest(
                sendgrid_client=self.sendgrid_client,
                email_from=self.settings.delivery.email_from,
                recipients=self.settings.delivery.email_to,
                subject="SENTINEL Daily Digest",
                html=html,
            )
            result["email"] = {
                "status": "sent",
                "status_code": getattr(response, "status_code", None) if not isinstance(response, dict) else response.get("status_code"),
            }
        return result

    async def run(self, scored_iocs: list[ScoredIOC | dict[str, Any]], *args: Any, **kwargs: Any) -> DeliveryResult:
        self.reload_skill()
        items = [self._coerce_ioc(item) for item in scored_iocs]
        immediate: list[dict[str, Any]] = []
        if self.settings.delivery.enable_telegram_immediate_alerts:
            immediate = [item for item in items if item["risk_score"] >= self.settings.thresholds.alert_score]
            immediate.sort(key=lambda item: float(item["risk_score"]), reverse=True)
            immediate = immediate[: self.settings.delivery.telegram_max_alerts_per_run]
        digest_candidates = [
            item
            for item in items
            if item["risk_score"] >= 50 and self._within_last_24_hours(item.get("last_seen"))
        ]
        sent_immediate = 0
        for item in immediate:
            if await self.send_immediate_alert(item):
                sent_immediate += 1
        return DeliveryResult(immediate_alerts=sent_immediate, digest_candidates=len(digest_candidates))

    async def aclose(self) -> None:
        closer = getattr(self.telegram_bot, "shutdown", None)
        if closer is not None:
            maybe_awaitable = closer()
            if hasattr(maybe_awaitable, "__await__"):
                await maybe_awaitable

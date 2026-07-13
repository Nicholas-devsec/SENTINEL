from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sendgrid import SendGridAPIClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from telegram.error import TelegramError
from telegram import InlineKeyboardMarkup

from sentinel.alert_policy import build_alert_policy
from sentinel.agents.base import BaseAgent
from sentinel.agents.scorer import ScoredIOC
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.db.models import FeedbackRecord, IOC, IOCSighting
from sentinel.delivery.email_digest import render_daily_digest, send_daily_digest
from sentinel.delivery.telegram_bot import (
    build_feedback_markup,
    format_alert_message,
    format_grouped_alert_message,
    format_daily_digest_intro,
)


logger = logging.getLogger(__name__)


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
            "corroboration_sources": item.get("corroboration_sources"),
            "mitre_techniques": list(item.get("mitre_techniques", [])),
            "mitre_tactics": list(item.get("mitre_tactics", [])),
            "last_seen": item.get("last_seen"),
            "attributes": dict(item.get("attributes", {})),
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

    def _sort_last_seen_value(self, value: Any) -> datetime:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return datetime.min.replace(tzinfo=UTC)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value
        return datetime.min.replace(tzinfo=UTC)

    def _group_immediate_alerts(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        singles: list[dict[str, Any]] = []
        for item in items:
            reference_url = str(item.get("reference_url") or "").strip()
            if not reference_url:
                singles.append(item)
                continue
            grouped.setdefault(reference_url, []).append(item)

        cards: list[dict[str, Any]] = []
        for reference_url, members in grouped.items():
            ordered = sorted(
                members,
                key=lambda item: (
                    float(item.get("risk_score", 0.0)),
                    str(item.get("value", "")),
                ),
                reverse=True,
            )
            primary = ordered[0]
            if len(ordered) == 1:
                cards.append(primary)
                continue
            cards.append(
                {
                    **primary,
                    "grouped_iocs": [
                        {"type": member["type"], "value": member["value"]}
                        for member in ordered
                    ],
                    "related_cves": sorted(
                        {
                            cve
                            for member in ordered
                            for cve in member.get("related_cves", [])
                        }
                    ),
                    "mitre_techniques": sorted(
                        {
                            technique
                            for member in ordered
                            for technique in member.get("mitre_techniques", [])
                        }
                    ),
                    "mitre_tactics": sorted(
                        {
                            tactic
                            for member in ordered
                            for tactic in member.get("mitre_tactics", [])
                        }
                    ),
                    "corroboration_sources": max(
                        int(member.get("corroboration_sources", 1) or 1) for member in ordered
                    ),
                    "last_seen": max(
                        (
                            self._sort_last_seen_value(member.get("last_seen"))
                            for member in ordered
                            if member.get("last_seen") is not None
                        ),
                        default=primary.get("last_seen"),
                    ),
                }
            )
        cards.extend(singles)
        cards.sort(key=lambda item: float(item.get("risk_score", 0.0)), reverse=True)
        return cards

    def _is_web_discovery_item(self, item: dict[str, Any]) -> bool:
        return str(item.get("source") or "").strip().lower().startswith("discovery:")

    def _alert_policy(self):
        return build_alert_policy(self.settings)

    def _select_immediate_candidates(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        policy = self._alert_policy()
        qualified = [
            item
            for item in items
            if policy.qualifies_immediate(item, is_web_discovery=self._is_web_discovery_item(item))
        ]
        if not qualified:
            return []

        qualifying_urls = {
            str(item.get("reference_url") or "").strip()
            for item in qualified
            if str(item.get("reference_url") or "").strip()
        }
        selected: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for item in items:
            item_id = str(item.get("id") or "")
            reference_url = str(item.get("reference_url") or "").strip()
            include = policy.qualifies_immediate(item, is_web_discovery=self._is_web_discovery_item(item))
            if not include and reference_url and reference_url in qualifying_urls:
                include = True
            if not include:
                continue
            dedupe_key = item_id or f"{item.get('type')}|{item.get('value')}|{reference_url}"
            if dedupe_key in seen_ids:
                continue
            seen_ids.add(dedupe_key)
            selected.append(item)
        return selected

    def _select_digest_candidates(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        policy = self._alert_policy()
        return [
            item
            for item in items
            if self._within_last_24_hours(item.get("last_seen"))
            and policy.qualifies_digest(item, is_web_discovery=self._is_web_discovery_item(item))
        ]

    async def send_immediate_alert(self, item: dict[str, Any]) -> bool:
        if self.telegram_bot is None:
            return False
        grouped_iocs = item.get("grouped_iocs") or []
        if grouped_iocs:
            message = format_grouped_alert_message(
                source=item["source"],
                risk_score=item["risk_score"],
                severity=item["severity"],
                iocs=grouped_iocs,
                last_seen=item.get("last_seen"),
                source_title=item.get("source_title"),
                reference_url=item.get("reference_url"),
                related_cves=item.get("related_cves", []),
                corroboration_sources=item.get("corroboration_sources"),
                mitre_techniques=item.get("mitre_techniques", []),
                mitre_tactics=item.get("mitre_tactics", []),
                attributes=item.get("attributes", {}),
            )
        else:
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
                corroboration_sources=item.get("corroboration_sources"),
                mitre_techniques=item.get("mitre_techniques", []),
                mitre_tactics=item.get("mitre_tactics", []),
                attributes=item.get("attributes", {}),
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

    async def send_immediate_alerts(self, items: list[dict[str, Any]]) -> int:
        prepared = [self._coerce_ioc(item) for item in items]
        grouped = self._group_immediate_alerts(prepared)
        sent = 0
        for item in grouped:
            if await self.send_immediate_alert(item):
                sent += 1
        return sent

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
            existing = await self._find_existing_feedback(
                session=session,
                ioc_id=parsed_ioc_id,
                analyst_id=analyst_id,
                channel=channel,
            )
            getter = getattr(session, "get", None)
            row = None
            if getter is not None and isinstance(parsed_ioc_id, UUID):
                row = await getter(IOC, parsed_ioc_id)
            if existing is not None:
                if existing.verdict == normalized:
                    if row is not None:
                        row.analyst_verdict = normalized
                    await session.commit()
                    return existing
            record = FeedbackRecord(
                ioc_id=parsed_ioc_id,
                analyst_id=analyst_id,
                verdict=normalized,
                timestamp=datetime.now(UTC),
                channel=channel,
                source=row.source if row is not None else None,
            )
            if row is not None:
                row.analyst_verdict = normalized
            session.add(record)
            await session.commit()
            return record

    async def handle_callback_query(self, query: Any) -> FeedbackRecord | bool:
        verdict, ioc_id = query.data.split(":", 1)
        analyst_id = str(query.from_user.id)
        logger.info("Received Telegram feedback callback verdict=%s ioc_id=%s analyst_id=%s", verdict, ioc_id, analyst_id)
        try:
            if verdict == "remove_ioc":
                removed = await self.remove_ioc_from_db(ioc_id=ioc_id)
                await query.answer(
                    "Removed IOC from database" if removed else "IOC was already absent",
                    show_alert=True,
                )
                logger.info(
                    "Processed Telegram IOC removal ioc_id=%s analyst_id=%s removed=%s",
                    ioc_id,
                    analyst_id,
                    removed,
                )
                return removed
            existing = await self._feedback_exists(
                ioc_id=ioc_id,
                analyst_id=analyst_id,
                channel="telegram",
                verdict=verdict,
            )
            record = await self.record_feedback(
                ioc_id=ioc_id,
                analyst_id=analyst_id,
                verdict=verdict,
                channel="telegram",
            )
            await query.answer(
                self._feedback_ack_text(record.verdict, repeated=existing),
                show_alert=True,
            )
            logger.info(
                "Recorded Telegram feedback verdict=%s ioc_id=%s analyst_id=%s repeated=%s",
                record.verdict,
                ioc_id,
                analyst_id,
                existing,
            )
            return record
        except Exception:
            logger.exception("Failed to record Telegram feedback verdict=%s ioc_id=%s analyst_id=%s", verdict, ioc_id, analyst_id)
            try:
                await query.answer("Failed to record feedback", show_alert=True)
            except Exception:
                logger.exception("Failed to acknowledge Telegram feedback error to analyst_id=%s", analyst_id)
            raise

    async def remove_ioc_from_db(self, *, ioc_id: str) -> bool:
        try:
            parsed_ioc_id: UUID | str = UUID(str(ioc_id))
        except ValueError:
            parsed_ioc_id = ioc_id
        async with self.session_factory() as session:
            if hasattr(session, "remove_ioc"):
                return await session.remove_ioc(parsed_ioc_id)
            getter = getattr(session, "get", None)
            row = None
            if getter is not None and isinstance(parsed_ioc_id, UUID):
                row = await getter(IOC, parsed_ioc_id)
            if row is None:
                result = await session.execute(select(IOC).where(IOC.id == parsed_ioc_id).limit(1))
                row = result.scalar_one_or_none()
            if row is None:
                return False
            await session.execute(delete(IOCSighting).where(IOCSighting.ioc_id == parsed_ioc_id))
            await session.execute(delete(FeedbackRecord).where(FeedbackRecord.ioc_id == parsed_ioc_id))
            await session.delete(row)
            await session.commit()
            return True

    async def _find_existing_feedback(
        self,
        *,
        session: Any,
        ioc_id: UUID | str,
        analyst_id: str,
        channel: str,
    ) -> FeedbackRecord | None:
        if hasattr(session, "storage"):
            for record in reversed(session.storage):
                if str(record.ioc_id) == str(ioc_id) and record.analyst_id == analyst_id and record.channel == channel:
                    return record
            return None
        result = await session.execute(
            select(FeedbackRecord)
            .where(FeedbackRecord.ioc_id == ioc_id)
            .where(FeedbackRecord.analyst_id == analyst_id)
            .where(FeedbackRecord.channel == channel)
            .order_by(FeedbackRecord.timestamp.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _feedback_exists(
        self,
        *,
        ioc_id: str,
        analyst_id: str,
        channel: str,
        verdict: str,
    ) -> bool:
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
            existing = await self._find_existing_feedback(
                session=session,
                ioc_id=parsed_ioc_id,
                analyst_id=analyst_id,
                channel=channel,
            )
        return existing is not None and existing.verdict == normalized

    def _feedback_ack_text(self, verdict: str, *, repeated: bool) -> str:
        label = {
            "confirmed": "confirmed",
            "false_positive": "false positive",
            "needs_review": "needs review",
        }.get(verdict, verdict.replace("_", " "))
        prefix = "Already recorded" if repeated else "Recorded"
        return f"{prefix}: {label}"

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
            immediate_candidates = self._select_immediate_candidates(items)
            immediate = self._group_immediate_alerts(immediate_candidates)
            immediate = immediate[: self.settings.delivery.telegram_max_alerts_per_run]
        digest_candidates = self._select_digest_candidates(items)
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

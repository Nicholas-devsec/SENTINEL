from __future__ import annotations

import asyncio
import html
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
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
from sentinel.db.models import AlertEvent, FeedbackRecord, IOC, IOCSighting
from sentinel.delivery.email_digest import render_daily_digest, send_daily_digest
from sentinel.delivery.telegram_bot import (
    TELEGRAM_PARSE_MODE,
    build_feedback_markup,
    format_alert_message,
    format_grouped_alert_message,
    format_daily_digest_intro,
)
from sentinel.feedback import CONFIRMED, FALSE_POSITIVE, LOW_LEVEL_TRUE_POSITIVE, NEEDS_REVIEW, normalize_verdict


logger = logging.getLogger(__name__)
FALLBACK_DIGEST_MIN_SCORE = 25.0
HASH_TYPES = {"md5", "sha1", "sha256"}
DIRECT_IOC_FEED_SOURCES = {"threatfox", "urlhaus", "feodotracker", "otx", "malwarebazaar", "phishtank"}
CAMPAIGN_STOPWORDS = {
    "about",
    "access",
    "account",
    "accounts",
    "against",
    "analyst",
    "attack",
    "attacks",
    "breach",
    "campaign",
    "credential",
    "credentials",
    "cyber",
    "data",
    "delivers",
    "delivery",
    "evolves",
    "files",
    "for",
    "from",
    "government",
    "group",
    "hackers",
    "harvest",
    "impacting",
    "indicator",
    "indicators",
    "information",
    "intel",
    "kit",
    "kits",
    "loader",
    "malware",
    "phishing",
    "persistent",
    "payload",
    "payloads",
    "ransomware",
    "real",
    "report",
    "research",
    "security",
    "silently",
    "sophisticated",
    "stealer",
    "steals",
    "sending",
    "targets",
    "threat",
    "toolkit",
    "toolkits",
    "update",
    "uses",
    "using",
    "weeks",
    "with",
}


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

    def _is_article_card(self, item: dict[str, Any]) -> bool:
        provenance = str(item.get("provenance") or item.get("attributes", {}).get("provenance") or "").strip().lower()
        source = str(item.get("source") or "").strip().lower()
        reference_url = str(item.get("reference_url") or "").strip()
        grouped = item.get("grouped_iocs") or []
        if source in DIRECT_IOC_FEED_SOURCES:
            return False
        if not reference_url:
            return False
        if provenance in {"writeup", "discovery"} or source.startswith("discovery:"):
            return True
        return bool(grouped) or bool(item.get("source_title"))

    def _is_discovery_article_card(self, item: dict[str, Any]) -> bool:
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        provenance = str(item.get("provenance") or attrs.get("provenance") or "").strip().lower()
        source = str(item.get("source") or "").strip().lower()
        return provenance == "discovery" or source.startswith("discovery:")

    def _group_immediate_alerts(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        singles: list[dict[str, Any]] = []
        for item in items:
            reference_url = str(item.get("reference_url") or "").strip()
            if not reference_url or not self._is_article_card(item):
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
                    "grouped_ids": [str(member.get("id")) for member in ordered if member.get("id")],
                    "grouped_iocs": [
                        {
                            "type": member["type"],
                            "value": member["value"],
                            "section_label": member.get("attributes", {}).get("ioc_section_label"),
                        }
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
                    "attributes": {
                        **dict(primary.get("attributes", {})),
                        "article_ioc_count": max(
                            int(member.get("attributes", {}).get("article_ioc_count", 0) or 0)
                            for member in ordered
                        )
                        or len(ordered),
                    },
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

    def _title_tokens(self, item: dict[str, Any]) -> set[str]:
        title = str(item.get("source_title") or "").lower()
        return {
            token
            for token in re.findall(r"[a-z0-9]+", title)
            if len(token) >= 5 and token not in CAMPAIGN_STOPWORDS
        }

    def _campaign_signature(self, item: dict[str, Any]) -> frozenset[str]:
        tokens = self._title_tokens(item)
        if tokens:
            return frozenset(sorted(tokens))
        reference_url = str(item.get("reference_url") or "").strip()
        host = urlparse(reference_url).hostname or ""
        host_tokens = {
            token
            for token in re.findall(r"[a-z0-9]+", host.lower())
            if len(token) >= 5 and token not in {"www", "blog", "news", "com", "org", "net"}
        }
        return frozenset(sorted(host_tokens))

    def _ioc_entries_for_card(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        grouped = item.get("grouped_iocs") or []
        if grouped:
            return [
                {
                    "type": str(member.get("type", "unknown")),
                    "value": str(member.get("value", "")),
                    "section_label": member.get("section_label"),
                }
                for member in grouped
            ]
        return [
            {
                "type": str(item.get("type", "unknown")),
                "value": str(item.get("value", "")),
                "section_label": item.get("attributes", {}).get("ioc_section_label"),
            }
        ]

    def _merge_digest_card(self, base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged_iocs: dict[tuple[str, str], dict[str, str]] = {}
        for member in self._ioc_entries_for_card(base) + self._ioc_entries_for_card(incoming):
            key = (member["type"], member["value"])
            merged_iocs[key] = member
        related_titles = sorted(
            {
                title
                for title in [
                    base.get("source_title"),
                    incoming.get("source_title"),
                    *(base.get("attributes", {}).get("related_titles") or []),
                    *(incoming.get("attributes", {}).get("related_titles") or []),
                ]
                if title
            }
        )
        related_urls = sorted(
            {
                url
                for url in [
                    base.get("reference_url"),
                    incoming.get("reference_url"),
                    *(base.get("attributes", {}).get("related_urls") or []),
                    *(incoming.get("attributes", {}).get("related_urls") or []),
                ]
                if url
            }
        )
        primary = base
        secondary = incoming
        if float(incoming.get("risk_score", 0.0)) > float(base.get("risk_score", 0.0)):
            primary, secondary = incoming, base
        attributes = dict(primary.get("attributes", {}))
        attributes["related_titles"] = related_titles
        attributes["related_urls"] = related_urls
        attributes["similar_article_count"] = len(related_urls) or len(related_titles) or 1
        attributes["article_ioc_count"] = max(
            int(base.get("attributes", {}).get("article_ioc_count", 0) or 0),
            int(incoming.get("attributes", {}).get("article_ioc_count", 0) or 0),
            len(merged_iocs),
        )
        return {
            **primary,
            "grouped_iocs": sorted(
                merged_iocs.values(),
                key=lambda entry: (
                    str(entry.get("section_label") or ""),
                    entry["type"],
                    entry["value"],
                ),
            ),
            "related_cves": sorted({*primary.get("related_cves", []), *secondary.get("related_cves", [])}),
            "mitre_techniques": sorted({*primary.get("mitre_techniques", []), *secondary.get("mitre_techniques", [])}),
            "mitre_tactics": sorted({*primary.get("mitre_tactics", []), *secondary.get("mitre_tactics", [])}),
            "corroboration_sources": max(
                int(primary.get("corroboration_sources", 1) or 1),
                int(secondary.get("corroboration_sources", 1) or 1),
            ),
            "last_seen": max(
                self._sort_last_seen_value(primary.get("last_seen")),
                self._sort_last_seen_value(secondary.get("last_seen")),
            ),
            "attributes": attributes,
        }

    def _dedupe_digest_cards(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cards = self._group_immediate_alerts(items)
        cards.sort(
            key=lambda item: (
                float(item.get("risk_score", 0.0)),
                self._sort_last_seen_value(item.get("last_seen")),
            ),
            reverse=True,
        )
        deduped: list[dict[str, Any]] = []
        for card in cards:
            if not self._is_article_card(card):
                deduped.append(card)
                continue
            signature = self._campaign_signature(card)
            merged = False
            if signature:
                for index, existing in enumerate(deduped):
                    if signature & self._campaign_signature(existing):
                        deduped[index] = self._merge_digest_card(existing, card)
                        merged = True
                        break
            if not merged:
                deduped.append(card)
        deduped.sort(
            key=lambda item: (
                float(item.get("risk_score", 0.0)),
                self._sort_last_seen_value(item.get("last_seen")),
            ),
            reverse=True,
        )
        return deduped

    def _is_web_discovery_item(self, item: dict[str, Any]) -> bool:
        return str(item.get("source") or "").strip().lower().startswith("discovery:")

    def _hash_family_key(self, item: dict[str, Any]) -> str | None:
        ioc_type = str(item.get("type") or "").strip().lower()
        if ioc_type not in HASH_TYPES:
            return None
        attributes = item.get("attributes") or {}
        family = attributes.get("hash_family") if isinstance(attributes, dict) else None
        if isinstance(family, dict):
            for hash_type in ("sha256", "sha1", "md5"):
                value = family.get(hash_type)
                if isinstance(value, str) and value.strip():
                    return value.strip().lower()
        explicit_key = attributes.get("hash_family_key") if isinstance(attributes, dict) else None
        if isinstance(explicit_key, str) and explicit_key.strip():
            return explicit_key.strip().lower()
        value = str(item.get("value") or "").strip().lower()
        return value or None

    def _dedupe_hash_family_candidates(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_family: dict[str, dict[str, Any]] = {}
        passthrough: list[dict[str, Any]] = []
        for item in items:
            family_key = self._hash_family_key(item)
            if family_key is None:
                passthrough.append(item)
                continue
            existing = by_family.get(family_key)
            if existing is None:
                by_family[family_key] = item
        deduped = [*passthrough, *by_family.values()]
        deduped.sort(
            key=lambda item: (
                float(item.get("risk_score", 0.0) or 0.0),
                self._sort_last_seen_value(item.get("last_seen")),
            ),
            reverse=True,
        )
        suppressed = len(items) - len(deduped)
        if suppressed:
            self.logger.info("Suppressed %s duplicate file-hash variant alert candidate(s)", suppressed)
        return deduped

    # -- alert ledger -------------------------------------------------------
    #
    # Feed items linger in source windows for days, so the same IOC would be
    # re-selected and re-sent on every cron run without a persistent record of
    # what was already delivered. The ledger also keeps immediate alerts from
    # being double-counted into the next daily digest.

    def _card_ioc_ids(self, card: dict[str, Any]) -> list[str]:
        grouped_ids = card.get("grouped_ids") or []
        if grouped_ids:
            return [str(ioc_id) for ioc_id in grouped_ids if ioc_id]
        ioc_id = card.get("id")
        return [str(ioc_id)] if ioc_id else []

    async def _recently_alerted_ids(self, ioc_ids: list[str]) -> set[str]:
        parsed: list[UUID] = []
        for raw in ioc_ids:
            try:
                parsed.append(UUID(str(raw)))
            except (TypeError, ValueError):
                continue
        if not parsed:
            return set()
        cutoff = datetime.now(UTC) - timedelta(
            hours=max(1, int(self.settings.delivery.alert_resend_after_hours))
        )
        async with self.session_factory() as session:
            if not hasattr(session, "execute"):
                return set()
            rows = await session.execute(
                select(AlertEvent.ioc_id)
                .where(AlertEvent.ioc_id.in_(parsed))
                .where(AlertEvent.sent_at >= cutoff)
            )
            return {str(ioc_id) for (ioc_id,) in rows.all()}

    async def _feedback_labeled_ids(self, ioc_ids: list[str]) -> set[str]:
        parsed: list[UUID] = []
        for raw in ioc_ids:
            try:
                parsed.append(UUID(str(raw)))
            except (TypeError, ValueError):
                continue
        if not parsed:
            return set()
        feedback_verdicts = {CONFIRMED, LOW_LEVEL_TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_REVIEW}
        async with self.session_factory() as session:
            if not hasattr(session, "execute"):
                return set()
            rows = await session.execute(
                select(FeedbackRecord.ioc_id)
                .where(FeedbackRecord.ioc_id.in_(parsed))
                .where(FeedbackRecord.verdict.in_(sorted(feedback_verdicts)))
            )
            return {str(ioc_id) for (ioc_id,) in rows.all()}

    async def _filter_recently_alerted(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        recently = await self._recently_alerted_ids(
            [str(item.get("id")) for item in items if item.get("id")]
        )
        if not recently:
            return items
        kept = [item for item in items if str(item.get("id") or "") not in recently]
        suppressed = len(items) - len(kept)
        if suppressed:
            self.logger.info(
                "Alert ledger suppressed %s already-alerted IOC(s) within the %sh resend window",
                suppressed,
                self.settings.delivery.alert_resend_after_hours,
            )
        return kept

    async def _filter_feedback_labeled(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        labeled = await self._feedback_labeled_ids(
            [str(item.get("id")) for item in items if item.get("id")]
        )
        if not labeled:
            return items
        kept = [item for item in items if str(item.get("id") or "") not in labeled]
        suppressed = len(items) - len(kept)
        if suppressed:
            self.logger.info("Feedback ledger suppressed %s already-labeled IOC alert candidate(s)", suppressed)
        return kept

    async def _record_alert_events(self, cards: list[dict[str, Any]], *, alert_kind: str) -> None:
        now = datetime.now(UTC)
        events: list[AlertEvent] = []
        for card in cards:
            for ioc_id in self._card_ioc_ids(card):
                try:
                    parsed = UUID(str(ioc_id))
                except (TypeError, ValueError):
                    continue
                events.append(
                    AlertEvent(
                        ioc_id=parsed,
                        channel="telegram",
                        alert_kind=alert_kind,
                        reference_url=str(card.get("reference_url") or "") or None,
                        risk_score=float(card.get("risk_score", 0.0) or 0.0),
                        sent_at=now,
                    )
                )
        if not events:
            return
        async with self.session_factory() as session:
            if not hasattr(session, "execute"):
                return
            for event in events:
                session.add(event)
            await session.commit()

    def _alert_policy(self):
        return build_alert_policy(self.settings)

    def _trusted_feedback_sources(self) -> set[str]:
        return {
            feed.name.lower()
            for feed in self.settings.sources.feeds
            if feed.enabled and float(feed.trust) >= 0.90
        }

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

    def _select_feedback_backfill_candidates(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        floor = float(self.settings.thresholds.feedback_candidate_score)
        trusted_sources = self._trusted_feedback_sources()
        candidates: list[dict[str, Any]] = []
        for item in items:
            source = str(item.get("source") or "").strip().lower()
            if source not in trusted_sources:
                continue
            if not self._within_last_24_hours(item.get("last_seen")):
                continue
            if float(item.get("risk_score", 0.0)) < floor:
                continue
            attributes = dict(item.get("attributes", {}))
            attributes["delivery_reason"] = "feedback_backfill"
            candidates.append({**item, "attributes": attributes})
        candidates.sort(
            key=lambda item: (
                float(item.get("risk_score", 0.0)),
                self._sort_last_seen_value(item.get("last_seen")),
            ),
            reverse=True,
        )
        return candidates

    def _top_up_feed_type_candidates(
        self,
        selected: list[dict[str, Any]],
        pool: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        limits = self._normalized_type_limits(self.settings.workflow.telegram_type_limits_per_run)
        if not limits:
            return selected
        counts = {key: 0 for key in limits}
        seen = {str(item.get("id") or f"{item.get('type')}|{item.get('value')}") for item in selected}
        for item in selected:
            if self._is_article_card(item):
                continue
            bucket = self._type_bucket_for(str(item.get("type") or ""))
            if bucket in counts:
                counts[bucket] += 1
        topped_up = list(selected)
        for item in pool:
            if self._is_article_card(item):
                continue
            key = str(item.get("id") or f"{item.get('type')}|{item.get('value')}")
            if key in seen:
                continue
            bucket = self._type_bucket_for(str(item.get("type") or ""))
            if bucket not in limits or counts[bucket] >= limits[bucket]:
                continue
            topped_up.append(item)
            seen.add(key)
            counts[bucket] += 1
            if all(counts[key] >= limit for key, limit in limits.items()):
                break
        return topped_up

    def _normalized_type_limits(self, type_limits: dict[str, int] | None) -> dict[str, int]:
        limits: dict[str, int] = {}
        for raw_key, raw_limit in (type_limits or {}).items():
            key = str(raw_key).strip().lower()
            if not key:
                continue
            limits[key] = max(0, int(raw_limit))
        return limits

    def _type_bucket_for(self, item_type: str) -> str:
        normalized = str(item_type or "").strip().lower()
        if normalized in HASH_TYPES:
            return "hash"
        return normalized

    def _campaign_key(self, item: dict[str, Any]) -> str:
        reference_url = str(item.get("reference_url") or "").strip().lower()
        if reference_url:
            return f"reference:{reference_url}"
        source = str(item.get("source") or "").strip().lower()
        source_title = str(item.get("source_title") or "").strip().lower()
        if source_title:
            return f"title:{source}:{source_title}"
        return f"ioc:{source}:{item.get('type')}:{item.get('value')}"

    def _diversify_campaign_cards(self, cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
        diversified: list[dict[str, Any]] = []
        deferred: list[dict[str, Any]] = []
        seen_campaigns: set[str] = set()
        for card in cards:
            campaign_key = self._campaign_key(card)
            if campaign_key in seen_campaigns:
                deferred.append(card)
                continue
            seen_campaigns.add(campaign_key)
            diversified.append(card)
        return [*diversified, *deferred]

    def _apply_type_limits(self, cards: list[dict[str, Any]], type_limits: dict[str, int] | None) -> list[dict[str, Any]]:
        limits = self._normalized_type_limits(type_limits)
        if not limits:
            return cards
        counts = {key: 0 for key in limits}
        selected: list[dict[str, Any]] = []
        for card in cards:
            bucket = self._type_bucket_for(str(card.get("type") or ""))
            if bucket not in limits:
                continue
            if counts[bucket] >= limits[bucket]:
                continue
            counts[bucket] += 1
            selected.append(card)
        return selected

    def _apply_delivery_limits(self, cards: list[dict[str, Any]], *, apply_burst_cap: bool = True) -> list[dict[str, Any]]:
        feed_limit = max(0, int(self.settings.workflow.telegram_feed_alert_limit_per_run))
        feed_cards: list[dict[str, Any]] = []
        feed_article_cards: list[dict[str, Any]] = []
        discovery_article_cards: list[dict[str, Any]] = []
        for card in cards:
            if self._is_article_card(card):
                if self._is_discovery_article_card(card):
                    discovery_article_cards.append(card)
                else:
                    feed_article_cards.append(card)
            else:
                feed_cards.append(card)
        feed_cards = self._diversify_campaign_cards(feed_cards)
        feed_cards = self._apply_type_limits(feed_cards, self.settings.workflow.telegram_type_limits_per_run)
        feed_cards = self._diversify_campaign_cards(feed_cards)
        if (
            self.settings.workflow.telegram_feed_article_alert_limit_per_run is not None
            or self.settings.workflow.telegram_discovery_article_alert_limit_per_run is not None
        ):
            feed_article_limit = max(0, int(self.settings.workflow.telegram_feed_article_alert_limit_per_run or 0))
            discovery_article_limit = max(0, int(self.settings.workflow.telegram_discovery_article_alert_limit_per_run or 0))
            article_cards = [
                *feed_article_cards[:feed_article_limit],
                *discovery_article_cards[:discovery_article_limit],
            ]
        else:
            article_limit = max(0, int(self.settings.workflow.telegram_article_alert_limit_per_run))
            article_cards = [*feed_article_cards, *discovery_article_cards][:article_limit]
        limited = [*feed_cards[:feed_limit], *article_cards]
        limited.sort(key=lambda item: float(item.get("risk_score", 0.0)), reverse=True)
        burst_cap = max(0, int(self.settings.delivery.telegram_max_alerts_per_run))
        if apply_burst_cap and burst_cap > 0:
            return limited[:burst_cap]
        return limited

    def _select_digest_candidates(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        policy = self._alert_policy()
        recent_items = [
            item
            for item in items
            if self._within_last_24_hours(item.get("last_seen"))
        ]
        qualified = [
            item
            for item in recent_items
            if policy.qualifies_digest(item, is_web_discovery=self._is_web_discovery_item(item))
        ]
        backfill = [
            item
            for item in recent_items
            if policy.qualifies_digest_backfill(item, is_web_discovery=self._is_web_discovery_item(item))
        ]
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in [*qualified, *backfill]:
            dedupe_key = str(item.get("id") or f"{item.get('type')}|{item.get('value')}|{item.get('reference_url')}")
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            selected.append(item)
        if selected:
            return self._dedupe_hash_family_candidates(selected)
        return [
            item
            for item in self._dedupe_hash_family_candidates(recent_items)
            if float(item.get("risk_score", 0.0)) >= FALLBACK_DIGEST_MIN_SCORE
        ]

    async def _load_ioc_row(self, session: Any, parsed_ioc_id: UUID | str) -> IOC | None:
        if not hasattr(session, "execute") and not hasattr(session, "get"):
            return None
        getter = getattr(session, "get", None)
        if getter is not None and isinstance(parsed_ioc_id, UUID):
            row = await getter(IOC, parsed_ioc_id)
            if row is not None:
                return row
        result = await session.execute(select(IOC).where(IOC.id == parsed_ioc_id).limit(1))
        return result.scalar_one_or_none()

    async def _record_feedback_with_session(
        self,
        *,
        session: Any,
        ioc_id: UUID | str,
        analyst_id: str,
        verdict: str,
        channel: str,
    ) -> FeedbackRecord:
        existing = await self._find_existing_feedback(
            session=session,
            ioc_id=ioc_id,
            analyst_id=analyst_id,
            channel=channel,
        )
        row = await self._load_ioc_row(session, ioc_id)
        if existing is not None and existing.verdict == verdict:
            if row is not None:
                row.analyst_verdict = verdict
            return existing
        record = FeedbackRecord(
            ioc_id=ioc_id,
            analyst_id=analyst_id,
            verdict=verdict,
            timestamp=datetime.now(UTC),
            channel=channel,
            source=row.source if row is not None else None,
        )
        if row is not None:
            row.analyst_verdict = verdict
        session.add(record)
        return record

    async def _feedback_target_ids(self, session: Any, *, parsed_ioc_id: UUID | str) -> list[UUID | str]:
        if hasattr(session, "feedback_target_ids"):
            return list(await session.feedback_target_ids(parsed_ioc_id))
        if not hasattr(session, "execute") and not hasattr(session, "get"):
            return [parsed_ioc_id]
        row = await self._load_ioc_row(session, parsed_ioc_id)
        if row is None:
            return []
        result = await session.execute(
            select(IOCSighting.provenance, IOCSighting.reference_url).where(IOCSighting.ioc_id == parsed_ioc_id)
        )
        sightings = result.all()
        article_urls = {
            str(reference_url).strip()
            for provenance, reference_url in sightings
            if str(provenance or "").strip().lower() in {"writeup", "discovery"} and str(reference_url or "").strip()
        }
        if not article_urls:
            return [parsed_ioc_id]
        target_ids: set[UUID | str] = {parsed_ioc_id}
        for article_url in article_urls:
            sibling_rows = await session.execute(
                select(IOCSighting.ioc_id).where(IOCSighting.reference_url == article_url)
            )
            target_ids.update(ioc_id for (ioc_id,) in sibling_rows.all())
        return list(target_ids)

    async def _suppress_false_positive_scope(
        self,
        *,
        parsed_ioc_id: UUID | str,
        analyst_id: str,
        channel: str = "telegram",
    ) -> tuple[int, bool]:
        async with self.session_factory() as session:
            target_ids = await self._feedback_target_ids(session, parsed_ioc_id=parsed_ioc_id)
            if not target_ids:
                return 0, False
            changed = False
            for target_id in target_ids:
                existing = await self._find_existing_feedback(
                    session=session,
                    ioc_id=target_id,
                    analyst_id=analyst_id,
                    channel=channel,
                )
                if existing is None or existing.verdict != "false_positive":
                    changed = True
                await self._record_feedback_with_session(
                    session=session,
                    ioc_id=target_id,
                    analyst_id=analyst_id,
                    verdict="false_positive",
                    channel=channel,
                )
            await session.commit()
            return len(target_ids), changed

    async def send_immediate_alert(self, item: dict[str, Any]) -> bool:
        if self.telegram_bot is None:
            return False
        grouped_iocs = item.get("grouped_iocs") or []
        delivery_reason = item.get("attributes", {}).get("delivery_reason")
        if delivery_reason == "feedback_backfill":
            heading = "SENTINEL Feedback Candidate"
        elif delivery_reason == "needs_review_retriage":
            heading = "SENTINEL Needs Review"
        else:
            heading = "SENTINEL Alert"
        if grouped_iocs:
            message = format_grouped_alert_message(
                heading=heading,
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
                heading=heading,
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
                parse_mode=TELEGRAM_PARSE_MODE,
                reply_markup=self._build_markup(item.get("id")),
            )
            await self._record_alert_events([item], alert_kind="immediate")
            return True
        except TelegramError as exc:
            self.logger.warning("Telegram alert delivery failed for %s: %s", item["value"], type(exc).__name__)
            return False

    async def send_immediate_alerts(self, items: list[dict[str, Any]]) -> int:
        prepared = [self._coerce_ioc(item) for item in items]
        prepared = await self._filter_recently_alerted(prepared)
        prepared = await self._filter_feedback_labeled(prepared)
        grouped = self._group_immediate_alerts(prepared)
        sent = 0
        for item in grouped:
            if await self.send_immediate_alert(item):
                sent += 1
        return sent

    async def record_feedback(self, *, ioc_id: str, analyst_id: str, verdict: str, channel: str = "telegram") -> FeedbackRecord:
        normalized = normalize_verdict(verdict)
        try:
            parsed_ioc_id: UUID | str = UUID(str(ioc_id))
        except ValueError:
            parsed_ioc_id = ioc_id
        async with self.session_factory() as session:
            record = await self._record_feedback_with_session(
                session=session,
                ioc_id=parsed_ioc_id,
                analyst_id=analyst_id,
                verdict=normalized,
                channel=channel,
            )
            await session.commit()
            return record

    async def handle_callback_query(self, query: Any) -> FeedbackRecord | bool:
        raw_verdict, ioc_id = query.data.split(":", 1)
        verdict = normalize_verdict(raw_verdict)
        analyst_id = str(query.from_user.id)
        logger.info("Received Telegram feedback callback verdict=%s ioc_id=%s analyst_id=%s", verdict, ioc_id, analyst_id)
        try:
            try:
                parsed_ioc_id: UUID | str = UUID(str(ioc_id))
            except ValueError:
                parsed_ioc_id = ioc_id
            if verdict == FALSE_POSITIVE:
                affected, changed = await self._suppress_false_positive_scope(
                    parsed_ioc_id=parsed_ioc_id,
                    analyst_id=analyst_id,
                    channel="telegram",
                )
                ack_text = "Already suppressed" if not changed else f"Recorded FP and suppressed {affected} IOC(s)"
                await query.answer(ack_text, show_alert=True)
                await self._confirm_callback_message(query, verdict=FALSE_POSITIVE, repeated=not changed)
                return affected
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
            await self._confirm_callback_message(query, verdict=record.verdict, repeated=existing)
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
        normalized = normalize_verdict(verdict)
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
            CONFIRMED: "confirmed",
            LOW_LEVEL_TRUE_POSITIVE: "low-level true positive",
            FALSE_POSITIVE: "false positive",
            NEEDS_REVIEW: "needs review",
        }.get(verdict, verdict.replace("_", " "))
        prefix = "Already recorded" if repeated else "Recorded"
        return f"{prefix}: {label}"

    async def _confirm_callback_message(self, query: Any, *, verdict: str, repeated: bool) -> None:
        message = getattr(query, "message", None)
        if message is None:
            return
        confirmation = self._feedback_confirmation_note(verdict, repeated=repeated)
        confirmation_html = f"<b>{html.escape(confirmation)}</b>"
        try:
            current_html = str(getattr(message, "html_text", None) or "")
            current_text = str(getattr(message, "text", "") or "")
            if not current_html and current_text:
                current_html = html.escape(current_text)
            if current_html and confirmation not in current_text and hasattr(message, "edit_text"):
                await message.edit_text(
                    f"{current_html}\n\n{confirmation_html}",
                    parse_mode=TELEGRAM_PARSE_MODE,
                    reply_markup=None,
                )
                return
            current_caption_html = str(getattr(message, "html_caption", None) or "")
            current_caption = str(getattr(message, "caption", "") or "")
            if not current_caption_html and current_caption:
                current_caption_html = html.escape(current_caption)
            if current_caption_html and confirmation not in current_caption and hasattr(message, "edit_caption"):
                await message.edit_caption(
                    caption=f"{current_caption_html}\n\n{confirmation_html}",
                    parse_mode=TELEGRAM_PARSE_MODE,
                    reply_markup=None,
                )
                return
            if hasattr(message, "edit_reply_markup"):
                await message.edit_reply_markup(reply_markup=None)
                await self._send_callback_confirmation_reply(message, confirmation)
                return
            await self._send_callback_confirmation_reply(message, confirmation)
        except Exception:
            logger.exception("Failed to update Telegram alert with callback confirmation")
            await self._send_callback_confirmation_reply(message, confirmation)

    async def _send_callback_confirmation_reply(self, message: Any, confirmation: str) -> None:
        reply_text = getattr(message, "reply_text", None)
        if reply_text is None:
            return
        try:
            await reply_text(
                f"Feedback confirmation: {confirmation}",
                disable_notification=True,
            )
        except Exception:
            logger.exception("Failed to send Telegram callback confirmation reply")

    def _feedback_confirmation_note(self, verdict: str, *, repeated: bool) -> str:
        label = {
            CONFIRMED: "True Positive",
            LOW_LEVEL_TRUE_POSITIVE: "Low-level True Positive",
            FALSE_POSITIVE: "False Positive",
            NEEDS_REVIEW: "Needs Review",
        }.get(verdict, verdict.replace("_", " ").title())
        prefix = "Feedback already recorded" if repeated else "Feedback recorded"
        return f"{prefix}: {label}"

    async def daily_digest(self, items: list[dict[str, Any]]) -> Any:
        items = await self._filter_recently_alerted(items)
        items = await self._filter_feedback_labeled(items)
        digest_cards = self._dedupe_digest_cards(items)
        top_items = self._apply_delivery_limits(digest_cards, apply_burst_cap=False)[
            : self.settings.delivery.telegram_daily_digest_limit
        ]
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
                    grouped_iocs = item.get("grouped_iocs") or []
                    if grouped_iocs:
                        message = format_grouped_alert_message(
                            heading=f"SENTINEL Daily Digest {index}/{len(top_items)}",
                            source=item["source"],
                            risk_score=float(item["risk_score"]),
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
                            attributes=item.get("attributes", {}),
                        )
                    await self.telegram_bot.send_message(
                        chat_id=self.settings.delivery.telegram_chat_id,
                        text=message,
                        parse_mode=TELEGRAM_PARSE_MODE,
                        reply_markup=self._build_markup(item.get("id")),
                    )
                    if index < len(top_items):
                        await asyncio.sleep(0.75)
                await self._record_alert_events(top_items, alert_kind="digest")
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
            feedback_backfill_candidates = self._select_feedback_backfill_candidates(items)
            if immediate_candidates:
                immediate_candidates = self._top_up_feed_type_candidates(
                    immediate_candidates,
                    feedback_backfill_candidates,
                )
            else:
                immediate_candidates = feedback_backfill_candidates
            immediate_candidates = self._dedupe_hash_family_candidates(immediate_candidates)
            immediate_candidates = await self._filter_recently_alerted(immediate_candidates)
            immediate_candidates = await self._filter_feedback_labeled(immediate_candidates)
            immediate = self._group_immediate_alerts(immediate_candidates)
            immediate = self._apply_delivery_limits(immediate)
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

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol

import feedparser
import httpx
from redis.asyncio import Redis

from sentinel.agents.base import BaseAgent
from sentinel.config import SentinelSettings, _is_disabled_value, _is_missing_secret, get_settings


TRUST_SCORES_SECTION = re.compile(r"## Trust Scores\s+(.*?)(?:\n## |\Z)", re.DOTALL)
TRUST_SCORE_LINE = re.compile(r"^- ([a-zA-Z0-9_:-]+):\s*([0-9]*\.?[0-9]+)\s*$")
CVE_TEXT_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass(slots=True)
class RawIOC:
    value: str
    type: str
    source: str
    source_trust: float
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = field(default_factory=list)
    description: str | None = None
    reference_url: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_queue_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["first_seen"] = self.first_seen.isoformat()
        payload["last_seen"] = self.last_seen.isoformat()
        return payload


class SourceAdapter(Protocol):
    source_name: str

    async def fetch(self) -> list[RawIOC]:
        ...


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _normalize_timestamp(value: str | None) -> datetime:
    if not value:
        return _now_utc()
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return _now_utc()


def _infer_ioc_type(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ipv4"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    return "domain"


class OTXPulseAdapter:
    source_name = "otx"

    def __init__(
        self,
        api_url: str,
        *,
        trust_score: float,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_url = api_url
        self.trust_score = trust_score
        self.api_key = api_key
        self.client = client or httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    def _extract_indicator_value(self, indicator: dict[str, Any]) -> str | None:
        for key in ("indicator", "ioc", "url", "domain", "hostname", "ip", "value"):
            value = indicator.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _extract_reference_url(self, pulse: dict[str, Any], indicator: dict[str, Any]) -> str | None:
        for key in ("reference", "reference_url", "url"):
            value = indicator.get(key)
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                return value
        references = pulse.get("references")
        if isinstance(references, list):
            for reference in references:
                if isinstance(reference, str) and reference.startswith(("http://", "https://")):
                    return reference
        return None

    def _extract_tags(self, pulse: dict[str, Any], indicator: dict[str, Any]) -> list[str]:
        tags: list[str] = []
        for container in (pulse.get("tags"), indicator.get("tags")):
            if isinstance(container, list):
                tags.extend(str(tag).strip() for tag in container if str(tag).strip())
        malware_families = pulse.get("malware_families")
        if isinstance(malware_families, list):
            for family in malware_families:
                if isinstance(family, dict):
                    display_name = family.get("display_name") or family.get("name")
                    if isinstance(display_name, str) and display_name.strip():
                        tags.append(display_name.strip())
        return sorted(set(tags))

    def _extract_description(self, pulse: dict[str, Any], indicator: dict[str, Any]) -> str | None:
        for key in ("description", "title"):
            value = indicator.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for key in ("name", "title", "description"):
            value = pulse.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _normalize_indicator_type(self, raw_type: str | None, value: str) -> str:
        if not raw_type:
            return _infer_ioc_type(value)
        normalized = raw_type.strip().lower()
        mapping = {
            "hostname": "domain",
            "domain": "domain",
            "domain-name": "domain",
            "url": "url",
            "uri": "url",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "filehash-md5": "md5",
            "filehash-sha1": "sha1",
            "filehash-sha256": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "cve": "cve",
        }
        return mapping.get(normalized, _infer_ioc_type(value))

    def _build_record(self, pulse: dict[str, Any], indicator: dict[str, Any]) -> RawIOC | None:
        value = self._extract_indicator_value(indicator)
        if not value:
            return None
        indicator_type = indicator.get("type")
        normalized_type = self._normalize_indicator_type(indicator_type if isinstance(indicator_type, str) else None, value)
        seen = _normalize_timestamp(
            str(
                indicator.get("created")
                or indicator.get("modified")
                or pulse.get("modified")
                or pulse.get("created")
                or ""
            )
        )
        pulse_name = pulse.get("name")
        pulse_id = pulse.get("id")
        author_name = pulse.get("author_name")
        return RawIOC(
            value=value,
            type=normalized_type,
            source=self.source_name,
            source_trust=self.trust_score,
            first_seen=seen,
            last_seen=seen,
            tags=self._extract_tags(pulse, indicator),
            description=self._extract_description(pulse, indicator),
            reference_url=self._extract_reference_url(pulse, indicator),
            attributes={
                "pulse_id": pulse_id,
                "pulse_name": pulse_name,
                "indicator_id": indicator.get("id"),
                "indicator_type": indicator.get("type"),
                "author_name": author_name,
            },
        )

    async def fetch(self) -> list[RawIOC]:
        response = await self.client.get(self.api_url, headers=self._headers())
        response.raise_for_status()
        payload = response.json()
        pulses = payload.get("results", payload) if isinstance(payload, dict) else payload
        if not isinstance(pulses, list):
            return []
        records: list[RawIOC] = []
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            indicators = pulse.get("indicators")
            if not isinstance(indicators, list):
                continue
            for indicator in indicators:
                if not isinstance(indicator, dict):
                    continue
                record = self._build_record(pulse, indicator)
                if record is not None:
                    records.append(record)
        return records


class URLHausAdapter:
    source_name = "urlhaus"

    def __init__(self, feed_url: str, *, trust_score: float, client: httpx.AsyncClient | None = None) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        self.client = client or httpx.AsyncClient(timeout=30.0)

    async def fetch(self) -> list[RawIOC]:
        response = await self.client.get(self.feed_url)
        response.raise_for_status()
        reader = csv.DictReader(io.StringIO(response.text))
        records: list[RawIOC] = []
        for row in reader:
            value = (row.get("url") or row.get("ioc") or "").strip()
            if not value:
                continue
            seen = _normalize_timestamp(row.get("dateadded") or row.get("firstseen"))
            tags = [tag.strip() for tag in (row.get("tags") or "").split(",") if tag.strip()]
            records.append(
                RawIOC(
                    value=value,
                    type="url",
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=seen,
                    last_seen=seen,
                    tags=tags,
                    description=row.get("threat") or row.get("url_status"),
                    reference_url=row.get("urlhaus_link"),
                    attributes={
                        "url_status": row.get("url_status"),
                        "reporter": row.get("reporter"),
                    },
                )
            )
        return records


class FeodoTrackerAdapter:
    source_name = "feodotracker"

    def __init__(self, feed_url: str, *, trust_score: float, client: httpx.AsyncClient | None = None) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        self.client = client or httpx.AsyncClient(timeout=30.0)

    async def fetch(self) -> list[RawIOC]:
        response = await self.client.get(self.feed_url)
        response.raise_for_status()
        payload = response.json()
        records: list[RawIOC] = []
        for item in payload:
            value = str(item.get("ip_address") or item.get("host") or "").strip()
            if not value:
                continue
            seen = _normalize_timestamp(item.get("first_seen") or item.get("last_online"))
            records.append(
                RawIOC(
                    value=value,
                    type="ipv4",
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=seen,
                    last_seen=_normalize_timestamp(item.get("last_online")) if item.get("last_online") else seen,
                    tags=[
                        tag
                        for tag in [item.get("malware"), item.get("status")]
                        if isinstance(tag, str) and tag
                    ],
                    description=item.get("host") or item.get("malware"),
                    attributes={
                        "port": item.get("port"),
                        "asn": item.get("asn"),
                        "country": item.get("country"),
                    },
                )
            )
        return records


class RSSAdapter:
    source_name = "rss_default"

    def __init__(self, feed_url: str, *, trust_score: float, client: httpx.AsyncClient | None = None) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        self.client = client or httpx.AsyncClient(timeout=30.0)

    async def fetch(self) -> list[RawIOC]:
        response = await self.client.get(self.feed_url)
        response.raise_for_status()
        parsed = feedparser.parse(response.text)
        records: list[RawIOC] = []
        for entry in parsed.entries:
            link = getattr(entry, "link", None) or entry.get("link")
            title = getattr(entry, "title", None) or entry.get("title")
            published = getattr(entry, "published", None) or entry.get("published")
            summary = getattr(entry, "summary", None) or entry.get("summary")
            value = link or title
            if not value:
                continue
            records.append(
                RawIOC(
                    value=value.strip(),
                    type="url" if link else "domain",
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=_normalize_timestamp(published),
                    last_seen=_normalize_timestamp(published),
                    tags=[tag.get("term") for tag in entry.get("tags", []) if tag.get("term")],
                    description=title or summary,
                    reference_url=link,
                    attributes={"summary": summary},
                )
            )
        return records


class ScraperAgent(BaseAgent):
    queue_name = "sentinel:raw_iocs"

    def __init__(
        self,
        skill_path: str = "skills/sources/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        redis_client: Redis | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        self.redis = redis_client
        self.http_client = http_client or httpx.AsyncClient(timeout=30.0)
        self._owns_redis = redis_client is None
        self._owns_http_client = http_client is None

    def _extract_related_cves(self, item: RawIOC) -> list[str]:
        text_parts: list[str] = [item.value, item.description or "", " ".join(item.tags)]
        for value in item.attributes.values():
            if isinstance(value, str):
                text_parts.append(value)
        matches = {
            match.group(0).upper()
            for match in CVE_TEXT_RE.finditer("\n".join(text_parts))
        }
        return sorted(matches)

    def _is_recent(self, item: RawIOC) -> bool:
        cutoff = datetime.now(UTC) - __import__("datetime").timedelta(days=self.settings.sources.max_item_age_days)
        return max(item.first_seen, item.last_seen) >= cutoff

    def _decorate_item(self, item: RawIOC) -> RawIOC:
        attributes = dict(item.attributes)
        attributes["related_cves"] = self._extract_related_cves(item)
        return RawIOC(
            value=item.value,
            type=item.type,
            source=item.source,
            source_trust=item.source_trust,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            tags=list(item.tags),
            description=item.description,
            reference_url=item.reference_url,
            attributes=attributes,
        )

    def get_source_trust_scores(self) -> dict[str, float]:
        section_match = TRUST_SCORES_SECTION.search(self.skill_prompt)
        if not section_match:
            return {}
        trust_scores: dict[str, float] = {}
        for raw_line in section_match.group(1).splitlines():
            match = TRUST_SCORE_LINE.match(raw_line.strip())
            if match:
                trust_scores[match.group(1).lower()] = float(match.group(2))
        return trust_scores

    def _build_adapters(self) -> list[SourceAdapter]:
        trust_scores = self.get_source_trust_scores()
        adapters: list[SourceAdapter] = []
        for feed in self.settings.sources.feeds:
            if not feed.enabled:
                continue
            source_name = feed.name.lower()
            trust_score = trust_scores.get(source_name, feed.trust)
            if source_name == "urlhaus":
                adapters.append(URLHausAdapter(feed.url, trust_score=trust_score, client=self.http_client))
            elif source_name == "feodotracker":
                adapters.append(FeodoTrackerAdapter(feed.url, trust_score=trust_score, client=self.http_client))
            elif source_name == "otx":
                adapters.append(
                    OTXPulseAdapter(
                        feed.url,
                        trust_score=trust_score,
                        api_key=self.settings.sources.otx_api_key,
                        client=self.http_client,
                    )
                )
            else:
                adapters.append(RSSAdapter(feed.url, trust_score=trust_score, client=self.http_client))
        return adapters

    async def publish_to_queue(self, iocs: Iterable[RawIOC]) -> int:
        redis_url = self.settings.db.redis_url
        if _is_missing_secret(redis_url) or _is_disabled_value(redis_url):
            self.logger.info("Skipping Redis queue publish because REDIS_URL is disabled.")
            return 0
        if self.redis is None:
            self.redis = Redis.from_url(redis_url, decode_responses=True)
        count = 0
        try:
            for ioc in iocs:
                await self.redis.rpush(self.queue_name, json.dumps(ioc.to_queue_payload()))
                count += 1
        except Exception as exc:
            self.logger.warning("Redis queue publish failed; continuing without queue persistence: %s", type(exc).__name__)
            return 0
        return count

    async def run(self, *args: Any, **kwargs: Any) -> list[RawIOC]:
        self.reload_skill()
        adapters = self._build_adapters()
        results = await asyncio.gather(*(adapter.fetch() for adapter in adapters), return_exceptions=True)
        collected: list[RawIOC] = []
        for adapter, result in zip(adapters, results, strict=True):
            if isinstance(result, Exception):
                self.logger.exception("Scrape failed for source %s", adapter.source_name, exc_info=result)
                continue
            self.logger.info("Scraped %s indicators from %s", len(result), adapter.source_name)
            collected.extend(self._decorate_item(item) for item in result if self._is_recent(item))
        await self.publish_to_queue(collected)
        return collected

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self.http_client.aclose()
        if self._owns_redis and self.redis is not None:
            await self.redis.aclose()

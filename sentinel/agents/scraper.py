from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import urlparse

import feedparser
import httpx
from redis.asyncio import Redis
from sqlalchemy import select

from sentinel.agents.base import BaseAgent
from sentinel.config import SentinelSettings, _is_disabled_value, _is_missing_secret, get_settings
from sentinel.db.models import DiscoveryMemory, Source


TRUST_SCORES_SECTION = re.compile(r"## Trust Scores\s+(.*?)(?:\n## |\Z)", re.DOTALL)
TRUST_SCORE_LINE = re.compile(r"^- ([a-zA-Z0-9_:-]+):\s*([0-9]*\.?[0-9]+)\s*$")
CVE_TEXT_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DEFAULT_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}
OTX_HOSTS = {"otx.alienvault.com"}
SECTION_ONLY_WRITEUP_SOURCES = {"google_cloud_threat_intelligence"}
SANS_ISC_DIARY_SOURCE = "sans_isc_diary"
SANS_ISC_CONTEXT_RE = re.compile(
    r"\b(?:attacker|scanner|source ip|c2|command and control|malicious host)\b",
    re.IGNORECASE,
)
SANS_ISC_PUBLIC_RESOLVERS = {
    "1.0.0.1",
    "1.1.1.1",
    "8.8.4.4",
    "8.8.8.8",
    "9.9.9.9",
    "9.9.9.10",
}
SANS_ISC_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


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
    provenance: str = "feed"

    def to_queue_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["first_seen"] = self.first_seen.isoformat()
        payload["last_seen"] = self.last_seen.isoformat()
        return payload


@dataclass(slots=True)
class RawWriteup:
    """An article/blog post treated as source material, never as an IOC itself."""

    source: str
    source_trust: float
    url: str
    title: str | None
    published_at: datetime
    summary: str | None = None
    tags: list[str] = field(default_factory=list)
    content_text: str | None = None
    fetch_error: str | None = None


@dataclass(slots=True)
class SourceScrapeDiagnostic:
    source: str
    fetched: int = 0
    pre_balance_kept: int = 0
    kept: int = 0
    stale_dropped: int = 0
    balance_dropped: int = 0
    error: str | None = None
    writeups_fetched: int = 0
    iocs_extracted: int = 0


@dataclass(slots=True)
class ScrapeReport:
    items: list[RawIOC]
    diagnostics: list[SourceScrapeDiagnostic]
    writeups: list[RawWriteup] = field(default_factory=list)


class SourceAdapter(Protocol):
    source_name: str

    async def fetch(self) -> list[RawIOC]:
        ...


class WriteupAdapter(Protocol):
    source_name: str

    async def fetch_writeups(self) -> list[RawWriteup]:
        ...


class SnapshotStateStore(Protocol):
    async def load(self) -> dict[str, Any]:
        ...

    async def save(self, state: dict[str, Any]) -> None:
        ...


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _normalize_timestamp(value: str | None) -> datetime:
    if not value:
        return _now_utc()
    normalized = value.strip()
    try:
        if normalized.endswith("Z"):
            return datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if normalized.endswith(" UTC"):
            return datetime.fromisoformat(normalized.removesuffix(" UTC").replace(" ", "T") + "+00:00")
        if normalized.endswith(" GMT"):
            return datetime.fromisoformat(normalized.removesuffix(" GMT").replace(" ", "T") + "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(normalized)
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


def _is_otx_url(url: str) -> bool:
    host = (urlparse(str(url or "")).hostname or "").lower()
    return host in OTX_HOSTS


class OTXPulseAdapter:
    source_name = "otx"

    def __init__(
        self,
        api_url: str,
        *,
        trust_score: float,
        lookback_hours: int | None = None,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_url = api_url
        self.trust_score = trust_score
        self.lookback_hours = lookback_hours
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
        pulse_id = pulse.get("id")
        if isinstance(pulse_id, str) and pulse_id.strip():
            return f"https://otx.alienvault.com/pulse/{pulse_id.strip()}"
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
        params: dict[str, Any] = {"limit": 50}
        if self.lookback_hours is not None:
            # OTX accepts timestamp-based filtering; keeping this explicit narrows the pull to the same
            # rolling window we enforce locally and reduces stale subscribed pulse results.
            params["modified_since"] = (_now_utc() - __import__("datetime").timedelta(hours=self.lookback_hours)).isoformat()
        response = await self.client.get(self.api_url, headers=self._headers(), params=params)
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


class ThreatFoxAdapter:
    source_name = "threatfox"

    def __init__(
        self,
        api_url: str,
        *,
        trust_score: float,
        api_key: str | None = None,
        lookback_hours: int = 24,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_url = api_url
        self.trust_score = trust_score
        self.api_key = api_key
        self.lookback_hours = lookback_hours
        self.client = client or httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _normalize_ioc_type(self, raw_type: str | None, value: str) -> tuple[str, str, dict[str, Any]]:
        if not raw_type:
            return _infer_ioc_type(value), value, {}
        normalized = raw_type.strip().lower()
        attributes: dict[str, Any] = {}
        if normalized == "ip:port":
            host, _, port = value.partition(":")
            if port.isdigit():
                attributes["port"] = int(port)
            return "ipv4", host, attributes
        mapping = {
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "domain": "domain",
            "url": "url",
            "md5_hash": "md5",
            "sha1_hash": "sha1",
            "sha256_hash": "sha256",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
        }
        return mapping.get(normalized, _infer_ioc_type(value)), value, attributes

    async def fetch(self) -> list[RawIOC]:
        if not self.api_key or _is_missing_secret(self.api_key):
            return []
        days = max(1, min(7, int((self.lookback_hours + 23) // 24)))
        response = await self.client.post(
            self.api_url,
            headers=self._headers(),
            json={"query": "get_iocs", "days": days},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("query_status") != "ok":
            return []
        data = payload.get("data")
        if not isinstance(data, list):
            return []
        records: list[RawIOC] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            value = str(item.get("ioc") or "").strip()
            if not value:
                continue
            normalized_type, normalized_value, extra_attributes = self._normalize_ioc_type(item.get("ioc_type"), value)
            first_seen = _normalize_timestamp(item.get("first_seen"))
            last_seen = _normalize_timestamp(item.get("last_seen")) if item.get("last_seen") else first_seen
            tags = []
            for tag in item.get("tags") or []:
                if isinstance(tag, str) and tag.strip():
                    tags.append(tag.strip())
            for extra_tag in (item.get("malware_printable"), item.get("threat_type")):
                if isinstance(extra_tag, str) and extra_tag.strip():
                    tags.append(extra_tag.strip())
            records.append(
                RawIOC(
                    value=normalized_value,
                    type=normalized_type,
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    tags=sorted(set(tags)),
                    description=item.get("threat_type_desc") or item.get("ioc_type_desc") or item.get("malware_printable"),
                    reference_url=(
                        f"https://threatfox.abuse.ch/ioc/{item.get('id')}/"
                        if item.get("id")
                        else item.get("reference") or None
                    ),
                    attributes={
                        "threatfox_id": item.get("id"),
                        "reference_url_original": item.get("reference") or None,
                        "threat_type": item.get("threat_type"),
                        "malware": item.get("malware"),
                        "malware_printable": item.get("malware_printable"),
                        "confidence_level": item.get("confidence_level"),
                        "reporter": item.get("reporter"),
                        **extra_attributes,
                    },
                )
            )
        return records


class MalwareBazaarAdapter:
    source_name = "malwarebazaar"

    def __init__(
        self,
        api_url: str,
        *,
        trust_score: float,
        api_key: str | None = None,
        lookback_hours: int = 24,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_url = api_url
        self.trust_score = trust_score
        self.api_key = api_key
        self.lookback_hours = lookback_hours
        self.client = client or httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _build_records(self, sample: dict[str, Any]) -> list[RawIOC]:
        first_seen = _normalize_timestamp(sample.get("first_seen"))
        last_seen = _normalize_timestamp(sample.get("last_seen")) if sample.get("last_seen") else first_seen
        sha256_hash = str(sample.get("sha256_hash") or "").strip()
        reference_url = f"https://bazaar.abuse.ch/sample/{sha256_hash}/" if sha256_hash else None
        tags = []
        for field in ("signature", "file_type", "file_name"):
            value = sample.get(field)
            if isinstance(value, str) and value.strip():
                tags.append(value.strip())
        if isinstance(sample.get("tags"), list):
            tags.extend(str(tag).strip() for tag in sample["tags"] if str(tag).strip())

        records: list[RawIOC] = []
        for raw_key, ioc_type in (("md5_hash", "md5"), ("sha1_hash", "sha1"), ("sha256_hash", "sha256")):
            value = str(sample.get(raw_key) or "").strip()
            if not value:
                continue
            records.append(
                RawIOC(
                    value=value,
                    type=ioc_type,
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    tags=sorted(set(tags)),
                    description=sample.get("signature") or sample.get("file_name") or "MalwareBazaar recent detection",
                    reference_url=reference_url,
                    attributes={
                        "sample_sha256": sha256_hash or None,
                        "file_name": sample.get("file_name"),
                        "signature": sample.get("signature"),
                        "reporter": sample.get("reporter"),
                        "file_type": sample.get("file_type"),
                    },
                )
            )
        return records

    async def fetch(self) -> list[RawIOC]:
        if not self.api_key or _is_missing_secret(self.api_key):
            return []
        hours = max(1, min(168, int(self.lookback_hours)))
        response = await self.client.post(
            self.api_url,
            headers=self._headers(),
            data={"query": "recent_detections", "hours": str(hours)},
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return []
        records: list[RawIOC] = []
        for sample in data:
            if not isinstance(sample, dict):
                continue
            records.extend(self._build_records(sample))
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
        filtered_lines: list[str] = []
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                candidate = line.lstrip("#").strip()
                if candidate.startswith("id,dateadded,"):
                    filtered_lines.append(candidate)
                continue
            filtered_lines.append(raw_line)
        if not filtered_lines:
            return []
        reader = csv.DictReader(io.StringIO("\n".join(filtered_lines)))
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


class DatabaseSnapshotStateStore:
    """Persist snapshot feed state in the configured source row."""

    def __init__(self, *, source_name: str, feed_url: str, trust_score: float) -> None:
        self.source_name = source_name
        self.feed_url = feed_url
        self.trust_score = trust_score

    async def load(self) -> dict[str, Any]:
        from sentinel.db.session import AsyncSessionFactory

        async with AsyncSessionFactory() as session:
            row = await session.scalar(select(Source).where(Source.name == self.source_name))
            if row is None:
                return {}
            metadata = row.metadata_json or {}
            return dict(metadata.get("snapshot_state") or {})

    async def save(self, state: dict[str, Any]) -> None:
        from sentinel.db.session import AsyncSessionFactory

        async with AsyncSessionFactory() as session:
            row = await session.scalar(select(Source).where(Source.name == self.source_name))
            if row is None:
                row = Source(
                    name=self.source_name,
                    url=self.feed_url,
                    trust=self.trust_score,
                    metadata_json={},
                )
                session.add(row)
                await session.flush()
            row.url = self.feed_url
            row.trust = self.trust_score
            metadata = dict(row.metadata_json or {})
            metadata["snapshot_state"] = state
            row.metadata_json = metadata
            await session.commit()


class OpenPhishAdapter:
    source_name = "openphish"

    def __init__(
        self,
        feed_url: str,
        *,
        trust_score: float,
        lookback_hours: int = 24,
        client: httpx.AsyncClient | None = None,
        state_store: SnapshotStateStore | None = None,
        now_factory: Any | None = None,
    ) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        self.lookback_hours = lookback_hours
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self.state_store = state_store or DatabaseSnapshotStateStore(
            source_name=self.source_name,
            feed_url=feed_url,
            trust_score=trust_score,
        )
        self.now_factory = now_factory or _now_utc

    def _headers(self, state: dict[str, Any]) -> dict[str, str]:
        headers = {
            "Accept": "text/plain",
            "User-Agent": DEFAULT_BROWSER_HEADERS["User-Agent"],
        }
        etag = str(state.get("etag") or "").strip()
        if etag:
            headers["If-None-Match"] = etag
        last_modified = str(state.get("last_modified") or "").strip()
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        return headers

    def _parse_urls(self, body: str) -> list[str]:
        urls: set[str] = set()
        for raw_line in body.splitlines():
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            if value.startswith(("http://", "https://")):
                urls.add(value)
        return sorted(urls)

    def _fresh_enough_to_diff(self, state: dict[str, Any], now: datetime) -> bool:
        raw_value = str(state.get("last_successful_at") or "").strip()
        if not raw_value:
            return False
        previous = _normalize_timestamp(raw_value)
        return now - previous <= timedelta(hours=max(0, int(self.lookback_hours)))

    def _next_state(
        self,
        *,
        state: dict[str, Any],
        now: datetime,
        content_hash: str | None = None,
        urls: list[str] | None = None,
        response: httpx.Response | None = None,
        unchanged: bool = False,
        emitted: int = 0,
        rebaseline_reason: str | None = None,
    ) -> dict[str, Any]:
        next_state = dict(state)
        next_state["last_checked_at"] = now.isoformat()
        next_state["last_successful_at"] = now.isoformat()
        next_state["last_emitted_count"] = emitted
        if rebaseline_reason:
            next_state["last_rebaseline_reason"] = rebaseline_reason
        elif "last_rebaseline_reason" in next_state:
            next_state.pop("last_rebaseline_reason", None)
        if unchanged:
            next_state["last_unchanged_at"] = now.isoformat()
        if content_hash is not None:
            next_state["content_sha256"] = content_hash
        if urls is not None:
            next_state["snapshot_urls"] = urls
            next_state["snapshot_count"] = len(urls)
        if response is not None:
            etag = response.headers.get("etag")
            last_modified = response.headers.get("last-modified")
            if etag:
                next_state["etag"] = etag
            if last_modified:
                next_state["last_modified"] = last_modified
        return next_state

    async def fetch(self) -> list[RawIOC]:
        try:
            state = await self.state_store.load()
        except Exception:
            return []

        now = self.now_factory()
        response = await self.client.get(self.feed_url, headers=self._headers(state))
        if response.status_code == 304:
            try:
                await self.state_store.save(self._next_state(state=state, now=now, response=response, unchanged=True))
            except Exception:
                return []
            return []
        response.raise_for_status()

        content_hash = hashlib.sha256(response.content).hexdigest()
        urls = self._parse_urls(response.text)
        raw_snapshot_urls = state.get("snapshot_urls")
        if not isinstance(raw_snapshot_urls, list):
            raw_snapshot_urls = []
        previous_urls = {
            str(value).strip()
            for value in raw_snapshot_urls
            if isinstance(value, str) and value.strip()
        }
        state_has_baseline = isinstance(state.get("snapshot_urls"), list) and bool(state.get("content_sha256"))
        if content_hash == state.get("content_sha256"):
            try:
                await self.state_store.save(
                    self._next_state(
                        state=state,
                        now=now,
                        content_hash=content_hash,
                        urls=urls,
                        response=response,
                        unchanged=True,
                    )
                )
            except Exception:
                return []
            return []

        if not state_has_baseline:
            try:
                await self.state_store.save(
                    self._next_state(
                        state=state,
                        now=now,
                        content_hash=content_hash,
                        urls=urls,
                        response=response,
                        rebaseline_reason="initial_baseline",
                    )
                )
            except Exception:
                return []
            return []

        if not self._fresh_enough_to_diff(state, now):
            try:
                await self.state_store.save(
                    self._next_state(
                        state=state,
                        now=now,
                        content_hash=content_hash,
                        urls=urls,
                        response=response,
                        rebaseline_reason="stale_snapshot_gap",
                    )
                )
            except Exception:
                return []
            return []

        added_urls = [url for url in urls if url not in previous_urls]
        try:
            await self.state_store.save(
                self._next_state(
                    state=state,
                    now=now,
                    content_hash=content_hash,
                    urls=urls,
                    response=response,
                    emitted=len(added_urls),
                )
            )
        except Exception:
            return []

        return [
            RawIOC(
                value=url,
                type="url",
                source=self.source_name,
                source_trust=self.trust_score,
                first_seen=now,
                last_seen=now,
                tags=["phishing", "openphish_community"],
                description="OpenPhish community phishing URL",
                reference_url="https://openphish.com/",
                attributes={
                    "feed_tier": "community",
                    "update_frequency": "12h",
                    "snapshot_diff": True,
                },
            )
            for url in added_urls
        ]


class TweetFeedAdapter:
    source_name = "tweetfeed"

    def __init__(self, api_url: str, *, trust_score: float, client: httpx.AsyncClient | None = None) -> None:
        self.api_url = api_url
        self.trust_score = trust_score
        self.client = client or httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": DEFAULT_BROWSER_HEADERS["User-Agent"],
        }

    def _normalize_ioc_type(self, raw_type: str | None, value: str) -> str:
        if not raw_type:
            return _infer_ioc_type(value)
        normalized = raw_type.strip().lower()
        mapping = {
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "domain": "domain",
            "url": "url",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
        }
        return mapping.get(normalized, _infer_ioc_type(value))

    async def fetch(self) -> list[RawIOC]:
        response = await self.client.get(self.api_url, headers=self._headers())
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            return []

        records: list[RawIOC] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            seen = _normalize_timestamp(str(item.get("date") or ""))
            tags = [str(tag).strip() for tag in item.get("tags") or [] if str(tag).strip()]
            user = str(item.get("user") or "").strip()
            tweet = str(item.get("tweet") or "").strip()
            records.append(
                RawIOC(
                    value=value,
                    type=self._normalize_ioc_type(item.get("type") if isinstance(item.get("type"), str) else None, value),
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=seen,
                    last_seen=seen,
                    tags=sorted(set(tags)),
                    description=f"TweetFeed IOC shared by @{user}" if user else "TweetFeed community IOC",
                    reference_url=tweet or None,
                    attributes={
                        "reporter": user or None,
                        "tweet": tweet or None,
                    },
                )
            )
        return records


class PhishTankAdapter:
    source_name = "phishtank"

    def __init__(
        self,
        feed_url: str,
        *,
        trust_score: float,
        app_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        self.app_key = app_key
        self.client = client or httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        return {"User-Agent": "phishtank/sentinel"}

    def _feed_url(self) -> str:
        if not self.app_key or _is_missing_secret(self.app_key):
            return self.feed_url
        marker = "/data/"
        if marker not in self.feed_url:
            return self.feed_url
        prefix, suffix = self.feed_url.split(marker, 1)
        return f"{prefix}{marker}{self.app_key.strip()}/{suffix}"

    async def fetch(self) -> list[RawIOC]:
        if not self.app_key or _is_missing_secret(self.app_key):
            return []
        response = await self.client.get(self._feed_url(), headers=self._headers())
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            return []
        records: list[RawIOC] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            value = str(item.get("url") or "").strip()
            if not value:
                continue
            seen = _normalize_timestamp(item.get("verification_time") or item.get("submission_time"))
            records.append(
                RawIOC(
                    value=value,
                    type="url",
                    source=self.source_name,
                    source_trust=self.trust_score,
                    first_seen=seen,
                    last_seen=seen,
                    tags=[tag for tag in [item.get("target"), "verified_phishing"] if isinstance(tag, str) and tag.strip()],
                    description=item.get("target") or "PhishTank verified phishing URL",
                    reference_url=item.get("phish_detail_url"),
                    attributes={
                        "phish_id": item.get("phish_id"),
                        "verified": item.get("verified"),
                        "online": item.get("online"),
                        "target": item.get("target"),
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
    """RSS/Atom feeds yield writeups (source material), not IOCs.

    Article links are never emitted as indicators; IOCs come from extracting
    the fetched article body downstream.
    """

    source_name = "rss_default"

    def __init__(
        self,
        feed_url: str,
        *,
        trust_score: float,
        source_name: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.feed_url = feed_url
        self.trust_score = trust_score
        if source_name is not None:
            self.source_name = source_name
        self.client = client or httpx.AsyncClient(timeout=30.0)

    async def fetch_writeups(self) -> list[RawWriteup]:
        response = await self.client.get(self.feed_url)
        response.raise_for_status()
        parsed = feedparser.parse(response.text)
        records: list[RawWriteup] = []
        for entry in parsed.entries:
            link = getattr(entry, "link", None) or entry.get("link")
            title = getattr(entry, "title", None) or entry.get("title")
            published = getattr(entry, "published", None) or entry.get("published")
            summary = getattr(entry, "summary", None) or entry.get("summary")
            if not link:
                continue
            records.append(
                RawWriteup(
                    source=self.source_name,
                    source_trust=self.trust_score,
                    url=link.strip(),
                    title=title,
                    published_at=_normalize_timestamp(published),
                    summary=summary,
                    tags=[tag.get("term") for tag in entry.get("tags", []) if tag.get("term")],
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
        request_timeout = float(self.settings.sources.http_timeout_seconds)
        self.http_client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(request_timeout, connect=min(request_timeout, 10.0)),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=0),
        )
        self._owns_redis = redis_client is None
        self._owns_http_client = http_client is None

    def _request_headers(self, url: str) -> dict[str, str]:
        headers = dict(DEFAULT_BROWSER_HEADERS)
        headers["Referer"] = url
        return headers

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
        cutoff = _now_utc() - timedelta(hours=self.settings.sources.max_item_age_hours)
        return max(item.first_seen, item.last_seen) >= cutoff

    def _writeup_cutoff(self) -> datetime:
        return _now_utc() - timedelta(hours=self.settings.sources.writeup_max_item_age_hours)

    def _writeup_search_terms(self) -> list[str]:
        return [term.strip().lower() for term in self.settings.sources.writeup_search.terms if term.strip()]

    def _matches_writeup_search(self, writeup: RawWriteup) -> bool:
        if writeup.source.lower() == SANS_ISC_DIARY_SOURCE:
            # Diary titles are often concrete but omit the generic search
            # terms; the Stormcast entries are podcast summaries, not diaries.
            return not (writeup.title or "").lower().startswith("isc stormcast")
        search_settings = self.settings.sources.writeup_search
        if not search_settings.enabled:
            return True
        terms = self._writeup_search_terms()
        if not terms:
            return True
        haystack = "\n".join(
            [
                writeup.title or "",
                writeup.summary or "",
                " ".join(writeup.tags),
            ]
        ).lower()
        return any(term in haystack for term in terms)

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
            provenance=item.provenance,
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

    def _build_adapters(self) -> tuple[list[SourceAdapter], list[WriteupAdapter]]:
        trust_scores = self.get_source_trust_scores()
        ioc_adapters: list[SourceAdapter] = []
        writeup_adapters: list[WriteupAdapter] = []
        for feed in self.settings.sources.feeds:
            if not feed.enabled:
                continue
            source_name = feed.name.lower()
            trust_score = trust_scores.get(source_name, feed.trust)
            if source_name == "urlhaus":
                ioc_adapters.append(URLHausAdapter(feed.url, trust_score=trust_score, client=self.http_client))
            elif source_name == "feodotracker":
                ioc_adapters.append(FeodoTrackerAdapter(feed.url, trust_score=trust_score, client=self.http_client))
            elif source_name == "otx" or _is_otx_url(feed.url):
                ioc_adapters.append(
                    OTXPulseAdapter(
                        feed.url,
                        trust_score=trust_score,
                        lookback_hours=self.settings.sources.max_item_age_hours,
                        api_key=self.settings.sources.otx_api_key,
                        client=self.http_client,
                    )
                )
            elif source_name == "threatfox":
                ioc_adapters.append(
                    ThreatFoxAdapter(
                        feed.url,
                        trust_score=trust_score,
                        api_key=self.settings.sources.threatfox_api_key,
                        lookback_hours=self.settings.sources.max_item_age_hours,
                        client=self.http_client,
                    )
                )
            elif source_name == "malwarebazaar":
                ioc_adapters.append(
                    MalwareBazaarAdapter(
                        feed.url,
                        trust_score=trust_score,
                        api_key=self.settings.sources.malwarebazaar_api_key,
                        lookback_hours=self.settings.sources.max_item_age_hours,
                        client=self.http_client,
                    )
                )
            elif source_name == "tweetfeed":
                ioc_adapters.append(TweetFeedAdapter(feed.url, trust_score=trust_score, client=self.http_client))
            elif source_name == "openphish":
                ioc_adapters.append(
                    OpenPhishAdapter(
                        feed.url,
                        trust_score=trust_score,
                        lookback_hours=self.settings.sources.max_item_age_hours,
                        client=self.http_client,
                    )
                )
            elif source_name == "phishtank":
                ioc_adapters.append(
                    PhishTankAdapter(
                        feed.url,
                        trust_score=trust_score,
                        app_key=self.settings.sources.phishtank_app_key,
                        client=self.http_client,
                    )
                )
            else:
                writeup_adapters.append(
                    RSSAdapter(
                        feed.url,
                        trust_score=trust_score,
                        source_name=source_name,
                        client=self.http_client,
                    )
                )
        return ioc_adapters, writeup_adapters

    async def _fetch_article_body(self, writeup: RawWriteup) -> None:
        from sentinel.agents.ioc_extract import html_to_text

        try:
            response = await asyncio.wait_for(
                self.http_client.get(writeup.url, headers=self._request_headers(writeup.url)),
                timeout=float(self.settings.sources.http_timeout_seconds),
            )
            response.raise_for_status()
            # Cap body size so a pathological page cannot balloon memory.
            writeup.content_text = html_to_text(response.text[:1_500_000])[:200_000]
        except Exception as exc:
            writeup.fetch_error = f"{type(exc).__name__}: {exc}"

    def _extract_iocs_from_writeup(self, writeup: RawWriteup) -> list[RawIOC]:
        from urllib.parse import urlparse

        from sentinel.agents.ioc_extract import (
            ExtractedIOC,
            extract_iocs_from_section,
            extract_iocs_from_text,
            find_ioc_section,
            refang,
        )

        text_parts = [writeup.title or "", writeup.summary or "", writeup.content_text or ""]
        full_text = "\n".join(text_parts)
        own_host = (urlparse(writeup.url).hostname or "").lower()
        exclude = {own_host} if own_host else set()
        if writeup.source.lower() == SANS_ISC_DIARY_SOURCE:
            # ISC diaries mix genuine indicators with citations and tool links.
            # Require local evidence for IPs and hashes. Plain linked URLs,
            # public resolvers, and CVEs in general news are not threat IOCs.
            lines = [refang(line) for line in full_text.splitlines()]
            candidates = extract_iocs_from_text(full_text, exclude_hostnames=exclude)
            extracted = [
                candidate for candidate in candidates
                if candidate.value not in SANS_ISC_PUBLIC_RESOLVERS
                if (
                    candidate.type in {"md5", "sha1", "sha256"}
                    and any(
                        candidate.value in line.lower()
                        and "hash" in " ".join(lines[max(0, index - 1) : index + 1]).lower()
                        for index, line in enumerate(lines)
                    )
                ) or (
                    candidate.type == "ipv4"
                    and any(
                        candidate.value in line
                        and (f"::ffff:{candidate.value}" in line or SANS_ISC_CONTEXT_RE.search(line))
                        for line in lines
                    )
                ) or (
                    candidate.type == "domain"
                    and any(
                        candidate.value in line.lower() and SANS_ISC_CONTEXT_RE.search(line)
                        for line in lines
                    )
                )
            ]
            # ISC sometimes publishes communication hosts as bare lines under
            # an explicit domain heading. Preserve the full host (including
            # subdomains); the generic extractor reduces it to the base domain.
            in_domain_list = False
            for line in lines:
                line = line.strip()
                if re.search(r"\bdomains?\b.*\b(?:communicated|traffic)\b|\btraffic to another domain\b", line, re.I):
                    in_domain_list = True
                    continue
                if not in_domain_list:
                    continue
                host = re.sub(r"^tcp://", "", line, flags=re.I).split(":", 1)[0].rstrip("/")
                if not SANS_ISC_HOST_RE.fullmatch(host):
                    in_domain_list = False
                    continue
                if host.lower() not in exclude and not any(item.type == "domain" and item.value == host.lower() for item in extracted):
                    extracted.append(ExtractedIOC(type="domain", value=host.lower()))
            extraction_mode = "sans_diary_atomic"
            max_items = int(self.settings.sources.writeup_search.max_iocs_per_article_fallback)
        else:
            # Prefer an explicit IOC/indicators section when the article has one, so
            # analyst-curated indicators earn full scoring context (parity with the
            # discovery path). Fall back to whole-body extraction otherwise.
            section = find_ioc_section(full_text)
            if section is not None:
                extracted = extract_iocs_from_section(section.text, exclude_hostnames=exclude)
                extraction_mode = "ioc_section"
                max_items = int(self.settings.sources.writeup_search.max_iocs_per_article_ioc_section)
            else:
                if writeup.source.lower() in SECTION_ONLY_WRITEUP_SOURCES:
                    return []
                extracted = extract_iocs_from_text(full_text, exclude_hostnames=exclude)
                extraction_mode = "fallback"
                max_items = int(self.settings.sources.writeup_search.max_iocs_per_article_fallback)
        if max_items > 0:
            extracted = extracted[:max_items]
        records: list[RawIOC] = []
        for candidate in extracted:
            records.append(
                RawIOC(
                    value=candidate.value,
                    type=candidate.type,
                    source=writeup.source,
                    source_trust=writeup.source_trust,
                    first_seen=writeup.published_at,
                    last_seen=writeup.published_at,
                    tags=list(writeup.tags),
                    description=writeup.title,
                    reference_url=writeup.url,
                    attributes={
                        "article_title": writeup.title,
                        "article_url": writeup.url,
                        "extraction": "regex-v1",
                        "extraction_mode": extraction_mode,
                        "ioc_section_label": candidate.section_label,
                    },
                    provenance="writeup",
                )
            )
        return records

    async def _process_writeups(
        self, adapter: WriteupAdapter
    ) -> tuple[list[RawWriteup], list[RawIOC], SourceScrapeDiagnostic]:
        timeout_seconds = float(self.settings.sources.http_timeout_seconds)
        writeups = await asyncio.wait_for(adapter.fetch_writeups(), timeout=timeout_seconds)
        blocked_urls, blocked_hosts = await self._load_feedback_suppressions()
        cutoff = self._writeup_cutoff()
        fresh = [writeup for writeup in writeups if writeup.published_at >= cutoff]
        stale = len(writeups) - len(fresh)
        matching = [writeup for writeup in fresh if self._matches_writeup_search(writeup)]
        filtered: list[RawWriteup] = []
        for writeup in matching:
            url = str(writeup.url or "").strip().lower()
            host = (httpx.URL(writeup.url).host or "").lower() if str(writeup.url or "").strip() else ""
            if url in blocked_urls or (host and host in blocked_hosts):
                continue
            filtered.append(writeup)
        limited = sorted(filtered, key=lambda writeup: writeup.published_at, reverse=True)[
            : self.settings.sources.writeup_search.max_candidates_per_source
        ]
        deadline = asyncio.get_running_loop().time() + max(
            1, int(self.settings.sources.writeup_search.fetch_budget_seconds)
        )
        processed: list[RawWriteup] = []
        for writeup in limited:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                writeup.fetch_error = "budget_exhausted"
                continue
            try:
                await asyncio.wait_for(self._fetch_article_body(writeup), timeout=min(timeout_seconds, remaining))
            except TimeoutError:
                writeup.fetch_error = "budget_exhausted"
            processed.append(writeup)
        extracted: list[RawIOC] = []
        for writeup in processed:
            extracted.extend(self._extract_iocs_from_writeup(writeup))
        diagnostic = SourceScrapeDiagnostic(
            source=adapter.source_name,
            pre_balance_kept=len(extracted),
            fetched=len(writeups),
            kept=len(extracted),
            stale_dropped=stale,
            writeups_fetched=len(processed),
            iocs_extracted=len(extracted),
        )
        return processed, extracted, diagnostic

    async def _load_feedback_suppressions(self) -> tuple[set[str], set[str]]:
        # Fail open: suppression memory is an optimization, and an unreadable
        # database (fresh install, missing table, outage) must never abort the
        # scrape itself.
        try:
            from sentinel.db.session import AsyncSessionFactory

            async with AsyncSessionFactory() as session:
                rows = (
                    await session.scalars(
                        select(DiscoveryMemory).where(DiscoveryMemory.kind.in_(["article_url", "publisher_host"]))
                    )
                ).all()
        except Exception as exc:
            self.logger.warning(
                "Feedback suppression memory unavailable; scraping without suppressions: %s",
                type(exc).__name__,
            )
            return set(), set()
        blocked_urls: set[str] = set()
        blocked_hosts: set[str] = set()
        for row in rows:
            if row.kind == "article_url":
                if row.false_positive >= max(1, int(self.settings.discovery.blocked_article_false_positive_threshold)) and row.false_positive > row.confirmed:
                    blocked_urls.add(row.key.lower())
            elif row.kind == "publisher_host":
                if (
                    row.false_positive >= max(1, int(self.settings.discovery.blocked_host_false_positive_threshold))
                    and row.false_positive > row.confirmed
                    and float(row.score) <= float(self.settings.discovery.blocked_host_max_score)
                ):
                    blocked_hosts.add(row.key.lower())
        return blocked_urls, blocked_hosts

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
        report = await self.run_with_diagnostics(*args, **kwargs)
        return report.items

    async def _fetch_adapter(self, adapter: SourceAdapter) -> list[RawIOC]:
        timeout_seconds = float(self.settings.sources.http_timeout_seconds)
        return await asyncio.wait_for(adapter.fetch(), timeout=timeout_seconds)

    def _rebalance_source_mix(
        self,
        items: list[RawIOC],
        diagnostics: list[SourceScrapeDiagnostic],
    ) -> list[RawIOC]:
        mix_settings = self.settings.sources.mix
        cap = int(mix_settings.max_items_per_source)
        if not mix_settings.enabled or cap <= 0 or not items:
            return items

        by_source: dict[str, list[RawIOC]] = {}
        for item in items:
            by_source.setdefault(item.source, []).append(item)

        for source_items in by_source.values():
            source_items.sort(
                key=lambda item: (
                    item.last_seen,
                    item.first_seen,
                    item.value,
                ),
                reverse=True,
            )

        diagnostic_by_source = {diagnostic.source: diagnostic for diagnostic in diagnostics}
        trimmed: dict[str, deque[RawIOC]] = {}
        source_order = sorted(
            by_source,
            key=lambda source: by_source[source][0].last_seen,
            reverse=True,
        )
        for source in source_order:
            source_items = by_source[source]
            kept_items = source_items[:cap]
            dropped = max(0, len(source_items) - len(kept_items))
            diagnostic = diagnostic_by_source.get(source)
            if diagnostic is not None:
                diagnostic.balance_dropped += dropped
                diagnostic.kept = len(kept_items)
            trimmed[source] = deque(kept_items)

        balanced: list[RawIOC] = []
        while True:
            advanced = False
            for source in source_order:
                queue = trimmed[source]
                if not queue:
                    continue
                balanced.append(queue.popleft())
                advanced = True
            if not advanced:
                break
        return balanced

    async def run_with_diagnostics(self, *args: Any, **kwargs: Any) -> ScrapeReport:
        self.reload_skill()
        ioc_adapters, writeup_adapters = self._build_adapters()
        results = await asyncio.gather(
            *(self._fetch_adapter(adapter) for adapter in ioc_adapters), return_exceptions=True
        )
        collected: list[RawIOC] = []
        diagnostics: list[SourceScrapeDiagnostic] = []
        for adapter, result in zip(ioc_adapters, results, strict=True):
            if isinstance(result, Exception):
                self.logger.exception("Scrape failed for source %s", adapter.source_name, exc_info=result)
                diagnostics.append(
                    SourceScrapeDiagnostic(
                        source=adapter.source_name,
                        error=f"{type(result).__name__}: {result}",
                    )
                )
                continue
            kept = 0
            stale = 0
            for item in result:
                if self._is_recent(item):
                    collected.append(self._decorate_item(item))
                    kept += 1
                else:
                    stale += 1
            self.logger.info(
                "Scraped %s indicators from %s; pre_balance_kept=%s stale_dropped=%s",
                len(result),
                adapter.source_name,
                kept,
                stale,
            )
            diagnostics.append(
                SourceScrapeDiagnostic(
                    source=adapter.source_name,
                    fetched=len(result),
                    pre_balance_kept=kept,
                    kept=kept,
                    stale_dropped=stale,
                )
            )

        all_writeups: list[RawWriteup] = []
        writeup_results = await asyncio.gather(
            *(self._process_writeups(adapter) for adapter in writeup_adapters), return_exceptions=True
        )
        for adapter, result in zip(writeup_adapters, writeup_results, strict=True):
            if isinstance(result, Exception):
                self.logger.exception("Writeup scrape failed for source %s", adapter.source_name, exc_info=result)
                diagnostics.append(
                    SourceScrapeDiagnostic(
                        source=adapter.source_name,
                        error=f"{type(result).__name__}: {result}",
                    )
                )
                continue
            writeups, extracted, diagnostic = result
            all_writeups.extend(writeups)
            collected.extend(self._decorate_item(item) for item in extracted)
            self.logger.info(
                "Processed %s fresh writeup(s) from %s; extracted %s IOC(s)",
                diagnostic.writeups_fetched,
                adapter.source_name,
                diagnostic.iocs_extracted,
            )
            diagnostics.append(diagnostic)

        collected = self._rebalance_source_mix(collected, diagnostics)
        for diagnostic in diagnostics:
            if diagnostic.balance_dropped > 0:
                self.logger.info(
                    "Balanced source mix for %s; pre_balance_kept=%s final_kept=%s balance_dropped=%s",
                    diagnostic.source,
                    diagnostic.pre_balance_kept,
                    diagnostic.kept,
                    diagnostic.balance_dropped,
                )
        await self.publish_to_queue(collected)
        return ScrapeReport(items=collected, diagnostics=diagnostics, writeups=all_writeups)

    async def aclose(self) -> None:
        if self._owns_http_client:
            try:
                await asyncio.wait_for(self.http_client.aclose(), timeout=5.0)
            except TimeoutError:
                self.logger.warning("Timed out while closing scraper HTTP client; continuing shutdown.")
        if self._owns_redis and self.redis is not None:
            try:
                await asyncio.wait_for(self.redis.aclose(), timeout=5.0)
            except TimeoutError:
                self.logger.warning("Timed out while closing scraper Redis client; continuing shutdown.")

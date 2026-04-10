from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.agents.base import BaseAgent
from sentinel.agents.scraper import RawIOC
from sentinel.db.models import IOC


PATTERN_LINE = re.compile(r"^- pattern:\s*(.+?)\s*$", re.IGNORECASE)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
ANY_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
LOCAL_HOSTS = {"localhost", "localhost.localdomain"}


@dataclass(slots=True)
class ValidatedIOC:
    value: str
    normalized_value: str
    dedupe_hash: str
    type: str
    source: str
    source_trust: float
    first_seen: datetime
    last_seen: datetime
    source_title: str | None
    reference_url: str | None
    related_cves: list[str]
    attributes: dict[str, Any]


class ValidationAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/validation/SKILL.md",
        *,
        tranco_path: str = "data/tranco_top10k.txt",
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.tranco_path = Path(tranco_path)
        if session_factory is None:
            from sentinel.db.session import AsyncSessionFactory

            self.session_factory = AsyncSessionFactory
        else:
            self.session_factory = session_factory
        self._tranco_cache: set[str] | None = None

    def _load_tranco_allowlist(self) -> set[str]:
        if self._tranco_cache is None:
            if not self.tranco_path.exists():
                self._tranco_cache = set()
            else:
                self._tranco_cache = {
                    line.strip().lower()
                    for line in self.tranco_path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")
                }
        return self._tranco_cache

    def _load_fp_patterns(self) -> list[str]:
        patterns: list[str] = []
        for line in self.skill_prompt.splitlines():
            match = PATTERN_LINE.match(line.strip())
            if match:
                patterns.append(match.group(1).lower())
        return patterns

    def _coerce_timestamp(self, value: datetime | str | None) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            try:
                if value.endswith("Z"):
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                parsed = datetime.fromisoformat(value)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                pass
        return datetime.now(UTC)

    def _normalize_ipv4(self, value: str) -> str | None:
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            return None
        if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
            return None
        # Assumption: documentation-only test networks are always rejected as false positives.
        if address in ipaddress.IPv4Network("192.0.2.0/24") or address in ipaddress.IPv4Network("198.51.100.0/24") or address in ipaddress.IPv4Network("203.0.113.0/24"):
            return None
        return str(address)

    def _normalize_ipv6(self, value: str) -> str | None:
        try:
            address = ipaddress.IPv6Address(value)
        except ipaddress.AddressValueError:
            return None
        if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
            return None
        if address in ipaddress.IPv6Network("2001:db8::/32"):
            return None
        return address.compressed

    def _normalize_domain(self, value: str) -> str | None:
        candidate = value.strip().rstrip(".").lower()
        if candidate in LOCAL_HOSTS or not DOMAIN_RE.fullmatch(candidate):
            return None
        if candidate in self._load_tranco_allowlist():
            return None
        return candidate

    def _normalize_url(self, value: str) -> str | None:
        parsed = urlparse(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None
        host = parsed.hostname or ""
        normalized_host = self._normalize_domain(host)
        if normalized_host is None:
            ipv4 = self._normalize_ipv4(host)
            ipv6 = self._normalize_ipv6(host)
            normalized_host = ipv4 or ipv6
        if normalized_host is None:
            return None
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        return f"{parsed.scheme.lower()}://{normalized_host}{port}{path}{query}{fragment}"

    def _normalize_hash(self, value: str, expected_length: int) -> str | None:
        candidate = value.strip().lower()
        return candidate if re.fullmatch(rf"[a-f0-9]{{{expected_length}}}", candidate) else None

    def _normalize_cve(self, value: str) -> str | None:
        candidate = value.strip().upper()
        return candidate if CVE_RE.fullmatch(candidate) else None

    def normalize_ioc(self, ioc_type: str, value: str) -> str | None:
        normalized_type = ioc_type.lower()
        if normalized_type == "ipv4":
            return self._normalize_ipv4(value)
        if normalized_type == "ipv6":
            return self._normalize_ipv6(value)
        if normalized_type == "domain":
            return self._normalize_domain(value)
        if normalized_type == "url":
            return self._normalize_url(value)
        if normalized_type == "md5":
            return self._normalize_hash(value, 32)
        if normalized_type == "sha1":
            return self._normalize_hash(value, 40)
        if normalized_type == "sha256":
            return self._normalize_hash(value, 64)
        if normalized_type == "cve":
            return self._normalize_cve(value)
        return None

    def _matches_fp_pattern(self, normalized_value: str) -> bool:
        value = normalized_value.lower()
        return any(pattern in value for pattern in self._load_fp_patterns())

    def _coerce_raw_ioc(self, item: RawIOC | dict[str, Any]) -> RawIOC:
        if isinstance(item, RawIOC):
            return item
        return RawIOC(
            value=item["value"],
            type=item["type"],
            source=item["source"],
            source_trust=float(item["source_trust"]),
            first_seen=self._coerce_timestamp(item.get("first_seen")),
            last_seen=self._coerce_timestamp(item.get("last_seen")),
            tags=list(item.get("tags", [])),
            description=item.get("description"),
            reference_url=item.get("reference_url"),
            attributes=dict(item.get("attributes", {})),
        )

    def _validate_item(self, item: RawIOC) -> ValidatedIOC | None:
        normalized_value = self.normalize_ioc(item.type, item.value)
        if normalized_value is None or self._matches_fp_pattern(normalized_value):
            return None
        dedupe_hash = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
        related_cves = sorted(
            {
                match.group(0).upper()
                for match in ANY_CVE_RE.finditer(
                    "\n".join(
                        [
                            item.value,
                            item.description or "",
                            item.reference_url or "",
                            " ".join(item.tags),
                            " ".join(str(value) for value in item.attributes.values() if isinstance(value, str)),
                        ]
                    )
                )
            }
        )
        if "related_cves" in item.attributes and isinstance(item.attributes["related_cves"], list):
            related_cves = sorted({*related_cves, *(str(value).upper() for value in item.attributes["related_cves"])})
        return ValidatedIOC(
            value=normalized_value,
            normalized_value=normalized_value,
            dedupe_hash=dedupe_hash,
            type=item.type.lower(),
            source=item.source,
            source_trust=item.source_trust,
            first_seen=self._coerce_timestamp(item.first_seen),
            last_seen=self._coerce_timestamp(item.last_seen),
            source_title=item.description,
            reference_url=item.reference_url,
            related_cves=related_cves,
            attributes={
                "tags": item.tags,
                "description": item.description,
                "reference_url": item.reference_url,
                **item.attributes,
            },
        )

    @asynccontextmanager
    async def _session_scope(self):
        async with self.session_factory() as session:
            yield session

    async def _persist_validated(self, session: AsyncSession, validated: Iterable[ValidatedIOC]) -> list[IOC]:
        persisted: list[IOC] = []
        for item in validated:
            existing = await session.scalar(select(IOC).where(IOC.dedupe_hash == item.dedupe_hash))
            if existing is not None:
                continue
            record = IOC(
                value=item.normalized_value,
                dedupe_hash=item.dedupe_hash,
                type=item.type,
                source=item.source,
                source_trust=item.source_trust,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                source_title=item.source_title,
                reference_url=item.reference_url,
                related_cves=item.related_cves,
            )
            session.add(record)
            persisted.append(record)
        await session.commit()
        for record in persisted:
            await session.refresh(record)
        return persisted

    async def run(self, raw_iocs: Iterable[RawIOC | dict[str, Any]], *args: Any, **kwargs: Any) -> list[IOC]:
        self.reload_skill()
        candidate_items = [self._coerce_raw_ioc(item) for item in raw_iocs]
        seen_hashes: set[str] = set()
        validated: list[ValidatedIOC] = []
        for item in candidate_items:
            result = self._validate_item(item)
            if result is None or result.dedupe_hash in seen_hashes:
                continue
            seen_hashes.add(result.dedupe_hash)
            validated.append(result)
        async with self._session_scope() as session:
            return await self._persist_validated(session, validated)

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
from sentinel.db.models import IOC, IOCSighting, SourceMaterial


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
    provenance: str = "feed"


@dataclass(slots=True)
class ValidationReport:
    """Canonical rows persisted this run, plus lineage bookkeeping."""

    new_iocs: list[IOC]
    corroborated_iocs: list[IOC]
    sightings_recorded: int

    @property
    def all_iocs(self) -> list[IOC]:
        return [*self.new_iocs, *self.corroborated_iocs]


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
        raw_host = host.strip().rstrip(".").lower()
        normalized_host = None
        if raw_host not in LOCAL_HOSTS and DOMAIN_RE.fullmatch(raw_host):
            normalized_host = raw_host
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
        if normalized_host in self._load_tranco_allowlist() and path == "/" and not query and not fragment:
            return None
        if normalized_host == "github.com" and path == "/" and not query and not fragment:
            return None
        if normalized_host.endswith(".github.io") and path == "/" and not query and not fragment:
            return None
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
            provenance=str(item.get("provenance", "feed")),
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
            provenance=item.provenance,
        )

    @asynccontextmanager
    async def _session_scope(self):
        async with self.session_factory() as session:
            yield session

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        # sqlite round-trips timezone-aware datetimes as naive; treat naive as UTC.
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    async def _record_sighting(
        self,
        session: AsyncSession,
        *,
        ioc_row: IOC,
        item: ValidatedIOC,
        source_material_ids: dict[str, Any] | None,
    ) -> bool:
        lineage_hash = IOCSighting.build_lineage_hash(
            ioc_id=ioc_row.id,
            source=item.source,
            provenance=item.provenance,
            reference_url=item.reference_url,
        )
        existing = await session.scalar(select(IOCSighting).where(IOCSighting.lineage_hash == lineage_hash))
        if existing is not None:
            existing.last_seen = max(self._as_utc(existing.last_seen), item.last_seen)
            existing.sighting_count += 1
            return False
        material_id = None
        if source_material_ids and item.reference_url:
            material_id = source_material_ids.get(item.reference_url)
        sighting_attributes: dict[str, Any] = {"tags": item.attributes.get("tags", [])}
        # Discovery attribution rides along so analyst feedback can be credited
        # back to the search profile / extraction mode that produced the alert.
        from sentinel.agents.discovery import ATTRIBUTION_KEYS

        for key in ATTRIBUTION_KEYS:
            if key in item.attributes:
                sighting_attributes[key] = item.attributes[key]
        session.add(
            IOCSighting(
                ioc_id=ioc_row.id,
                source=item.source,
                source_trust=item.source_trust,
                provenance=item.provenance,
                reference_url=item.reference_url,
                source_material_id=material_id,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                sighting_count=1,
                lineage_hash=lineage_hash,
                attributes=sighting_attributes,
            )
        )
        return True

    async def _persist_validated(
        self,
        session: AsyncSession,
        validated: Iterable[ValidatedIOC],
        *,
        source_material_ids: dict[str, Any] | None = None,
    ) -> ValidationReport:
        new_rows: list[IOC] = []
        corroborated: list[IOC] = []
        sightings = 0
        batch_rows: dict[str, IOC] = {}
        for item in validated:
            row = batch_rows.get(item.dedupe_hash)
            if row is None:
                row = await session.scalar(select(IOC).where(IOC.dedupe_hash == item.dedupe_hash))
            if row is not None and str(row.analyst_verdict or "").strip().lower() == "false_positive":
                continue
            if row is None:
                row = IOC(
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
                session.add(row)
                await session.flush()
                new_rows.append(row)
            else:
                row.first_seen = min(self._as_utc(row.first_seen), item.first_seen)
                row.last_seen = max(self._as_utc(row.last_seen), item.last_seen)
                merged_cves = sorted({*(row.related_cves or []), *item.related_cves})
                if merged_cves != (row.related_cves or []):
                    row.related_cves = merged_cves
                if row not in new_rows and row not in corroborated:
                    corroborated.append(row)
            batch_rows[item.dedupe_hash] = row
            if await self._record_sighting(
                session, ioc_row=row, item=item, source_material_ids=source_material_ids
            ):
                sightings += 1
        await session.commit()
        for record in new_rows:
            await session.refresh(record)
        return ValidationReport(
            new_iocs=new_rows,
            corroborated_iocs=corroborated,
            sightings_recorded=sightings,
        )

    async def run_with_report(
        self,
        raw_iocs: Iterable[RawIOC | dict[str, Any]],
        *,
        source_material_ids: dict[str, Any] | None = None,
    ) -> ValidationReport:
        self.reload_skill()
        candidate_items = [self._coerce_raw_ioc(item) for item in raw_iocs]
        validated: list[ValidatedIOC] = []
        for item in candidate_items:
            result = self._validate_item(item)
            if result is None:
                continue
            validated.append(result)
        async with self._session_scope() as session:
            return await self._persist_validated(
                session, validated, source_material_ids=source_material_ids
            )

    async def run(self, raw_iocs: Iterable[RawIOC | dict[str, Any]], *args: Any, **kwargs: Any) -> list[IOC]:
        report = await self.run_with_report(
            raw_iocs, source_material_ids=kwargs.get("source_material_ids")
        )
        return report.new_iocs


async def get_corroboration(session: AsyncSession, ioc_ids: Iterable[Any]) -> dict[Any, int]:
    """Distinct observing sources per IOC id, from the sightings table."""
    from sqlalchemy import func

    ids = list(ioc_ids)
    if not ids:
        return {}
    rows = await session.execute(
        select(IOCSighting.ioc_id, func.count(func.distinct(IOCSighting.source)))
        .where(IOCSighting.ioc_id.in_(ids))
        .group_by(IOCSighting.ioc_id)
    )
    return {ioc_id: count for ioc_id, count in rows.all()}


# Provenance strength ranking for choosing the best context per IOC. An IOC
# hand-listed in a writeup IOC section outranks a whole-body writeup extraction,
# which outranks a plain feed sighting.
_PROVENANCE_RANK = {"feed": 0, "manual": 1, "discovery": 2, "writeup": 2}


async def get_scoring_context(session: AsyncSession, ioc_ids: Iterable[Any]) -> dict[Any, dict[str, Any]]:
    """Per-IOC scoring context aggregated from sightings.

    Returns {ioc_id: {"provenance", "extraction_mode", "corroboration_sources"}}
    where provenance/extraction_mode reflect the strongest sighting (curated
    IOC-section beats fallback beats plain feed) and corroboration_sources is
    the count of distinct observing sources.
    """
    ids = list(ioc_ids)
    if not ids:
        return {}
    rows = await session.execute(
        select(
            IOCSighting.ioc_id,
            IOCSighting.source,
            IOCSighting.provenance,
            IOCSighting.attributes,
            SourceMaterial.extracted_ioc_count,
        )
        .outerjoin(SourceMaterial, IOCSighting.source_material_id == SourceMaterial.id)
        .where(IOCSighting.ioc_id.in_(ids))
    )
    context: dict[Any, dict[str, Any]] = {}
    distinct_sources: dict[Any, set[str]] = {}
    for ioc_id, source, provenance, attributes, extracted_ioc_count in rows.all():
        distinct_sources.setdefault(ioc_id, set()).add(source)
        extraction_mode = (attributes or {}).get("extraction_mode")
        # Curated IOC-section extractions get promoted to the strongest rank.
        rank = _PROVENANCE_RANK.get(provenance or "feed", 0)
        if extraction_mode == "ioc_section":
            rank = max(rank, 3)
        current = context.get(ioc_id)
        if current is None or rank > current["_rank"]:
            context[ioc_id] = {
                "provenance": provenance,
                "extraction_mode": extraction_mode,
                "_rank": rank,
                "article_ioc_count": int(extracted_ioc_count or 0),
            }
        elif current is not None and int(extracted_ioc_count or 0) > int(current.get("article_ioc_count") or 0):
            current["article_ioc_count"] = int(extracted_ioc_count or 0)
    for ioc_id, entry in context.items():
        entry.pop("_rank", None)
        entry["corroboration_sources"] = len(distinct_sources.get(ioc_id, {""}))
    return context

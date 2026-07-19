from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.config import SentinelSettings, get_settings
from sentinel.db.models import IOC
from sentinel.integrations.abuseipdb import AbuseIPDBClient
from sentinel.integrations.shodan import ShodanClient
from sentinel.integrations.virustotal import VirusTotalClient
from sentinel.integrations.whois import WhoisClient


WEIGHTS_SECTION = re.compile(r"## Scoring Weights\s+(.*?)(?:\n## |\Z)", re.DOTALL)
WEIGHT_LINE = re.compile(r"^- ([a-zA-Z0-9_:-]+):\s*([0-9]*\.?[0-9]+)\s*$")

# Provenance/curation values that carry evidential weight. An indicator hand-
# listed in a writeup's IOC section is treated as strong evidence; a whole-body
# extraction from a writeup/discovery page is weaker; a direct feed carries no
# context evidence on its own (its evidence must come from VT/AbuseIPDB).
CONTEXT_CURATED = 1.0
CONTEXT_WRITEUP = 0.6
CONTEXT_FEED = 0.0


logger = logging.getLogger(__name__)


def context_evidence_score(provenance: str | None, extraction_mode: str | None) -> float:
    if extraction_mode == "ioc_section":
        return CONTEXT_CURATED
    if provenance in {"writeup", "discovery"}:
        return CONTEXT_WRITEUP
    return CONTEXT_FEED


def corroboration_component(distinct_sources: int | None) -> float:
    """0.0 for a single source, 0.5 for two, 1.0 for three or more."""
    sources = distinct_sources or 1
    return max(0.0, min(1.0, (sources - 1) / 2.0))


@dataclass(slots=True)
class EnrichedIOC:
    value: str
    type: str
    source: str
    source_trust: float
    first_seen: datetime
    last_seen: datetime
    risk_score: float
    source_title: str | None = None
    reference_url: str | None = None
    related_cves: list[str] = field(default_factory=list)
    vt_detections: int | None = None
    vt_ratio: float | None = None
    shodan_ports: list[int] = field(default_factory=list)
    abuse_confidence: int | None = None
    whois: dict[str, Any] = field(default_factory=dict)
    enrichment_text: str = ""
    provider_results: dict[str, Any] = field(default_factory=dict)
    provider_errors: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    context_score: float = 0.0
    corroboration_sources: int = 1


class EnrichmentAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/enrichment/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        virustotal_client: VirusTotalClient | None = None,
        shodan_client: ShodanClient | None = None,
        abuseipdb_client: AbuseIPDBClient | None = None,
        whois_client: WhoisClient | None = None,
        semaphore_limits: dict[str, int] | None = None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        self.virustotal_client = virustotal_client or VirusTotalClient(self.settings.enrichment.virustotal_key)
        self.shodan_client = shodan_client or ShodanClient(self.settings.enrichment.shodan_key)
        self.abuseipdb_client = abuseipdb_client or AbuseIPDBClient(self.settings.enrichment.abuseipdb_key)
        self.whois_client = (whois_client or WhoisClient()) if self.settings.enrichment.enable_whois else None
        limits = semaphore_limits or {"virustotal": 4, "shodan": 4, "abuseipdb": 8, "whois": 8}
        self.semaphores = {name: asyncio.Semaphore(limit) for name, limit in limits.items()}
        self._owns_abuse_client = abuseipdb_client is None
        self.provider_timeout_seconds = float(self.settings.enrichment.provider_timeout_seconds)

    def get_scoring_weights(self) -> dict[str, float]:
        section_match = WEIGHTS_SECTION.search(self.skill_prompt)
        if not section_match:
            return self.settings.enrichment.weights.model_dump()
        weights: dict[str, float] = {}
        for raw_line in section_match.group(1).splitlines():
            match = WEIGHT_LINE.match(raw_line.strip())
            if match:
                weights[match.group(1)] = float(match.group(2))
        default_weights = self.settings.enrichment.weights.model_dump()
        default_weights.update(weights)
        return default_weights

    def _coerce_datetime(self, value: datetime | str | None) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            try:
                if value.endswith("Z"):
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                parsed = datetime.fromisoformat(value)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                return datetime.now(UTC)
        return datetime.now(UTC)

    def _coerce_ioc(self, item: IOC | dict[str, Any]) -> dict[str, Any]:
        if isinstance(item, IOC):
            return {
                "value": item.value,
                "type": item.type,
                "source": item.source,
                "source_trust": item.source_trust,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
                "source_title": item.source_title,
                "reference_url": item.reference_url,
                "related_cves": list(item.related_cves or []),
                "attributes": {},
            }
        return {
            "value": item["value"],
            "type": item["type"],
            "source": item["source"],
            "source_trust": float(item["source_trust"]),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "source_title": item.get("source_title"),
            "reference_url": item.get("reference_url"),
            "related_cves": list(item.get("related_cves", [])),
            "attributes": dict(item.get("attributes", {})),
        }

    async def _bounded(self, semaphore_name: str, coro) -> Any:
        async with self.semaphores[semaphore_name]:
            return await asyncio.wait_for(coro, timeout=self.provider_timeout_seconds)

    async def _fetch_virustotal(self, ioc: dict[str, Any]) -> dict[str, Any]:
        return await self._bounded("virustotal", self.virustotal_client.lookup_ioc(ioc["type"], ioc["value"]))

    async def _fetch_shodan(self, ioc: dict[str, Any]) -> dict[str, Any] | None:
        if ioc["type"] not in {"ipv4", "ipv6"}:
            return None
        return await self._bounded("shodan", self.shodan_client.lookup_host(ioc["value"]))

    async def _fetch_abuseipdb(self, ioc: dict[str, Any]) -> dict[str, Any] | None:
        if ioc["type"] not in {"ipv4", "ipv6"}:
            return None
        return await self._bounded("abuseipdb", self.abuseipdb_client.lookup_ip(ioc["value"]))

    async def _fetch_whois(self, ioc: dict[str, Any]) -> dict[str, Any] | None:
        if self.whois_client is None:
            return None
        if ioc["type"] not in {"domain", "url", "ipv4", "ipv6"}:
            return None
        lookup_value = ioc["value"]
        if ioc["type"] == "url":
            from urllib.parse import urlparse

            lookup_value = urlparse(ioc["value"]).hostname or ioc["value"]
        return await self._bounded("whois", self.whois_client.lookup(lookup_value))

    def _extract_vt_metrics(self, vt_result: dict[str, Any] | None) -> tuple[int | None, float]:
        if not vt_result:
            return None, 0.0
        stats = (
            vt_result.get("last_analysis_stats")
            or vt_result.get("attributes", {}).get("last_analysis_stats")
            or {}
        )
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected
        ratio = (malicious + suspicious) / total if total else 0.0
        return malicious + suspicious, ratio

    def _extract_ports(self, shodan_result: dict[str, Any] | None) -> list[int]:
        if not shodan_result:
            return []
        ports = shodan_result.get("ports") or []
        return [int(port) for port in ports if isinstance(port, (int, float, str)) and str(port).isdigit()]

    def _extract_abuse_confidence(self, abuse_result: dict[str, Any] | None) -> int | None:
        if not abuse_result:
            return None
        data = abuse_result.get("data", abuse_result)
        confidence = data.get("abuseConfidenceScore")
        if confidence is None:
            return None
        return int(confidence)

    def _compute_recency_score(self, first_seen: datetime, last_seen: datetime) -> float:
        reference = max(first_seen, last_seen)
        age_seconds = max((datetime.now(UTC) - reference).total_seconds(), 0.0)
        days = age_seconds / 86400
        return max(0.0, min(1.0, 1 - (days / 30)))

    def _build_enrichment_text(
        self,
        *,
        vt_result: dict[str, Any] | None,
        shodan_result: dict[str, Any] | None,
        abuse_result: dict[str, Any] | None,
        whois_result: dict[str, Any] | None,
    ) -> str:
        parts: list[str] = []
        if vt_result:
            parts.append(str(vt_result.get("attributes", vt_result)))
        if shodan_result:
            parts.append(str(shodan_result))
        if abuse_result:
            parts.append(str(abuse_result.get("data", abuse_result)))
        if whois_result:
            parts.append(str(whois_result))
        return "\n".join(parts)

    def score_components(
        self,
        *,
        weights: dict[str, float],
        vt_ratio: float,
        abuse_confidence: int | None,
        source_trust: float,
        recency_score: float,
        context_score: float = 0.0,
        corroboration: float = 0.0,
    ) -> dict[str, float]:
        """Per-component contribution to the risk score, in score points.

        Summing the values (and clamping to [0, 100]) yields the risk score;
        keeping the parts makes every score explainable to an analyst.
        """
        abuse_score = (abuse_confidence or 0) / 100
        return {
            "vt_ratio": round(weights.get("vt_ratio", 0.0) * vt_ratio * 100, 2),
            "abuse_confidence": round(weights.get("abuse_confidence", 0.0) * abuse_score * 100, 2),
            "source_trust": round(weights.get("source_trust", 0.0) * source_trust * 100, 2),
            "recency": round(weights.get("recency", 0.0) * recency_score * 100, 2),
            "context": round(weights.get("context", 0.0) * context_score * 100, 2),
            "corroboration": round(weights.get("corroboration", 0.0) * corroboration * 100, 2),
        }

    def _score_ioc(
        self,
        *,
        weights: dict[str, float],
        vt_ratio: float,
        abuse_confidence: int | None,
        source_trust: float,
        recency_score: float,
        context_score: float = 0.0,
        corroboration: float = 0.0,
    ) -> float:
        components = self.score_components(
            weights=weights,
            vt_ratio=vt_ratio,
            abuse_confidence=abuse_confidence,
            source_trust=source_trust,
            recency_score=recency_score,
            context_score=context_score,
            corroboration=corroboration,
        )
        return round(max(0.0, min(100.0, sum(components.values()))), 2)

    @staticmethod
    def _context_from(context: dict[str, Any] | None) -> tuple[float, int]:
        """(context_evidence, distinct_sources) from a per-IOC context dict."""
        if not context:
            return 0.0, 1
        context_score = context_evidence_score(
            context.get("provenance"), context.get("extraction_mode")
        )
        sources = int(context.get("corroboration_sources") or 1)
        return context_score, sources

    @staticmethod
    def _chunked(items: list[IOC | dict[str, Any]], batch_size: int) -> Iterable[list[IOC | dict[str, Any]]]:
        for start in range(0, len(items), batch_size):
            yield items[start : start + batch_size]

    async def _gather_provider_results(self, tasks: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        task_map = {name: asyncio.create_task(task) for name, task in tasks.items()}
        provider_results: dict[str, Any] = {}
        provider_errors: dict[str, str] = {}
        try:
            results = await asyncio.gather(*task_map.values(), return_exceptions=True)
        except asyncio.CancelledError:
            for task in task_map.values():
                task.cancel()
            await asyncio.gather(*task_map.values(), return_exceptions=True)
            raise
        for name, result in zip(task_map.keys(), results, strict=True):
            if isinstance(result, Exception):
                provider_errors[name] = str(result)
            else:
                provider_results[name] = result
        return provider_results, provider_errors

    async def _run_batch(
        self,
        batch: list[IOC | dict[str, Any]],
        *,
        weights: dict[str, float],
        context_by_value: dict[str, dict[str, Any]],
    ) -> list[EnrichedIOC]:
        def context_for(ioc: IOC | dict[str, Any]) -> dict[str, Any] | None:
            value = ioc.value if isinstance(ioc, IOC) else ioc.get("value")
            return context_by_value.get(value)

        tasks = [
            asyncio.create_task(self.enrich_one(ioc, weights=weights, context=context_for(ioc)))
            for ioc in batch
        ]
        try:
            return await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def enrich_one(
        self,
        item: IOC | dict[str, Any],
        *,
        weights: dict[str, float],
        context: dict[str, Any] | None = None,
    ) -> EnrichedIOC:
        ioc = self._coerce_ioc(item)
        context_score, corroboration_sources = self._context_from(context)
        first_seen = self._coerce_datetime(ioc["first_seen"])
        last_seen = self._coerce_datetime(ioc["last_seen"])
        tasks = {
            "virustotal": self._fetch_virustotal(ioc),
            "shodan": self._fetch_shodan(ioc),
            "abuseipdb": self._fetch_abuseipdb(ioc),
            "whois": self._fetch_whois(ioc),
        }
        provider_results, provider_errors = await self._gather_provider_results(tasks)

        vt_detections, vt_ratio = self._extract_vt_metrics(provider_results.get("virustotal"))
        abuse_confidence = self._extract_abuse_confidence(provider_results.get("abuseipdb"))
        score_breakdown = self.score_components(
            weights=weights,
            vt_ratio=vt_ratio,
            abuse_confidence=abuse_confidence,
            source_trust=float(ioc["source_trust"]),
            recency_score=self._compute_recency_score(first_seen, last_seen),
            context_score=context_score,
            corroboration=corroboration_component(corroboration_sources),
        )
        risk_score = round(max(0.0, min(100.0, sum(score_breakdown.values()))), 2)
        attributes = dict(ioc.get("attributes", {}))
        attributes["score_breakdown"] = score_breakdown
        return EnrichedIOC(
            value=ioc["value"],
            type=ioc["type"],
            source=ioc["source"],
            source_trust=float(ioc["source_trust"]),
            first_seen=first_seen,
            last_seen=last_seen,
            risk_score=risk_score,
            source_title=ioc.get("source_title"),
            reference_url=ioc.get("reference_url"),
            related_cves=list(ioc.get("related_cves", [])),
            vt_detections=vt_detections,
            vt_ratio=vt_ratio if provider_results.get("virustotal") is not None else None,
            shodan_ports=self._extract_ports(provider_results.get("shodan")),
            abuse_confidence=abuse_confidence,
            whois=provider_results.get("whois") or {},
            enrichment_text=self._build_enrichment_text(
                vt_result=provider_results.get("virustotal"),
                shodan_result=provider_results.get("shodan"),
                abuse_result=provider_results.get("abuseipdb"),
                whois_result=provider_results.get("whois"),
            ),
            provider_results=provider_results,
            provider_errors=provider_errors,
            attributes=attributes,
            context_score=context_score,
            corroboration_sources=corroboration_sources,
        )

    def rescore_from_stored(
        self,
        *,
        weights: dict[str, float],
        vt_ratio: float | None,
        abuse_confidence: int | None,
        source_trust: float,
        first_seen: datetime,
        last_seen: datetime,
        context: dict[str, Any] | None = None,
    ) -> float:
        """Recompute a risk score from already-stored evidence, no API calls.

        Used to re-level existing rows under the current weights/context without
        re-hitting VirusTotal/AbuseIPDB (and without burning their quota).
        """
        components = self.breakdown_from_stored(
            weights=weights,
            vt_ratio=vt_ratio,
            abuse_confidence=abuse_confidence,
            source_trust=source_trust,
            first_seen=first_seen,
            last_seen=last_seen,
            context=context,
        )
        return round(max(0.0, min(100.0, sum(components.values()))), 2)

    def breakdown_from_stored(
        self,
        *,
        weights: dict[str, float],
        vt_ratio: float | None,
        abuse_confidence: int | None,
        source_trust: float,
        first_seen: datetime,
        last_seen: datetime,
        context: dict[str, Any] | None = None,
    ) -> dict[str, float]:
        """Per-component score contributions from already-stored evidence."""
        context_score, corroboration_sources = self._context_from(context)
        return self.score_components(
            weights=weights,
            vt_ratio=vt_ratio or 0.0,
            abuse_confidence=abuse_confidence,
            source_trust=source_trust,
            recency_score=self._compute_recency_score(
                self._coerce_datetime(first_seen), self._coerce_datetime(last_seen)
            ),
            context_score=context_score,
            corroboration=corroboration_component(corroboration_sources),
        )

    async def run(
        self,
        validated_iocs: list[IOC | dict[str, Any]],
        *args: Any,
        context_by_value: dict[str, dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> list[EnrichedIOC]:
        self.reload_skill()
        weights = self.get_scoring_weights()
        context_by_value = context_by_value or {}
        started = time.perf_counter()
        max_iocs = max(1, int(self.settings.enrichment.max_iocs_per_run))
        batch_size = max(1, int(self.settings.enrichment.batch_size))
        selected_iocs = list(validated_iocs[:max_iocs])
        skipped = max(0, len(validated_iocs) - len(selected_iocs))
        if skipped:
            self.logger.warning(
                "Enrichment budget capped this run at %s IOC(s); skipped=%s",
                len(selected_iocs),
                skipped,
            )
        enriched: list[EnrichedIOC] = []
        try:
            for batch_number, batch in enumerate(self._chunked(selected_iocs, batch_size), start=1):
                batch_started = time.perf_counter()
                enriched.extend(
                    await self._run_batch(
                        batch,
                        weights=weights,
                        context_by_value=context_by_value,
                    )
                )
                self.logger.info(
                    "Enrichment batch %s completed for %s IOC(s) in %.2fs",
                    batch_number,
                    len(batch),
                    time.perf_counter() - batch_started,
                )
        except asyncio.CancelledError:
            self.logger.warning(
                "Enrichment cancelled after %.2fs; completed=%s IOC(s)",
                time.perf_counter() - started,
                len(enriched),
            )
            raise
        elapsed = time.perf_counter() - started
        self.logger.info(
            "Enrichment completed for %s/%s IOC(s) in %.2fs (whois=%s skipped=%s batch_size=%s)",
            len(enriched),
            len(validated_iocs),
            elapsed,
            "enabled" if self.whois_client is not None else "disabled",
            skipped,
            batch_size,
        )
        return enriched

    async def aclose(self) -> None:
        if self._owns_abuse_client:
            await self.abuseipdb_client.aclose()

from __future__ import annotations

import asyncio
import re
import time
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
        }

    async def _bounded(self, semaphore_name: str, coro) -> Any:
        async with self.semaphores[semaphore_name]:
            return await coro

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

    def _score_ioc(
        self,
        *,
        weights: dict[str, float],
        vt_ratio: float,
        abuse_confidence: int | None,
        source_trust: float,
        recency_score: float,
    ) -> float:
        abuse_score = (abuse_confidence or 0) / 100
        raw_score = (
            weights.get("vt_ratio", 0.0) * vt_ratio
            + weights.get("abuse_confidence", 0.0) * abuse_score
            + weights.get("source_trust", 0.0) * source_trust
            + weights.get("recency", 0.0) * recency_score
        )
        return round(max(0.0, min(100.0, raw_score * 100)), 2)

    async def enrich_one(self, item: IOC | dict[str, Any], *, weights: dict[str, float]) -> EnrichedIOC:
        ioc = self._coerce_ioc(item)
        first_seen = self._coerce_datetime(ioc["first_seen"])
        last_seen = self._coerce_datetime(ioc["last_seen"])
        tasks = {
            "virustotal": self._fetch_virustotal(ioc),
            "shodan": self._fetch_shodan(ioc),
            "abuseipdb": self._fetch_abuseipdb(ioc),
            "whois": self._fetch_whois(ioc),
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        provider_results: dict[str, Any] = {}
        provider_errors: dict[str, str] = {}
        for name, result in zip(tasks.keys(), results, strict=True):
            if isinstance(result, Exception):
                provider_errors[name] = str(result)
            else:
                provider_results[name] = result

        vt_detections, vt_ratio = self._extract_vt_metrics(provider_results.get("virustotal"))
        abuse_confidence = self._extract_abuse_confidence(provider_results.get("abuseipdb"))
        risk_score = self._score_ioc(
            weights=weights,
            vt_ratio=vt_ratio,
            abuse_confidence=abuse_confidence,
            source_trust=float(ioc["source_trust"]),
            recency_score=self._compute_recency_score(first_seen, last_seen),
        )
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
        )

    async def run(self, validated_iocs: list[IOC | dict[str, Any]], *args: Any, **kwargs: Any) -> list[EnrichedIOC]:
        self.reload_skill()
        weights = self.get_scoring_weights()
        started = time.perf_counter()
        enriched = await asyncio.gather(*(self.enrich_one(ioc, weights=weights) for ioc in validated_iocs))
        elapsed = time.perf_counter() - started
        self.logger.info(
            "Enrichment completed for %s IOC(s) in %.2fs (whois=%s)",
            len(validated_iocs),
            elapsed,
            "enabled" if self.whois_client is not None else "disabled",
        )
        return enriched

    async def aclose(self) -> None:
        if self._owns_abuse_client:
            await self.abuseipdb_client.aclose()

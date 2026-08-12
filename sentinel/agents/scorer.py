from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from sentinel.agents.base import BaseAgent
from sentinel.agents.enricher import EnrichedIOC
from sentinel.db.models import IOC
from sentinel.integrations.mitre_attack import MitreAttackRepository, TechniqueMatch


@dataclass(slots=True)
class ScoredIOC:
    value: str
    type: str
    source: str
    risk_score: float
    severity: str
    source_title: str | None = None
    reference_url: str | None = None
    related_cves: list[str] = field(default_factory=list)
    vt_detections: int | None = None
    abuse_confidence: int | None = None
    shodan_ports: list[int] = field(default_factory=list)
    external_links: dict[str, str] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    match_scores: dict[str, float] = field(default_factory=dict)
    enrichment_text: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


def map_severity(risk_score: float) -> str:
    if risk_score >= 90:
        return "critical"
    if risk_score >= 70:
        return "high"
    if risk_score >= 50:
        return "medium"
    return "informational"


def build_external_links_for_ioc(ioc: dict[str, Any]) -> dict[str, str]:
    value = str(ioc["value"])
    ioc_type = str(ioc["type"]).lower()
    source = str(ioc["source"]).lower()
    links = dict(ioc.get("external_links", {}))
    if ioc_type == "url":
        vt_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")
        links.setdefault("VirusTotal", f"https://www.virustotal.com/gui/url/{vt_id}")
    elif ioc_type == "domain":
        links.setdefault("VirusTotal", f"https://www.virustotal.com/gui/domain/{quote(value, safe='')}")
    elif ioc_type in {"ipv4", "ipv6"}:
        links.setdefault("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{quote(value, safe='')}")
    elif ioc_type in {"md5", "sha1", "sha256"}:
        links.setdefault("VirusTotal", f"https://www.virustotal.com/gui/file/{quote(value, safe='')}")
    if ioc_type in {"ipv4", "ipv6"}:
        links.setdefault("AbuseIPDB", f"https://www.abuseipdb.com/check/{quote(value, safe='')}")
        links.setdefault("Shodan", f"https://www.shodan.io/host/{quote(value, safe='')}")
    if source == "otx":
        links.setdefault("OTX", f"https://otx.alienvault.com/browse/global/pulses?q={quote(value, safe='')}")
    if source == "urlhaus" and ioc_type == "url":
        links.setdefault("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={quote(value, safe='')}")
    if source == "tweetfeed":
        links.setdefault("TweetFeed", f"https://tweetfeed.live/search/?q={quote(value, safe='')}")
    return links


class ScoringAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/mitre/SKILL.md",
        *,
        mitre_repository: MitreAttackRepository,
    ) -> None:
        super().__init__(skill_path)
        self.mitre_repository = mitre_repository

    def _coerce_ioc(self, item: EnrichedIOC | IOC | dict[str, Any]) -> dict[str, Any]:
        if isinstance(item, EnrichedIOC):
            return {
                "value": item.value,
                "type": item.type,
                "source": item.source,
                "risk_score": item.risk_score,
                "source_title": item.source_title,
                "reference_url": item.reference_url,
                "related_cves": list(item.related_cves),
                "enrichment_text": item.enrichment_text,
                "vt_detections": item.vt_detections,
                "abuse_confidence": item.abuse_confidence,
                "shodan_ports": item.shodan_ports,
                "provider_results": item.provider_results,
                "external_links": {},
                "attributes": dict(item.attributes),
            }
        if isinstance(item, IOC):
            return {
                "value": item.value,
                "type": item.type,
                "source": item.source,
                "risk_score": float(item.risk_score or 0.0),
                "source_title": item.source_title,
                "reference_url": item.reference_url,
                "related_cves": list(item.related_cves or []),
                "enrichment_text": "",
                "vt_detections": item.vt_detections,
                "abuse_confidence": item.abuse_confidence,
                "shodan_ports": item.shodan_ports,
                "provider_results": {},
                "external_links": {},
                "attributes": {},
            }
        return {
            "value": item["value"],
            "type": item["type"],
            "source": item["source"],
            "risk_score": float(item["risk_score"]),
            "source_title": item.get("source_title"),
            "reference_url": item.get("reference_url"),
            "related_cves": list(item.get("related_cves", [])),
            "enrichment_text": item.get("enrichment_text", ""),
            "vt_detections": item.get("vt_detections"),
            "abuse_confidence": item.get("abuse_confidence"),
            "shodan_ports": list(item.get("shodan_ports", [])),
            "provider_results": item.get("provider_results", {}),
            "external_links": dict(item.get("external_links", {})),
            "attributes": dict(item.get("attributes", {})),
        }

    def _build_context(self, ioc: dict[str, Any]) -> str:
        parts = [
            ioc["value"],
            ioc["type"],
            ioc.get("enrichment_text", ""),
            str(ioc.get("provider_results", {})),
        ]
        return "\n".join(part for part in parts if part)

    def _map_severity(self, risk_score: float) -> str:
        return map_severity(risk_score)

    def score_one(self, item: EnrichedIOC | IOC | dict[str, Any]) -> ScoredIOC:
        ioc = self._coerce_ioc(item)
        context = self._build_context(ioc)
        matches = self.mitre_repository.search(context, limit=3)
        tactics: list[str] = []
        for match in matches:
            for tactic in match.tactics:
                if tactic not in tactics:
                    tactics.append(tactic)
        return ScoredIOC(
            value=ioc["value"],
            type=ioc["type"],
            source=ioc["source"],
            risk_score=ioc["risk_score"],
            severity=self._map_severity(ioc["risk_score"]),
            source_title=ioc.get("source_title"),
            reference_url=ioc.get("reference_url"),
            related_cves=list(ioc.get("related_cves", [])),
            vt_detections=ioc.get("vt_detections"),
            abuse_confidence=ioc.get("abuse_confidence"),
            shodan_ports=list(ioc.get("shodan_ports", [])),
            external_links=build_external_links_for_ioc(ioc),
            mitre_techniques=[match.attack_id for match in matches],
            mitre_tactics=tactics,
            match_scores={match.attack_id: round(match.score, 4) for match in matches},
            enrichment_text=ioc.get("enrichment_text", ""),
            attributes=dict(ioc.get("attributes", {})),
        )

    async def run(self, enriched_iocs: list[EnrichedIOC | IOC | dict[str, Any]], *args: Any, **kwargs: Any) -> list[ScoredIOC]:
        self.reload_skill()
        return [self.score_one(ioc) for ioc in enriched_iocs]

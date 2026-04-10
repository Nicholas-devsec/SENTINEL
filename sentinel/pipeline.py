from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.enricher import EnrichedIOC, EnrichmentAgent
from sentinel.agents.rule_generator import GeneratedArtifacts, RuleGeneratorAgent
from sentinel.agents.scorer import ScoredIOC, ScoringAgent, build_external_links_for_ioc
from sentinel.agents.scraper import RawIOC, ScraperAgent
from sentinel.agents.validator import ValidationAgent
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.db.models import Base, IOC
from sentinel.db.session import AsyncSessionFactory, get_engine
from sentinel.integrations.mitre_attack import MitreAttackRepository
from telegram import Bot


@dataclass(slots=True)
class PipelineResult:
    scraped: int
    validated: int
    enriched: int
    scored: int
    generated: int
    immediate_alerts: int
    digest_candidates: int


async def init_db() -> None:
    async with get_engine().begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def _persist_enrichment(enriched_items: list[EnrichedIOC]) -> list[IOC]:
    async with AsyncSessionFactory() as session:
        persisted: list[IOC] = []
        for enriched in enriched_items:
            row = await session.scalar(select(IOC).where(IOC.dedupe_hash == __import__("hashlib").sha256(enriched.value.encode("utf-8")).hexdigest()))
            if row is None:
                continue
            row.risk_score = enriched.risk_score
            row.vt_detections = enriched.vt_detections
            row.shodan_ports = enriched.shodan_ports
            row.abuse_confidence = enriched.abuse_confidence
            persisted.append(row)
        await session.commit()
        return persisted


async def _persist_scoring(scored_items: list[ScoredIOC]) -> list[IOC]:
    async with AsyncSessionFactory() as session:
        persisted: list[IOC] = []
        for scored in scored_items:
            row = await session.scalar(select(IOC).where(IOC.value == scored.value))
            if row is None:
                continue
            row.risk_score = scored.risk_score
            row.severity = scored.severity
            row.mitre_techniques = scored.mitre_techniques
            row.mitre_tactics = scored.mitre_tactics
            persisted.append(row)
        await session.commit()
        return persisted


async def _persist_generated(generated: list[GeneratedArtifacts]) -> None:
    async with AsyncSessionFactory() as session:
        for artifact in generated:
            row = await session.scalar(select(IOC).where(IOC.value == artifact.value))
            if row is None:
                continue
            row.sigma_rule = artifact.sigma_rule
            row.crowdstrike_pushed = artifact.crowdstrike_response is not None
        await session.commit()


def _build_telegram_bot(settings: SentinelSettings) -> Bot | None:
    token = settings.delivery.telegram_token.strip()
    if _is_missing_secret(token):
        return None
    return Bot(token=token)


def build_agents(settings: SentinelSettings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    mitre_path = settings.mitre.stix_path.strip()
    if not mitre_path or mitre_path.startswith("${"):
        raise ValueError("MITRE_STIX_PATH must point to a local ATT&CK enterprise STIX bundle for live scoring.")
    mitre_repo = MitreAttackRepository(stix_path=settings.mitre.stix_path)
    telegram_bot = _build_telegram_bot(settings)
    return {
        "scraper": ScraperAgent(settings=settings),
        "validator": ValidationAgent(),
        "enricher": EnrichmentAgent(settings=settings),
        "scorer": ScoringAgent(mitre_repository=mitre_repo),
        "rule_generator": RuleGeneratorAgent(settings=settings, repo_path=Path.cwd()),
        "delivery": DeliveryAgent(settings=settings, telegram_bot=telegram_bot),
    }


async def run_pipeline_once(settings: SentinelSettings | None = None) -> PipelineResult:
    settings = settings or get_settings()
    await init_db()
    agents = build_agents(settings)
    try:
        raw_items: list[RawIOC] = await agents["scraper"].run()
        validated_rows: list[IOC] = await agents["validator"].run(raw_items)
        enriched_items: list[EnrichedIOC] = await agents["enricher"].run(validated_rows)
        await _persist_enrichment(enriched_items)
        scored_items: list[ScoredIOC] = await agents["scorer"].run(enriched_items)
        persisted_scored = await _persist_scoring(scored_items)
        delivery_payload = []
        for row, scored in zip(persisted_scored, scored_items, strict=False):
            payload = asdict(scored) if hasattr(scored, "__dataclass_fields__") else dict(scored)
            payload["id"] = str(row.id)
            payload["last_seen"] = row.last_seen
            delivery_payload.append(payload)
        generated = await agents["rule_generator"].run(delivery_payload)
        await _persist_generated(generated)
        delivery_result = await agents["delivery"].run(delivery_payload)
        return PipelineResult(
            scraped=len(raw_items),
            validated=len(validated_rows),
            enriched=len(enriched_items),
            scored=len(scored_items),
            generated=len(generated),
            immediate_alerts=delivery_result.immediate_alerts,
            digest_candidates=delivery_result.digest_candidates,
        )
    finally:
        for key in ("scraper", "enricher", "rule_generator"):
            closer = getattr(agents[key], "aclose", None)
            if closer is not None:
                await closer()


async def run_daily_digest(settings: SentinelSettings | None = None) -> Any:
    settings = settings or get_settings()
    await init_db()
    delivery = DeliveryAgent(settings=settings, telegram_bot=_build_telegram_bot(settings))
    try:
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        async with AsyncSessionFactory() as session:
            rows = list(
                (
                    await session.scalars(
                        select(IOC)
                        .where(IOC.last_seen >= cutoff)
                        .where(IOC.risk_score.is_not(None))
                        .order_by(IOC.risk_score.desc(), IOC.last_seen.desc())
                        .limit(settings.delivery.telegram_daily_digest_limit)
                    )
                ).all()
            )
        items = [
            {
                "id": str(row.id),
                "value": row.value,
                "type": row.type,
                "source": row.source,
                "risk_score": float(row.risk_score or 0.0),
                "severity": row.severity or "informational",
                "source_title": row.source_title,
                "reference_url": row.reference_url,
                "related_cves": list(row.related_cves or []),
                "vt_detections": row.vt_detections,
                "abuse_confidence": row.abuse_confidence,
                "shodan_ports": list(row.shodan_ports or []),
                "external_links": {},
                "mitre_techniques": row.mitre_techniques,
                "mitre_tactics": row.mitre_tactics,
                "last_seen": row.last_seen,
            }
            for row in rows
        ]
        for item in items:
            item["external_links"] = build_external_links_for_ioc(item)
        return await delivery.daily_digest(items)
    finally:
        closer = getattr(delivery, "aclose", None)
        if closer is not None:
            await closer()

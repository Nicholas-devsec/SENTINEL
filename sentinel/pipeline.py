from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.enricher import EnrichedIOC, EnrichmentAgent
from sentinel.agents.rule_generator import GeneratedArtifacts, RuleGeneratorAgent
from sentinel.agents.scorer import ScoredIOC, ScoringAgent, build_external_links_for_ioc, map_severity
from sentinel.agents.scraper import RawWriteup, ScrapeReport, ScraperAgent
from sentinel.agents.validator import ValidationAgent, get_corroboration, get_scoring_context
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.db.migrations import ensure_schema
from sentinel.db.models import IOC, SourceMaterial
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
    writeups: int = 0
    sightings: int = 0
    corroborated: int = 0
    discovered: int = 0


async def init_db() -> None:
    await ensure_schema(get_engine())


async def _persist_writeups(writeups: list[RawWriteup]) -> dict[str, Any]:
    """Get-or-create SourceMaterial rows; returns article url -> row id."""
    if not writeups:
        return {}
    url_to_id: dict[str, Any] = {}
    async with AsyncSessionFactory() as session:
        for writeup in writeups:
            row = await session.scalar(select(SourceMaterial).where(SourceMaterial.url == writeup.url))
            if row is None:
                row = SourceMaterial(
                    source=writeup.source,
                    url=writeup.url,
                    title=writeup.title,
                    published_at=writeup.published_at,
                    fetched_at=datetime.now(UTC) if writeup.content_text is not None else None,
                    content_text=writeup.content_text,
                    extraction_status="failed" if writeup.fetch_error else "extracted",
                    metadata_json={
                        "summary": writeup.summary,
                        "tags": writeup.tags,
                        "fetch_error": writeup.fetch_error,
                    },
                )
                session.add(row)
                await session.flush()
            url_to_id[writeup.url] = row.id
        await session.commit()
    return url_to_id


async def _persist_enrichment(enriched_items: list[EnrichedIOC]) -> list[IOC]:
    async with AsyncSessionFactory() as session:
        persisted: list[IOC] = []
        for enriched in enriched_items:
            dedupe_hash = hashlib.sha256(enriched.value.encode("utf-8")).hexdigest()
            row = await session.scalar(select(IOC).where(IOC.dedupe_hash == dedupe_hash))
            if row is None:
                continue
            row.risk_score = enriched.risk_score
            row.vt_detections = enriched.vt_detections
            row.vt_ratio = enriched.vt_ratio
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
        scrape_report: ScrapeReport = await agents["scraper"].run_with_diagnostics()
        raw_items = scrape_report.items
        all_writeups = list(scrape_report.writeups)
        discovered_count = 0
        if settings.discovery.enabled and settings.discovery.profiles:
            from sentinel.agents.discovery import DiscoveryAgent

            discovery = DiscoveryAgent(settings=settings)
            try:
                discovery_report = await discovery.run_with_report()
            finally:
                await discovery.aclose()
            raw_items = [*raw_items, *discovery_report.items]
            all_writeups.extend(discovery_report.writeups)
            discovered_count = len(discovery_report.items)
        source_material_ids = await _persist_writeups(all_writeups)
        validation_report = await agents["validator"].run_with_report(
            raw_items, source_material_ids=source_material_ids
        )
        validated_rows: list[IOC] = validation_report.new_iocs
        # Build per-IOC scoring context (provenance, curation, corroboration) so
        # the score reflects evidence and analyst curation, not feed identity.
        async with AsyncSessionFactory() as session:
            context_by_id = await get_scoring_context(session, [row.id for row in validated_rows])
        context_by_value = {
            row.value: context_by_id[row.id] for row in validated_rows if row.id in context_by_id
        }
        # Enrich non-feed (writeup/discovery) indicators first so a flood of feed
        # IOCs cannot exhaust the VirusTotal/AbuseIPDB budget before them.
        ordered_rows = sorted(
            validated_rows,
            key=lambda row: 0 if (context_by_value.get(row.value, {}).get("provenance") in {"writeup", "discovery"}) else 1,
        )
        enriched_items: list[EnrichedIOC] = await agents["enricher"].run(
            ordered_rows, context_by_value=context_by_value
        )
        await _persist_enrichment(enriched_items)
        scored_items: list[ScoredIOC] = await agents["scorer"].run(enriched_items)
        persisted_scored = await _persist_scoring(scored_items)
        async with AsyncSessionFactory() as session:
            corroboration = await get_corroboration(session, [row.id for row in persisted_scored])
        delivery_payload = []
        for row, scored in zip(persisted_scored, scored_items, strict=False):
            payload = asdict(scored) if hasattr(scored, "__dataclass_fields__") else dict(scored)
            payload["id"] = str(row.id)
            payload["last_seen"] = row.last_seen
            payload["corroboration_sources"] = corroboration.get(row.id, 1)
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
            writeups=len(all_writeups),
            sightings=validation_report.sightings_recorded,
            corroborated=len(validation_report.corroborated_iocs),
            discovered=discovered_count,
        )
    finally:
        for key in ("scraper", "enricher", "rule_generator", "delivery"):
            closer = getattr(agents[key], "aclose", None)
            if closer is not None:
                await closer()


@dataclass(slots=True)
class RescoreResult:
    rescored: int
    changed: int
    by_source_before: dict[str, float]
    by_source_after: dict[str, float]


async def rescore_existing_iocs(settings: SentinelSettings | None = None) -> RescoreResult:
    """Re-level every stored IOC under the current weights + scoring context.

    Uses only already-stored evidence (vt_ratio, abuse_confidence, trust,
    recency) plus freshly aggregated sighting context — no external API calls,
    so it is safe to run repeatedly and cannot burn VirusTotal/AbuseIPDB quota.
    """
    settings = settings or get_settings()
    await init_db()
    enricher = EnrichmentAgent(settings=settings)
    try:
        weights = enricher.get_scoring_weights()
        before_sum: dict[str, list[float]] = {}
        after_sum: dict[str, list[float]] = {}
        rescored = 0
        changed = 0
        async with AsyncSessionFactory() as session:
            rows = list((await session.scalars(select(IOC))).all())
            context_by_id = await get_scoring_context(session, [row.id for row in rows])
            for row in rows:
                before = float(row.risk_score or 0.0)
                new_score = enricher.rescore_from_stored(
                    weights=weights,
                    vt_ratio=row.vt_ratio,
                    abuse_confidence=row.abuse_confidence,
                    source_trust=float(row.source_trust or 0.0),
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    context=context_by_id.get(row.id),
                )
                before_sum.setdefault(row.source, []).append(before)
                after_sum.setdefault(row.source, []).append(new_score)
                if abs(new_score - before) > 1e-6:
                    changed += 1
                row.risk_score = new_score
                row.severity = map_severity(new_score)
                rescored += 1
            await session.commit()
        avg = lambda values: round(sum(values) / len(values), 2) if values else 0.0
        return RescoreResult(
            rescored=rescored,
            changed=changed,
            by_source_before={src: avg(vals) for src, vals in sorted(before_sum.items())},
            by_source_after={src: avg(vals) for src, vals in sorted(after_sum.items())},
        )
    finally:
        closer = getattr(enricher, "aclose", None)
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

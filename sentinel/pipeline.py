from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy import or_

from sentinel.agents.delivery import DeliveryAgent
from sentinel.agents.enricher import EnrichedIOC, EnrichmentAgent
from sentinel.agents.rule_generator import GeneratedArtifacts, RuleGeneratorAgent
from sentinel.agents.scorer import ScoredIOC, ScoringAgent, build_external_links_for_ioc, map_severity
from sentinel.agents.scraper import RawWriteup, ScrapeReport, ScraperAgent
from sentinel.agents.validator import ValidationAgent, get_corroboration, get_scoring_context
from sentinel.config import SentinelSettings, _is_missing_secret, get_settings
from sentinel.db.migrations import ensure_schema
from sentinel.db.models import AlertEvent, FeedbackRecord, IOC, IOCSighting, PipelineRun, SourceMaterial
from sentinel.db.session import AsyncSessionFactory, get_engine
from sentinel.integrations.mitre_attack import MitreAttackRepository
from telegram import Bot


logger = logging.getLogger(__name__)
HASH_TYPES = {"md5", "sha1", "sha256"}


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
    stage_durations: dict[str, float] | None = field(default=None, compare=False)


def _is_article_item(item: Any) -> bool:
    provenance = str(getattr(item, "provenance", None) or "").strip().lower()
    return provenance in {"writeup", "discovery"} and bool(str(getattr(item, "reference_url", None) or "").strip())


def _is_discovery_article_item(item: Any) -> bool:
    provenance = str(getattr(item, "provenance", None) or "").strip().lower()
    source = str(getattr(item, "source", "") or "").strip().lower()
    return provenance == "discovery" or source.startswith("discovery:")


def _is_discovery_writeup(writeup: RawWriteup) -> bool:
    return str(writeup.source or "").strip().lower().startswith("discovery:")


def _has_split_article_store_limits(settings: SentinelSettings) -> bool:
    workflow = settings.workflow
    return (
        workflow.feed_article_store_limit_per_run is not None
        or workflow.discovery_article_store_limit_per_run is not None
    )


def _article_store_limit(value: int | None) -> int:
    return max(0, int(value or 0))


def _raw_feed_hash_family_key(item: Any) -> tuple[str, str, str, str, int] | None:
    source = str(getattr(item, "source", "") or "").strip().lower()
    ioc_type = str(getattr(item, "type", "") or "").strip().lower()
    if source != "threatfox" or ioc_type not in HASH_TYPES:
        return None
    attrs = getattr(item, "attributes", {}) or {}
    original_reference = str(attrs.get("reference_url_original") or "").strip().lower()
    malware = str(attrs.get("malware") or attrs.get("malware_printable") or "").strip().lower()
    threat_type = str(attrs.get("threat_type") or getattr(item, "description", "") or "").strip().lower()
    reporter = str(attrs.get("reporter") or "").strip().lower()
    if not (original_reference or malware or threat_type):
        return None
    first_seen = getattr(item, "first_seen", datetime.now(UTC))
    first_seen = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=UTC)
    five_second_bucket = int(first_seen.timestamp()) // 5
    context = original_reference or malware or threat_type
    return (source, context, threat_type, reporter, five_second_bucket)


def _dedupe_feed_hash_families_before_limit(items: list[Any]) -> list[Any]:
    seen_families: set[tuple[str, str, str, str, int]] = set()
    deduped: list[Any] = []
    for item in items:
        family_key = _raw_feed_hash_family_key(item)
        if family_key is not None:
            if family_key in seen_families:
                continue
            seen_families.add(family_key)
        deduped.append(item)
    return deduped


def _normalized_type_limits(type_limits: dict[str, int] | None) -> dict[str, int]:
    limits: dict[str, int] = {}
    for raw_key, raw_limit in (type_limits or {}).items():
        key = str(raw_key).strip().lower()
        if not key:
            continue
        limits[key] = max(0, int(raw_limit))
    return limits


def _type_bucket_for(item_type: str) -> str:
    normalized = str(item_type or "").strip().lower()
    if normalized in HASH_TYPES:
        return "hash"
    return normalized


def _apply_type_limits(items: list[Any], type_limits: dict[str, int] | None) -> list[Any]:
    limits = _normalized_type_limits(type_limits)
    if not limits:
        return items
    counts = {key: 0 for key in limits}
    selected: list[Any] = []
    for item in items:
        bucket = _type_bucket_for(str(getattr(item, "type", "") or ""))
        if bucket not in limits:
            continue
        if counts[bucket] >= limits[bucket]:
            continue
        counts[bucket] += 1
        selected.append(item)
    return selected


def _apply_workflow_limits(
    settings: SentinelSettings,
    *,
    raw_items: list[Any],
    writeups: list[RawWriteup],
) -> tuple[list[Any], list[RawWriteup]]:
    feed_limit = max(0, int(settings.workflow.feed_ioc_store_limit_per_run))

    feed_items = [item for item in raw_items if not _is_article_item(item)]
    article_items = [item for item in raw_items if _is_article_item(item)]

    feed_items = _dedupe_feed_hash_families_before_limit(feed_items)
    feed_items = _apply_type_limits(feed_items, settings.workflow.store_type_limits_per_run)
    if feed_limit > 0:
        feed_items = feed_items[:feed_limit]
    else:
        feed_items = []

    def limit_article_bucket(
        *,
        bucket_items: list[Any],
        bucket_writeups: list[RawWriteup],
        limit: int,
    ) -> tuple[list[Any], list[RawWriteup]]:
        article_url_order: list[str] = []
        seen_urls: set[str] = set()
        for item in bucket_items:
            url = str(getattr(item, "reference_url", None) or "").strip()
            if url and url not in seen_urls:
                seen_urls.add(url)
                article_url_order.append(url)
        for writeup in bucket_writeups:
            url = str(writeup.url or "").strip()
            if url and url not in seen_urls:
                seen_urls.add(url)
                article_url_order.append(url)

        kept_article_urls = set(article_url_order[:limit]) if limit > 0 else set()
        return (
            [
                item
                for item in bucket_items
                if str(getattr(item, "reference_url", None) or "").strip() in kept_article_urls
            ],
            [writeup for writeup in bucket_writeups if str(writeup.url or "").strip() in kept_article_urls],
        )

    if _has_split_article_store_limits(settings):
        feed_article_limit = _article_store_limit(settings.workflow.feed_article_store_limit_per_run)
        discovery_article_limit = _article_store_limit(settings.workflow.discovery_article_store_limit_per_run)
        feed_article_items = [item for item in article_items if not _is_discovery_article_item(item)]
        discovery_article_items = [item for item in article_items if _is_discovery_article_item(item)]
        feed_writeups = [writeup for writeup in writeups if not _is_discovery_writeup(writeup)]
        discovery_writeups = [writeup for writeup in writeups if _is_discovery_writeup(writeup)]
        kept_feed_article_items, kept_feed_writeups = limit_article_bucket(
            bucket_items=feed_article_items,
            bucket_writeups=feed_writeups,
            limit=feed_article_limit,
        )
        kept_discovery_article_items, kept_discovery_writeups = limit_article_bucket(
            bucket_items=discovery_article_items,
            bucket_writeups=discovery_writeups,
            limit=discovery_article_limit,
        )
        return (
            [*feed_items, *kept_feed_article_items, *kept_discovery_article_items],
            [*kept_feed_writeups, *kept_discovery_writeups],
        )

    article_limit = max(0, int(settings.workflow.article_store_limit_per_run))
    article_url_order: list[str] = []
    seen_urls: set[str] = set()
    for item in article_items:
        url = str(getattr(item, "reference_url", None) or "").strip()
        if url and url not in seen_urls:
            seen_urls.add(url)
            article_url_order.append(url)
    for writeup in writeups:
        url = str(writeup.url or "").strip()
        if url and url not in seen_urls:
            seen_urls.add(url)
            article_url_order.append(url)

    kept_article_urls = set(article_url_order[:article_limit]) if article_limit > 0 else set()
    article_items = [
        item for item in article_items if str(getattr(item, "reference_url", None) or "").strip() in kept_article_urls
    ]
    writeups = [writeup for writeup in writeups if str(writeup.url or "").strip() in kept_article_urls]
    return [*feed_items, *article_items], writeups


def _ordered_processing_rows(
    rows: list[IOC],
    *,
    context_by_value: dict[str, dict[str, Any]],
) -> list[IOC]:
    return sorted(
        rows,
        key=lambda row: (
            0 if (context_by_value.get(row.value, {}).get("provenance") in {"writeup", "discovery"}) else 1,
            -(row.last_seen.timestamp() if hasattr(row.last_seen, "timestamp") else 0.0),
        ),
    )


async def init_db() -> None:
    await ensure_schema(get_engine())


async def _start_pipeline_run() -> Any | None:
    """Best-effort run-ledger row; a ledger failure must never block the run."""
    try:
        async with AsyncSessionFactory() as session:
            row = PipelineRun(started_at=datetime.now(UTC), status="running")
            session.add(row)
            await session.commit()
            return row.id
    except Exception:
        logger.exception("Failed to record pipeline run start; continuing without ledger row")
        return None


async def _finish_pipeline_run(
    run_id: Any | None,
    *,
    status: str,
    result: PipelineResult | None = None,
    error: str | None = None,
) -> None:
    if run_id is None:
        return
    try:
        async with AsyncSessionFactory() as session:
            row = await session.get(PipelineRun, run_id)
            if row is None:
                return
            row.finished_at = datetime.now(UTC)
            row.status = status
            row.error = error
            if result is not None:
                counts = asdict(result)
                row.stage_durations = counts.pop("stage_durations", None) or {}
                row.counts = counts
            await session.commit()
    except Exception:
        logger.exception("Failed to finalize pipeline run ledger row %s", run_id)


async def _persist_writeups(writeups: list[RawWriteup], raw_items: list[Any] | None = None) -> dict[str, Any]:
    """Get-or-create SourceMaterial rows; returns article url -> row id."""
    if not writeups:
        return {}
    url_to_id: dict[str, Any] = {}
    extracted_counts: dict[str, int] = {}
    for item in raw_items or []:
        reference_url = str(getattr(item, "reference_url", None) or "").strip()
        if reference_url:
            extracted_counts[reference_url] = extracted_counts.get(reference_url, 0) + 1
    async with AsyncSessionFactory() as session:
        for writeup in writeups:
            row = await session.scalar(select(SourceMaterial).where(SourceMaterial.url == writeup.url))
            extracted_ioc_count = extracted_counts.get(writeup.url, 0)
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
                    extracted_ioc_count=extracted_ioc_count,
                )
                session.add(row)
                await session.flush()
            else:
                row.source = writeup.source
                row.title = writeup.title or row.title
                row.published_at = writeup.published_at or row.published_at
                if writeup.content_text is not None:
                    row.fetched_at = datetime.now(UTC)
                    row.content_text = writeup.content_text
                row.extraction_status = "failed" if writeup.fetch_error else "extracted"
                row.extracted_ioc_count = extracted_ioc_count
                metadata = dict(row.metadata_json or {})
                metadata.update(
                    {
                        "summary": writeup.summary,
                        "tags": writeup.tags,
                        "fetch_error": writeup.fetch_error,
                    }
                )
                row.metadata_json = metadata
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
            breakdown = enriched.attributes.get("score_breakdown")
            if breakdown is not None:
                row.score_breakdown = breakdown
            persisted.append(row)
        await session.commit()
        return persisted


def _enriched_hash_family_key(item: EnrichedIOC) -> str | None:
    ioc_type = str(getattr(item, "type", "") or "").lower()
    if ioc_type not in HASH_TYPES:
        return None
    attributes = getattr(item, "attributes", {}) or {}
    family = attributes.get("hash_family")
    if isinstance(family, dict):
        for hash_type in ("sha256", "sha1", "md5"):
            value = family.get(hash_type)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    explicit_key = attributes.get("hash_family_key")
    if isinstance(explicit_key, str) and explicit_key.strip():
        return explicit_key.strip().lower()
    return str(getattr(item, "value", "") or "").strip().lower()


def _dedupe_enriched_hash_families(enriched_items: list[EnrichedIOC]) -> tuple[list[EnrichedIOC], list[EnrichedIOC]]:
    by_family: dict[str, EnrichedIOC] = {}
    family_members: dict[str, list[EnrichedIOC]] = {}
    passthrough: list[EnrichedIOC] = []
    for item in enriched_items:
        family_key = _enriched_hash_family_key(item)
        if family_key is None:
            passthrough.append(item)
            continue
        family_members.setdefault(family_key, []).append(item)
        existing = by_family.get(family_key)
        if existing is None:
            by_family[family_key] = item

    kept_ids = {id(item) for item in by_family.values()}
    kept = [item for item in enriched_items if id(item) in kept_ids or _enriched_hash_family_key(item) is None]
    suppressed = [
        member
        for family_key, members in family_members.items()
        for member in members
        if member is not by_family[family_key]
    ]
    return kept, suppressed


async def _delete_ioc_rows(items: list[EnrichedIOC]) -> int:
    if not items:
        return 0
    dedupe_hashes = [hashlib.sha256(item.value.encode("utf-8")).hexdigest() for item in items]
    async with AsyncSessionFactory() as session:
        result = await session.execute(select(IOC.id).where(IOC.dedupe_hash.in_(dedupe_hashes)))
        ids = [ioc_id for (ioc_id,) in result.all()]
        if not ids:
            return 0
        await session.execute(delete(AlertEvent).where(AlertEvent.ioc_id.in_(ids)))
        await session.execute(delete(FeedbackRecord).where(FeedbackRecord.ioc_id.in_(ids)))
        await session.execute(delete(IOCSighting).where(IOCSighting.ioc_id.in_(ids)))
        await session.execute(delete(IOC).where(IOC.id.in_(ids)))
        await session.commit()
        return len(ids)


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


def _ioc_identity(value: str, ioc_type: str, source: str) -> tuple[str, str, str]:
    return (str(value), str(ioc_type).lower(), str(source).lower())


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
    stage_durations: dict[str, float] = {}
    run_started = time.perf_counter()
    run_id = await _start_pipeline_run()
    try:
        stage_started = time.perf_counter()
        scrape_report: ScrapeReport = await agents["scraper"].run_with_diagnostics()
        stage_durations["scrape"] = round(time.perf_counter() - stage_started, 2)
        raw_items = scrape_report.items
        all_writeups = list(scrape_report.writeups)
        discovered_count = 0
        if settings.discovery.enabled and settings.discovery.profiles:
            from sentinel.agents.discovery import DiscoveryAgent

            discovery = DiscoveryAgent(settings=settings)
            try:
                stage_started = time.perf_counter()
                discovery_report = await discovery.run_with_report()
                stage_durations["discovery"] = round(time.perf_counter() - stage_started, 2)
            finally:
                await discovery.aclose()
            raw_items = [*raw_items, *discovery_report.items]
            all_writeups.extend(discovery_report.writeups)
            discovered_count = len(discovery_report.items)
        raw_items, all_writeups = _apply_workflow_limits(
            settings,
            raw_items=raw_items,
            writeups=all_writeups,
        )
        stage_started = time.perf_counter()
        source_material_ids = await _persist_writeups(all_writeups, raw_items)
        validation_report = await agents["validator"].run_with_report(
            raw_items, source_material_ids=source_material_ids
        )
        stage_durations["validate"] = round(time.perf_counter() - stage_started, 2)
        processing_rows: list[IOC] = validation_report.all_iocs
        # Build per-IOC scoring context (provenance, curation, corroboration) so
        # the score reflects evidence and analyst curation, not feed identity.
        stage_started = time.perf_counter()
        async with AsyncSessionFactory() as session:
            context_by_id = await get_scoring_context(session, [row.id for row in processing_rows])
        context_by_value = {
            row.value: context_by_id[row.id] for row in processing_rows if row.id in context_by_id
        }
        # Enrich non-feed (writeup/discovery) indicators first so a flood of feed
        # IOCs cannot exhaust the VirusTotal/AbuseIPDB budget before them.
        ordered_rows = _ordered_processing_rows(processing_rows, context_by_value=context_by_value)
        stage_durations["context"] = round(time.perf_counter() - stage_started, 2)
        stage_started = time.perf_counter()
        enriched_items: list[EnrichedIOC] = await agents["enricher"].run(
            ordered_rows, context_by_value=context_by_value
        )
        enriched_items, suppressed_hash_variants = _dedupe_enriched_hash_families(enriched_items)
        deleted_hash_variants = await _delete_ioc_rows(suppressed_hash_variants)
        if deleted_hash_variants:
            logger.info(
                "Suppressed %s duplicate file-hash variant IOC row(s) after enrichment",
                deleted_hash_variants,
            )
        stage_durations["enrich"] = round(time.perf_counter() - stage_started, 2)
        stage_started = time.perf_counter()
        await _persist_enrichment(enriched_items)
        scored_items: list[ScoredIOC] = await agents["scorer"].run(enriched_items)
        persisted_scored = await _persist_scoring(scored_items)
        stage_durations["score"] = round(time.perf_counter() - stage_started, 2)
        stage_started = time.perf_counter()
        async with AsyncSessionFactory() as session:
            corroboration = await get_corroboration(session, [row.id for row in persisted_scored])
        persisted_by_identity = {
            _ioc_identity(row.value, row.type, row.source): row for row in persisted_scored
        }
        delivery_payload = []
        for scored in scored_items:
            payload = asdict(scored) if hasattr(scored, "__dataclass_fields__") else dict(scored)
            row = persisted_by_identity.get(
                _ioc_identity(payload["value"], payload["type"], payload["source"])
            )
            if row is None:
                continue
            payload["id"] = str(row.id)
            payload["last_seen"] = row.last_seen
            context = context_by_id.get(row.id, {})
            payload["corroboration_sources"] = corroboration.get(row.id, 1)
            payload["provenance"] = context.get("provenance")
            payload["extraction_mode"] = context.get("extraction_mode")
            payload.setdefault("attributes", {})
            if context.get("article_ioc_count") is not None:
                payload["attributes"]["article_ioc_count"] = int(context.get("article_ioc_count") or 0)
            if payload["provenance"] is not None:
                payload["attributes"]["provenance"] = payload["provenance"]
            if payload["extraction_mode"] is not None:
                payload["attributes"]["extraction_mode"] = payload["extraction_mode"]
            delivery_payload.append(payload)
        generated = await agents["rule_generator"].run(delivery_payload)
        await _persist_generated(generated)
        stage_durations["generate"] = round(time.perf_counter() - stage_started, 2)
        stage_started = time.perf_counter()
        delivery_result = await agents["delivery"].run(delivery_payload)
        stage_durations["deliver"] = round(time.perf_counter() - stage_started, 2)
        stage_durations["total"] = round(time.perf_counter() - run_started, 2)
        logger.info(
            "Pipeline completed scraped=%s validated_new=%s corroborated=%s processed=%s enriched=%s scored=%s generated=%s immediate_alerts=%s durations=%s",
            len(raw_items),
            len(validation_report.new_iocs),
            len(validation_report.corroborated_iocs),
            len(processing_rows),
            len(enriched_items),
            len(scored_items),
            len(generated),
            delivery_result.immediate_alerts,
            stage_durations,
        )
        result = PipelineResult(
            scraped=len(raw_items),
            validated=len(validation_report.new_iocs),
            enriched=len(enriched_items),
            scored=len(scored_items),
            generated=len(generated),
            immediate_alerts=delivery_result.immediate_alerts,
            digest_candidates=delivery_result.digest_candidates,
            writeups=len(all_writeups),
            sightings=validation_report.sightings_recorded,
            corroborated=len(validation_report.corroborated_iocs),
            discovered=discovered_count,
            stage_durations=stage_durations,
        )
        await _finish_pipeline_run(run_id, status="succeeded", result=result)
        return result
    except Exception as exc:
        await _finish_pipeline_run(run_id, status="failed", error=f"{type(exc).__name__}: {exc}")
        raise
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
                breakdown = enricher.breakdown_from_stored(
                    weights=weights,
                    vt_ratio=row.vt_ratio,
                    abuse_confidence=row.abuse_confidence,
                    source_trust=float(row.source_trust or 0.0),
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    context=context_by_id.get(row.id),
                )
                new_score = round(max(0.0, min(100.0, sum(breakdown.values()))), 2)
                row.score_breakdown = breakdown
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
        candidate_pool_size = max(
            int(settings.delivery.telegram_daily_digest_limit),
            int(settings.delivery.telegram_digest_candidate_pool_size),
        )
        async with AsyncSessionFactory() as session:
            rows = list(
                (
                    await session.scalars(
                        select(IOC)
                        .where(IOC.last_seen >= cutoff)
                        .where(IOC.risk_score.is_not(None))
                        .where(or_(IOC.analyst_verdict.is_(None), IOC.analyst_verdict != "false_positive"))
                        .order_by(IOC.risk_score.desc(), IOC.last_seen.desc())
                        .limit(candidate_pool_size)
                    )
                ).all()
            )
            context_by_id = await get_scoring_context(session, [row.id for row in rows])
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
                "provenance": (context_by_id.get(row.id) or {}).get("provenance"),
                "extraction_mode": (context_by_id.get(row.id) or {}).get("extraction_mode"),
                "corroboration_sources": (context_by_id.get(row.id) or {}).get("corroboration_sources", 1),
                "attributes": {
                    "article_ioc_count": int((context_by_id.get(row.id) or {}).get("article_ioc_count") or 0),
                    "provenance": (context_by_id.get(row.id) or {}).get("provenance"),
                    "extraction_mode": (context_by_id.get(row.id) or {}).get("extraction_mode"),
                    "score_breakdown": getattr(row, "score_breakdown", None),
                },
            }
            for row in rows
        ]
        for item in items:
            item["external_links"] = build_external_links_for_ioc(item)
        return await delivery.daily_digest(delivery._select_digest_candidates(items))
    finally:
        closer = getattr(delivery, "aclose", None)
        if closer is not None:
            await closer()

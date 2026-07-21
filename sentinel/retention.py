from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.config import RetentionSettings
from sentinel.db.models import AlertEvent, FeedbackRecord, IOC, IOCSighting, SourceMaterial


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetentionResult:
    pruned_iocs: int = 0
    pruned_source_materials: int = 0


def _aware_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=max(0, int(days)))


async def prune_retention(
    *,
    settings: RetentionSettings,
    session_factory: async_sessionmaker[AsyncSession],
    now: datetime | None = None,
) -> RetentionResult:
    """Prune stale low-value rows while preserving learning-critical data."""
    if not settings.enabled:
        return RetentionResult()

    current = _aware_utc(now or datetime.now(UTC))
    async with session_factory() as session:
        feedback_ids = {
            ioc_id
            for (ioc_id,) in (await session.execute(select(FeedbackRecord.ioc_id))).all()
        }
        alert_ids = {
            ioc_id
            for (ioc_id,) in (await session.execute(select(AlertEvent.ioc_id))).all()
        }
        article_ids = {
            ioc_id
            for (ioc_id,) in (
                await session.execute(
                    select(IOCSighting.ioc_id).where(
                        IOCSighting.provenance.in_(["writeup", "discovery"])
                    )
                )
            ).all()
        }
        feed_sighting_ids = {
            ioc_id
            for (ioc_id,) in (
                await session.execute(
                    select(IOCSighting.ioc_id).where(IOCSighting.provenance == "feed")
                )
            ).all()
        }

        iocs = list((await session.scalars(select(IOC))).all())
        prune_ids: list[Any] = []
        for row in iocs:
            if row.id in feedback_ids and settings.keep_feedback_labeled:
                continue
            if row.id in feedback_ids:
                ttl_days = settings.feedback_ioc_ttl_days
            elif row.id in article_ids:
                ttl_days = settings.article_ioc_ttl_days
            elif row.id in alert_ids:
                ttl_days = settings.alerted_ioc_ttl_days
            elif row.id in feed_sighting_ids:
                ttl_days = settings.unalerted_feed_ioc_ttl_days
            else:
                ttl_days = settings.unalerted_feed_ioc_ttl_days
            if _aware_utc(row.last_seen) < _cutoff(current, ttl_days):
                prune_ids.append(row.id)

        pruned_iocs = len(prune_ids)
        if prune_ids:
            await session.execute(delete(AlertEvent).where(AlertEvent.ioc_id.in_(prune_ids)))
            await session.execute(delete(FeedbackRecord).where(FeedbackRecord.ioc_id.in_(prune_ids)))
            await session.execute(delete(IOCSighting).where(IOCSighting.ioc_id.in_(prune_ids)))
            await session.execute(delete(IOC).where(IOC.id.in_(prune_ids)))

        referenced_material_ids = {
            source_material_id
            for (source_material_id,) in (
                await session.execute(
                    select(IOCSighting.source_material_id).where(IOCSighting.source_material_id.is_not(None))
                )
            ).all()
        }
        material_cutoff = _cutoff(current, settings.source_material_ttl_days)
        source_materials = list((await session.scalars(select(SourceMaterial))).all())
        prune_material_ids = [
            material.id
            for material in source_materials
            if material.id not in referenced_material_ids
            and _aware_utc(material.fetched_at or material.published_at or material.updated_at) < material_cutoff
        ]
        pruned_source_materials = len(prune_material_ids)
        if prune_material_ids:
            await session.execute(delete(SourceMaterial).where(SourceMaterial.id.in_(prune_material_ids)))

        await session.commit()

    result = RetentionResult(pruned_iocs=pruned_iocs, pruned_source_materials=pruned_source_materials)
    if pruned_iocs or pruned_source_materials:
        logger.info(
            "Retention pruned stale rows: iocs=%s source_materials=%s",
            pruned_iocs,
            pruned_source_materials,
        )
    return result

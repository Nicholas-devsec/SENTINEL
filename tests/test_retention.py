from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from sentinel.config import RetentionSettings
from sentinel.db.models import AlertEvent, FeedbackRecord, IOC, IOCSighting, SourceMaterial
from sentinel.retention import prune_retention


def _ioc(value: str, *, last_seen: datetime) -> IOC:
    return IOC(
        value=value,
        dedupe_hash=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        type="domain",
        source="threatfox",
        source_trust=0.9,
        first_seen=last_seen,
        last_seen=last_seen,
    )


def _sighting(row: IOC, *, provenance: str, last_seen: datetime, material: SourceMaterial | None = None) -> IOCSighting:
    return IOCSighting(
        ioc_id=row.id,
        source=row.source,
        source_trust=row.source_trust,
        provenance=provenance,
        reference_url=material.url if material else None,
        source_material_id=material.id if material else None,
        first_seen=last_seen,
        last_seen=last_seen,
        lineage_hash=IOCSighting.build_lineage_hash(
            ioc_id=row.id,
            source=row.source,
            provenance=provenance,
            reference_url=material.url if material else None,
        ),
    )


@pytest.mark.asyncio
async def test_retention_prunes_only_stale_unalerted_feed_noise(db_session_factory) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    old = now - timedelta(days=10)
    article_material = SourceMaterial(
        source="rapid7_blog",
        url="https://rapid7.example/report",
        title="Article with IOCs",
        published_at=old,
        fetched_at=old,
        extraction_status="extracted",
        extracted_ioc_count=1,
    )
    unreferenced_old_material = SourceMaterial(
        source="old_blog",
        url="https://old.example/report",
        title="Old unreferenced article",
        published_at=old,
        fetched_at=old,
        extraction_status="extracted",
        extracted_ioc_count=0,
    )
    fresh_feed = _ioc("fresh-feed.example", last_seen=now - timedelta(days=1))
    stale_feed = _ioc("stale-feed.example", last_seen=old)
    alerted_feed = _ioc("alerted-feed.example", last_seen=old)
    labeled_feed = _ioc("labeled-feed.example", last_seen=old)
    article_ioc = _ioc("article-linked.example", last_seen=old)

    async with db_session_factory() as session:
        session.add_all(
            [
                article_material,
                unreferenced_old_material,
                fresh_feed,
                stale_feed,
                alerted_feed,
                labeled_feed,
                article_ioc,
            ]
        )
        await session.flush()
        session.add_all(
            [
                _sighting(fresh_feed, provenance="feed", last_seen=fresh_feed.last_seen),
                _sighting(stale_feed, provenance="feed", last_seen=stale_feed.last_seen),
                _sighting(alerted_feed, provenance="feed", last_seen=alerted_feed.last_seen),
                _sighting(labeled_feed, provenance="feed", last_seen=labeled_feed.last_seen),
                _sighting(article_ioc, provenance="writeup", last_seen=article_ioc.last_seen, material=article_material),
                AlertEvent(ioc_id=alerted_feed.id, channel="telegram", alert_kind="immediate", sent_at=old),
                FeedbackRecord(
                    ioc_id=labeled_feed.id,
                    analyst_id="analyst",
                    verdict="false_positive",
                    timestamp=old,
                    channel="telegram",
                    source=labeled_feed.source,
                ),
            ]
        )
        await session.commit()

    result = await prune_retention(
        settings=RetentionSettings(
            unalerted_feed_ioc_ttl_days=5,
            alerted_ioc_ttl_days=90,
            article_ioc_ttl_days=30,
            source_material_ttl_days=5,
            keep_feedback_labeled=True,
        ),
        session_factory=db_session_factory,
        now=now,
    )

    async with db_session_factory() as session:
        remaining_iocs = {row.value for row in (await session.scalars(select(IOC))).all()}
        remaining_materials = {row.url for row in (await session.scalars(select(SourceMaterial))).all()}

    assert result.pruned_iocs == 1
    assert result.pruned_source_materials == 1
    assert "stale-feed.example" not in remaining_iocs
    assert {
        "fresh-feed.example",
        "alerted-feed.example",
        "labeled-feed.example",
        "article-linked.example",
    } <= remaining_iocs
    assert "https://rapid7.example/report" in remaining_materials
    assert "https://old.example/report" not in remaining_materials

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from sentinel.agents.scraper import RawIOC
from sentinel.agents.validator import ValidationAgent, get_corroboration, get_scoring_context
from sentinel.db.models import IOC, IOCSighting, SourceMaterial


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@pytest.fixture
def validation_skill(tmp_path: Path) -> Path:
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(
        """---
version: 1.0.0
last_updated: 2026-04-08
updated_by: test
---

# Validation Skill

## False Positive Rules
- Reject RFC1918, localhost, loopback, and documentation-only test values.
- pattern: benign.example

## Learner Updates
<!-- learner: append here -->
""",
        encoding="utf-8",
    )
    return skill_path


@pytest.fixture
def tranco_file(tmp_path: Path) -> Path:
    path = tmp_path / "tranco_top10k.txt"
    path.write_text("trusted-site.com\n", encoding="utf-8")
    return path


@pytest.fixture
def agent(validation_skill: Path, tranco_file: Path, db_session_factory) -> ValidationAgent:
    return ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=db_session_factory,
    )


@pytest.mark.asyncio
async def test_validator_persists_only_valid_unique_iocs(agent: ValidationAgent, db_session_factory) -> None:
    inputs = [
        RawIOC(
            value="8.8.8.8",
            type="ipv4",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="EXAMPLE.org",
            type="domain",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="https://example.org/login",
            type="url",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="D41D8CD98F00B204E9800998ECF8427E",
            type="md5",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="CVE-2026-12345",
            type="cve",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="8.8.8.8",
            type="ipv4",
            source="feed-b",
            source_trust=0.7,
            first_seen=datetime(2026, 4, 8, 11, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 11, 5, tzinfo=UTC),
        ),
    ]

    persisted = await agent.run(inputs)

    assert len(persisted) == 5
    assert {ioc.value for ioc in persisted} == {
        "8.8.8.8",
        "example.org",
        "https://example.org/login",
        "d41d8cd98f00b204e9800998ecf8427e",
        "CVE-2026-12345",
    }
    async with db_session_factory() as session:
        rows = list((await session.scalars(select(IOC))).all())
        assert len(rows) == 5
        assert len({ioc.dedupe_hash for ioc in rows}) == 5


@pytest.mark.asyncio
async def test_validator_preserves_lineage_for_corroborated_iocs(agent: ValidationAgent, db_session_factory) -> None:
    """Same IOC from two sources: one canonical row, two sightings, corroboration=2."""
    inputs = [
        RawIOC(
            value="8.8.8.8",
            type="ipv4",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
        ),
        RawIOC(
            value="8.8.8.8",
            type="ipv4",
            source="feed-b",
            source_trust=0.7,
            first_seen=datetime(2026, 4, 8, 11, 0, tzinfo=UTC),
            last_seen=datetime(2026, 4, 8, 11, 5, tzinfo=UTC),
        ),
    ]

    report = await agent.run_with_report(inputs)

    assert len(report.new_iocs) == 1
    assert report.sightings_recorded == 2
    row = report.new_iocs[0]
    # Canonical row's last_seen extends to the later source's observation.
    assert as_utc(row.last_seen) == datetime(2026, 4, 8, 11, 5, tzinfo=UTC)
    async with db_session_factory() as session:
        sightings = list((await session.scalars(select(IOCSighting))).all())
        assert {sighting.source for sighting in sightings} == {"feed-a", "feed-b"}
        assert all(sighting.ioc_id == row.id for sighting in sightings)
        corroboration = await get_corroboration(session, [row.id])
        assert corroboration[row.id] == 2


@pytest.mark.asyncio
async def test_validator_repeat_run_updates_sighting_not_duplicate(agent: ValidationAgent, db_session_factory) -> None:
    def make_input(last_seen: datetime) -> RawIOC:
        return RawIOC(
            value="evil.example.net",
            type="domain",
            source="feed-a",
            source_trust=0.9,
            first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
            last_seen=last_seen,
        )

    first_report = await agent.run_with_report([make_input(datetime(2026, 4, 8, 10, 5, tzinfo=UTC))])
    second_report = await agent.run_with_report([make_input(datetime(2026, 4, 9, 10, 5, tzinfo=UTC))])

    assert len(first_report.new_iocs) == 1
    assert second_report.new_iocs == []
    assert len(second_report.corroborated_iocs) == 1
    async with db_session_factory() as session:
        sightings = list((await session.scalars(select(IOCSighting))).all())
        assert len(sightings) == 1
        assert sightings[0].sighting_count == 2
        assert as_utc(sightings[0].last_seen) == datetime(2026, 4, 9, 10, 5, tzinfo=UTC)
        rows = list((await session.scalars(select(IOC))).all())
        assert len(rows) == 1
        assert as_utc(rows[0].last_seen) == datetime(2026, 4, 9, 10, 5, tzinfo=UTC)


@pytest.mark.asyncio
async def test_validator_records_writeup_provenance_and_material_link(
    agent: ValidationAgent, db_session_factory
) -> None:
    import uuid

    material_id = uuid.uuid4()
    inputs = [
        {
            "value": "203.0.114.7",
            "type": "ipv4",
            "source": "talos_blog",
            "source_trust": 0.6,
            "first_seen": "2026-04-08T10:00:00+00:00",
            "last_seen": "2026-04-08T10:00:00+00:00",
            "reference_url": "https://blog.example/campaign-writeup",
            "provenance": "writeup",
        }
    ]

    persisted = await agent.run(
        inputs, source_material_ids={"https://blog.example/campaign-writeup": material_id}
    )

    assert len(persisted) == 1
    async with db_session_factory() as session:
        sighting = await session.scalar(select(IOCSighting))
        assert sighting is not None
        assert sighting.provenance == "writeup"
        assert sighting.reference_url == "https://blog.example/campaign-writeup"
        assert sighting.source_material_id == material_id


@pytest.mark.asyncio
async def test_validator_rejects_false_positives_and_private_ranges(agent: ValidationAgent, db_session_factory) -> None:
    inputs = [
        {"value": "10.1.2.3", "type": "ipv4", "source": "feed", "source_trust": 0.5},
        {"value": "localhost", "type": "domain", "source": "feed", "source_trust": 0.5},
        {"value": "trusted-site.com", "type": "domain", "source": "feed", "source_trust": 0.5},
        {"value": "benign.example", "type": "domain", "source": "feed", "source_trust": 0.5},
        {"value": "ftp://example.org/malware", "type": "url", "source": "feed", "source_trust": 0.5},
        {"value": "999.1.1.1", "type": "ipv4", "source": "feed", "source_trust": 0.5},
        {"value": "2001:db8::1", "type": "ipv6", "source": "feed", "source_trust": 0.5},
    ]

    persisted = await agent.run(inputs)

    assert persisted == []
    async with db_session_factory() as session:
        assert list((await session.scalars(select(IOC))).all()) == []


@pytest.mark.asyncio
async def test_validator_deduplicates_against_existing_database_rows(agent: ValidationAgent, db_session_factory) -> None:
    first_batch = [
        {"value": "example.net", "type": "domain", "source": "feed-a", "source_trust": 0.5},
    ]
    second_batch = [
        {"value": "EXAMPLE.NET", "type": "domain", "source": "feed-b", "source_trust": 0.9},
    ]

    first_persisted = await agent.run(first_batch)
    second_persisted = await agent.run(second_batch)

    assert len(first_persisted) == 1
    assert second_persisted == []
    async with db_session_factory() as session:
        rows = list((await session.scalars(select(IOC))).all())
        assert len(rows) == 1
        # Lineage from the second source is preserved as a sighting.
        sightings = list((await session.scalars(select(IOCSighting))).all())
        assert {sighting.source for sighting in sightings} == {"feed-a", "feed-b"}


@pytest.mark.asyncio
async def test_validator_accepts_ipv6_and_sha256_iocs(agent: ValidationAgent) -> None:
    inputs = [
        {
            "value": "2606:4700:4700::1111",
            "type": "ipv6",
            "source": "feed-a",
            "source_trust": 0.8,
        },
        {
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "type": "sha256",
            "source": "feed-a",
            "source_trust": 0.8,
        },
    ]

    persisted = await agent.run(inputs)

    assert len(persisted) == 2
    assert {ioc.type for ioc in persisted} == {"ipv6", "sha256"}
    assert {ioc.value for ioc in persisted} == {
        "2606:4700:4700::1111",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }


def test_validator_rejects_generic_github_root_urls(agent: ValidationAgent) -> None:
    assert agent.normalize_ioc("url", "https://github.com/") is None
    assert agent.normalize_ioc("url", "https://bentleyvazquezpvey.github.io/") is None
    assert (
        agent.normalize_ioc("url", "https://github.com/antivirus-free-bitdefender")
        == "https://github.com/antivirus-free-bitdefender"
    )


def test_validator_allows_specific_paths_on_allowlisted_hosts(agent: ValidationAgent) -> None:
    assert agent.normalize_ioc("domain", "trusted-site.com") is None
    assert agent.normalize_ioc("url", "https://trusted-site.com/") is None
    assert agent.normalize_ioc("url", "https://trusted-site.com/malicious/path") == "https://trusted-site.com/malicious/path"


@pytest.mark.asyncio
async def test_validator_persists_source_link_title_and_related_cves(agent: ValidationAgent, db_session_factory) -> None:
    persisted = await agent.run(
        [
            RawIOC(
                value="example.org",
                type="domain",
                source="otx",
                source_trust=0.9,
                first_seen=datetime(2026, 4, 8, 10, 0, tzinfo=UTC),
                last_seen=datetime(2026, 4, 8, 10, 5, tzinfo=UTC),
                description="Stealer pulse referencing CVE-2026-12345",
                reference_url="https://otx.alienvault.com/pulse/123",
                attributes={"related_cves": ["CVE-2026-12345"], "pulse_name": "Stealer pulse"},
            )
        ]
    )

    assert len(persisted) == 1
    async with db_session_factory() as session:
        row = await session.scalar(select(IOC))
        assert row.source_title == "Stealer pulse referencing CVE-2026-12345"
        assert row.reference_url == "https://otx.alienvault.com/pulse/123"
        assert row.related_cves == ["CVE-2026-12345"]


@pytest.mark.asyncio
async def test_get_scoring_context_picks_strongest_provenance_and_counts_sources(
    db_session_factory,
) -> None:
    """An IOC seen by a plain feed and a curated writeup section should report
    the curated provenance and a corroboration count of 2."""
    import uuid

    ioc_id = uuid.uuid4()
    async with db_session_factory() as session:
        material = SourceMaterial(
            source="discovery:securelist.com",
            url="https://securelist.example/hellonet",
            title="HelloNet campaign",
            published_at=datetime(2026, 7, 1, tzinfo=UTC),
            extraction_status="extracted",
            extracted_ioc_count=14,
            metadata_json={},
        )
        session.add(material)
        await session.flush()
        session.add(
            IOC(
                id=ioc_id,
                value="45.155.204.9",
                dedupe_hash="hash-ctx",
                type="ipv4",
                source="threatfox",
                source_trust=0.94,
                first_seen=datetime(2026, 7, 1, tzinfo=UTC),
                last_seen=datetime(2026, 7, 1, tzinfo=UTC),
            )
        )
        session.add(
            IOCSighting(
                ioc_id=ioc_id,
                source="threatfox",
                source_trust=0.94,
                provenance="feed",
                first_seen=datetime(2026, 7, 1, tzinfo=UTC),
                last_seen=datetime(2026, 7, 1, tzinfo=UTC),
                lineage_hash="lineage-feed",
                attributes={},
            )
        )
        session.add(
            IOCSighting(
                ioc_id=ioc_id,
                source="discovery:securelist.com",
                source_trust=0.67,
                provenance="writeup",
                source_material_id=material.id,
                first_seen=datetime(2026, 7, 1, tzinfo=UTC),
                last_seen=datetime(2026, 7, 1, tzinfo=UTC),
                lineage_hash="lineage-writeup",
                attributes={"extraction_mode": "ioc_section"},
            )
        )
        await session.commit()

        context = await get_scoring_context(session, [ioc_id])

    entry = context[ioc_id]
    assert entry["corroboration_sources"] == 2
    assert entry["provenance"] == "writeup"
    assert entry["extraction_mode"] == "ioc_section"
    assert entry["article_ioc_count"] == 14

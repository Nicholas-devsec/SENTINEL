from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.agents.scraper import RawIOC
from sentinel.agents.validator import ValidationAgent
from sentinel.db.models import IOC


class FakeScalarResult:
    def __init__(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)


class FakeSession:
    def __init__(self, storage: list[IOC]) -> None:
        self.storage = storage
        self.pending: list[IOC] = []

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def scalar(self, statement):
        dedupe_hash = statement.compile().params.get("dedupe_hash_1")
        for item in self.storage:
            if item.dedupe_hash == dedupe_hash:
                return item
        return None

    async def scalars(self, statement):
        return FakeScalarResult(self.storage)

    def add(self, record: IOC) -> None:
        self.pending.append(record)

    async def commit(self) -> None:
        self.storage.extend(self.pending)
        self.pending = []

    async def refresh(self, record: IOC) -> None:
        return None


class FakeSessionFactory:
    def __init__(self) -> None:
        self.storage: list[IOC] = []

    def __call__(self) -> FakeSession:
        return FakeSession(self.storage)


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


@pytest.mark.asyncio
async def test_validator_persists_only_valid_unique_iocs(
    validation_skill: Path,
    tranco_file: Path,
) -> None:
    session_factory = FakeSessionFactory()
    agent = ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=session_factory,
    )
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
    assert len(session_factory.storage) == 5
    assert len({ioc.dedupe_hash for ioc in session_factory.storage}) == 5


@pytest.mark.asyncio
async def test_validator_rejects_false_positives_and_private_ranges(
    validation_skill: Path,
    tranco_file: Path,
) -> None:
    session_factory = FakeSessionFactory()
    agent = ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=session_factory,
    )
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
    assert session_factory.storage == []


@pytest.mark.asyncio
async def test_validator_deduplicates_against_existing_database_rows(
    validation_skill: Path,
    tranco_file: Path,
) -> None:
    session_factory = FakeSessionFactory()
    agent = ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=session_factory,
    )
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
    assert len(session_factory.storage) == 1


@pytest.mark.asyncio
async def test_validator_accepts_ipv6_and_sha256_iocs(
    validation_skill: Path,
    tranco_file: Path,
) -> None:
    session_factory = FakeSessionFactory()
    agent = ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=session_factory,
    )
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


@pytest.mark.asyncio
async def test_validator_persists_source_link_title_and_related_cves(
    validation_skill: Path,
    tranco_file: Path,
) -> None:
    session_factory = FakeSessionFactory()
    agent = ValidationAgent(
        skill_path=str(validation_skill),
        tranco_path=str(tranco_file),
        session_factory=session_factory,
    )

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
    row = session_factory.storage[0]
    assert row.source_title == "Stealer pulse referencing CVE-2026-12345"
    assert row.reference_url == "https://otx.alienvault.com/pulse/123"
    assert row.related_cves == ["CVE-2026-12345"]

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel.db.migrations import ensure_schema


LEGACY_FEEDBACK_TABLE = """
CREATE TABLE feedback_records (
    id CHAR(32) PRIMARY KEY,
    ioc_id CHAR(32) NOT NULL,
    analyst_id VARCHAR(255) NOT NULL,
    verdict VARCHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL,
    channel VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


@pytest.mark.asyncio
async def test_ensure_schema_adds_new_columns_to_legacy_tables(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/legacy.db")
    try:
        # Simulate a database created before the lineage upgrade.
        async with engine.begin() as connection:
            await connection.execute(text(LEGACY_FEEDBACK_TABLE))

        applied = await ensure_schema(engine)

        assert any("feedback_records ADD COLUMN source" in statement for statement in applied)
        # New tables exist and legacy table accepted the new column.
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO feedback_records (id, ioc_id, analyst_id, verdict, timestamp, channel, source) "
                     "VALUES ('x', 'y', 'a', 'confirmed', CURRENT_TIMESTAMP, 'telegram', 'threatfox')")
            )
            for table in ("iocs", "ioc_sightings", "source_materials", "experiment_logs", "schema_migrations"):
                await connection.execute(text(f"SELECT * FROM {table} LIMIT 1"))
            migration_rows = list(
                (
                    await connection.execute(
                        text("SELECT migration_id FROM schema_migrations ORDER BY migration_id")
                    )
                ).scalars()
            )
            assert "feedback_records.source" in migration_rows

        # Idempotent: second run applies nothing.
        assert await ensure_schema(engine) == []
    finally:
        await engine.dispose()

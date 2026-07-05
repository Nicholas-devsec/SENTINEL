"""Additive schema migration for existing SENTINEL databases.

`Base.metadata.create_all` creates missing tables but never adds columns to
tables that already exist. This module inspects the live schema and issues
`ALTER TABLE ... ADD COLUMN` for columns introduced after a database was
first created, so upgrades stay non-destructive without requiring a full
Alembic setup yet.

TODO(alembic): replace with versioned Alembic migrations once the schema
stabilizes; alembic is already in requirements.txt.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel.db.models import Base

logger = logging.getLogger(__name__)

# table -> {column_name: SQL type usable in ADD COLUMN on sqlite and postgres}
ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    "iocs": {
        "vt_ratio": "FLOAT",
    },
    "feedback_records": {
        "source": "VARCHAR(255)",
    },
    "experiment_logs": {
        "eval_mode": "VARCHAR(32)",
        "target": "VARCHAR(255)",
        "details": "JSON",
    },
}


def _missing_columns(sync_connection) -> list[tuple[str, str, str]]:
    inspector = inspect(sync_connection)
    existing_tables = set(inspector.get_table_names())
    missing: list[tuple[str, str, str]] = []
    for table, columns in ADDITIVE_COLUMNS.items():
        if table not in existing_tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, sql_type in columns.items():
            if name not in existing:
                missing.append((table, name, sql_type))
    return missing


async def ensure_schema(engine: AsyncEngine) -> list[str]:
    """Create missing tables and add missing columns. Returns applied ALTERs."""
    applied: list[str] = []
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        missing = await connection.run_sync(_missing_columns)
        for table, column, sql_type in missing:
            statement = f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"
            await connection.execute(text(statement))
            applied.append(statement)
            logger.info("Applied additive migration: %s", statement)
    return applied

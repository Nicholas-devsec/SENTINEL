from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sentinel.db.models import Base


@pytest.fixture
def smoke_fixture() -> str:
    return "sentinel"


@pytest_asyncio.fixture
async def db_session_factory(tmp_path):
    """Real async sqlite database with the full SENTINEL schema."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'sentinel-test.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    try:
        yield factory
    finally:
        await engine.dispose()

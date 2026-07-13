from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from sentinel.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    settings = get_settings()
    engine_url = make_url(settings.db.url)
    engine_kwargs = {
        "echo": False,
        "future": True,
        "pool_pre_ping": settings.db.pool_pre_ping,
    }
    # SQLite needs a different pool model and does not benefit from the same
    # long-lived connection tuning as Postgres.
    if not engine_url.drivername.startswith("sqlite"):
        engine_kwargs.update(
            {
                "pool_recycle": settings.db.pool_recycle_seconds,
                "pool_size": settings.db.pool_size,
                "max_overflow": settings.db.max_overflow,
            }
        )
    return create_async_engine(settings.db.url, **engine_kwargs)


@lru_cache(maxsize=1)
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=get_engine(), expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_session_factory()() as session:
        yield session


def AsyncSessionFactory() -> AsyncSession:
    return get_session_factory()()


engine = get_engine

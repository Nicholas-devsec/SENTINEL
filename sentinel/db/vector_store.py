from __future__ import annotations

from typing import Any


class VectorStore:
    """Minimal ChromaDB wrapper scaffold for later IOC clustering work."""

    def __init__(self, collection_name: str = "ioc-embeddings") -> None:
        self.collection_name = collection_name

    async def upsert(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError("VectorStore is scaffolded in Prompt 1 and implemented later.")


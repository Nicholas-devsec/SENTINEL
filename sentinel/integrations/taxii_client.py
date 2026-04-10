from __future__ import annotations

from collections.abc import Callable
from typing import Any

from taxii2client.v21 import Collection


class TaxiiFeedClient:
    """Thin wrapper around TAXII collection access for easier testing."""

    def __init__(self, collection_factory: Callable[..., Any] | None = None) -> None:
        self.collection_factory = collection_factory or Collection

    def get_objects(self, collection_url: str, *, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
        collection = self.collection_factory(collection_url, headers=headers or {})
        response = collection.get_objects()
        return list(response.get("objects", []))

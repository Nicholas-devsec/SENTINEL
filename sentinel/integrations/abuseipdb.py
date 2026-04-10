from __future__ import annotations

from typing import Any

import httpx


class AbuseIPDBClient:
    """Async AbuseIPDB REST client."""

    def __init__(self, api_key: str, *, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = api_key
        self.client = client or httpx.AsyncClient(base_url="https://api.abuseipdb.com/api/v2", timeout=30.0)
        self._owns_client = client is None

    async def lookup_ip(self, value: str) -> dict[str, Any]:
        response = await self.client.get(
            "/check",
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()


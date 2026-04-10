from __future__ import annotations

from typing import Any

import httpx


class CrowdStrikeClient:
    """Minimal async Falcon IOC ingestion client."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        base_url: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.AsyncClient(base_url=self.base_url, timeout=30.0)
        self._owns_client = client is None
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        response = await self.client.post(
            "/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
        )
        response.raise_for_status()
        payload = response.json()
        self._access_token = payload["access_token"]
        return self._access_token

    async def push_ioc(self, payload: dict[str, Any]) -> dict[str, Any]:
        token = self._access_token or await self._authenticate()
        response = await self.client.post(
            "/indicators/entities/iocs/v1",
            json={"indicators": [payload]},
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

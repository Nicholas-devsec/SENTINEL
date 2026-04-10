from __future__ import annotations

import asyncio
from typing import Any


class ShodanClient:
    """Async wrapper around the Shodan SDK."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def lookup_host(self, value: str) -> dict[str, Any]:
        import shodan

        client = shodan.Shodan(self.api_key)
        return await asyncio.to_thread(client.host, value)

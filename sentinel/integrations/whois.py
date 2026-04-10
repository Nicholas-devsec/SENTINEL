from __future__ import annotations

import asyncio
from typing import Any


class WhoisClient:
    """Async wrapper around python-whois."""

    async def lookup(self, value: str) -> dict[str, Any]:
        import whois

        result = await asyncio.to_thread(whois.whois, value)
        if hasattr(result, "data"):
            return dict(result.data)
        return dict(result)

from __future__ import annotations

import asyncio
from typing import Any


class VirusTotalClient:
    """Async wrapper around vt-py for IOC lookups."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def lookup_ioc(self, ioc_type: str, value: str) -> dict[str, Any]:
        import vt

        async def _fetch() -> dict[str, Any]:
            async with vt.Client(self.api_key) as client:
                object_path = self._build_object_path(ioc_type=ioc_type, value=value)
                result = await client.get_object_async(object_path)
                return getattr(result, "to_dict", lambda: dict(result))()

        return await _fetch()

    def _build_object_path(self, *, ioc_type: str, value: str) -> str:
        normalized_type = ioc_type.lower()
        if normalized_type == "url":
            import base64

            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").strip("=")
            return f"/urls/{url_id}"
        if normalized_type == "domain":
            return f"/domains/{value}"
        if normalized_type in {"ipv4", "ipv6"}:
            return f"/ip_addresses/{value}"
        return f"/files/{value}"

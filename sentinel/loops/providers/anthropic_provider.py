from __future__ import annotations

from anthropic import AsyncAnthropic

from sentinel.config import AnthropicSettings
from sentinel.loops.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    def __init__(self, settings: AnthropicSettings) -> None:
        self.settings = settings
        self.client = AsyncAnthropic(api_key=settings.api_key)

    async def complete(self, prompt: str) -> str:
        response = await self.client.messages.create(
            model=self.settings.model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )


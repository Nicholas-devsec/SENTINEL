from __future__ import annotations

from openai import AsyncOpenAI

from sentinel.config import OpenAISettings
from sentinel.loops.providers.base import LLMProvider


class OpenAIProvider(LLMProvider):
    def __init__(self, settings: OpenAISettings, *, client: AsyncOpenAI | None = None) -> None:
        self.settings = settings
        self.client = client or AsyncOpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url or None,
        )

    async def complete(self, prompt: str) -> str:
        response = await self.client.responses.create(
            model=self.settings.model,
            input=prompt,
        )
        output_text = getattr(response, "output_text", None)
        if output_text:
            return output_text
        parts: list[str] = []
        for item in getattr(response, "output", []) or []:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if text:
                    parts.append(text)
        return "".join(parts)

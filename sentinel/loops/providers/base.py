from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str) -> str:
        """Return a completion for the provided prompt."""


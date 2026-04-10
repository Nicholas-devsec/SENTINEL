from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseAgent(ABC):
    """Base class for all SENTINEL agents with skill hot-reload support."""

    def __init__(self, skill_path: str | Path, *, logger: logging.Logger | None = None) -> None:
        self.skill_path = Path(skill_path)
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.skill_prompt = self._read_skill_file()

    def _read_skill_file(self) -> str:
        return self.skill_path.read_text(encoding="utf-8")

    def reload_skill(self) -> str:
        self.skill_prompt = self._read_skill_file()
        self.logger.info("Reloaded skill file from %s", self.skill_path)
        return self.skill_prompt

    @abstractmethod
    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run the agent's asynchronous workload."""


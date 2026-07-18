from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.config import SentinelSettings


@dataclass(frozen=True, slots=True)
class AlertPolicy:
    immediate_min_score: float
    curated_immediate_min_score: float
    corroborated_context_min_score: float
    digest_min_score: float
    curated_digest_min_score: float
    digest_backfill_min_score: float

    def _provenance(self, item: dict[str, Any]) -> str:
        return str(item.get("provenance") or item.get("attributes", {}).get("provenance") or "").strip().lower()

    def _extraction_mode(self, item: dict[str, Any]) -> str:
        return str(item.get("extraction_mode") or item.get("attributes", {}).get("extraction_mode") or "").strip().lower()

    def _corroboration_sources(self, item: dict[str, Any]) -> int:
        try:
            return int(item.get("corroboration_sources", 1) or 1)
        except (TypeError, ValueError):
            return 1

    def _is_curated_context(self, item: dict[str, Any]) -> bool:
        return (
            self._provenance(item) in {"writeup", "discovery"}
            and self._extraction_mode(item) == "ioc_section"
        )

    def _is_corroborated_context(self, item: dict[str, Any]) -> bool:
        return (
            self._provenance(item) in {"writeup", "discovery"}
            and self._corroboration_sources(item) >= 2
        )

    def qualifies_immediate(self, item: dict[str, Any], *, is_web_discovery: bool = False) -> bool:
        score = float(item.get("risk_score", 0.0))
        if score >= self.immediate_min_score:
            return True
        if self._is_curated_context(item) and score >= self.curated_immediate_min_score:
            return True
        if self._is_corroborated_context(item) and score >= self.corroborated_context_min_score:
            return True
        return False

    def qualifies_digest(self, item: dict[str, Any], *, is_web_discovery: bool = False) -> bool:
        score = float(item.get("risk_score", 0.0))
        if score >= self.digest_min_score:
            return True
        if self._is_curated_context(item) and score >= self.curated_digest_min_score:
            return True
        return False

    def qualifies_digest_backfill(self, item: dict[str, Any], *, is_web_discovery: bool = False) -> bool:
        score = float(item.get("risk_score", 0.0))
        if score >= self.digest_backfill_min_score:
            return True
        if self._is_curated_context(item) and score >= min(self.curated_digest_min_score, self.digest_backfill_min_score):
            return True
        return False


def build_alert_policy(settings: SentinelSettings) -> AlertPolicy:
    return AlertPolicy(
        immediate_min_score=float(settings.thresholds.alert_score),
        curated_immediate_min_score=float(settings.thresholds.curated_immediate_score),
        corroborated_context_min_score=float(settings.thresholds.corroborated_immediate_score),
        digest_min_score=float(settings.thresholds.digest_score),
        curated_digest_min_score=float(settings.thresholds.curated_digest_score),
        digest_backfill_min_score=float(settings.thresholds.digest_backfill_score),
    )

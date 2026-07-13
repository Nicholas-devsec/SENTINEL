from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.config import SentinelSettings


HIGH_SEVERITY_MIN_SCORE = 70.0
MEDIUM_SEVERITY_MIN_SCORE = 50.0


@dataclass(frozen=True, slots=True)
class AlertPolicy:
    immediate_min_score: float
    digest_min_score: float

    def qualifies_immediate(self, item: dict[str, Any], *, is_web_discovery: bool = False) -> bool:
        return float(item.get("risk_score", 0.0)) >= self.immediate_min_score

    def qualifies_digest(self, item: dict[str, Any], *, is_web_discovery: bool = False) -> bool:
        return float(item.get("risk_score", 0.0)) >= self.digest_min_score


def build_alert_policy(settings: SentinelSettings) -> AlertPolicy:
    immediate_min_score = max(float(settings.thresholds.alert_score), HIGH_SEVERITY_MIN_SCORE)
    return AlertPolicy(
        immediate_min_score=immediate_min_score,
        digest_min_score=MEDIUM_SEVERITY_MIN_SCORE,
    )

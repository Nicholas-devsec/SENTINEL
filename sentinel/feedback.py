from __future__ import annotations

from typing import Final


CONFIRMED: Final = "confirmed"
LOW_LEVEL_TRUE_POSITIVE: Final = "low_level_true_positive"
FALSE_POSITIVE: Final = "false_positive"
NEEDS_REVIEW: Final = "needs_review"

POSITIVE_VERDICTS: Final = frozenset({CONFIRMED, LOW_LEVEL_TRUE_POSITIVE})
LEARNING_VERDICTS: Final = frozenset({CONFIRMED, LOW_LEVEL_TRUE_POSITIVE, FALSE_POSITIVE})
DISCOVERY_MEMORY_VERDICTS: Final = frozenset({CONFIRMED, LOW_LEVEL_TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_REVIEW})

LOW_LEVEL_TRUE_POSITIVE_WEIGHT: Final = 0.5


def normalize_verdict(verdict: str) -> str:
    normalized = str(verdict or "").strip().lower()
    return {
        "confirm_threat": CONFIRMED,
        "true_positive": CONFIRMED,
        "tp": CONFIRMED,
        CONFIRMED: CONFIRMED,
        "low_level_tp": LOW_LEVEL_TRUE_POSITIVE,
        "low_level_true_positive": LOW_LEVEL_TRUE_POSITIVE,
        "low-level_true_positive": LOW_LEVEL_TRUE_POSITIVE,
        "low-level true positive": LOW_LEVEL_TRUE_POSITIVE,
        "low_level true positive": LOW_LEVEL_TRUE_POSITIVE,
        FALSE_POSITIVE: FALSE_POSITIVE,
        "fp": FALSE_POSITIVE,
        NEEDS_REVIEW: NEEDS_REVIEW,
    }.get(normalized, normalized)


def positive_weight(verdict: str) -> float:
    normalized = normalize_verdict(verdict)
    if normalized == CONFIRMED:
        return 1.0
    if normalized == LOW_LEVEL_TRUE_POSITIVE:
        return LOW_LEVEL_TRUE_POSITIVE_WEIGHT
    return 0.0


def scoring_target(verdict: str) -> float:
    normalized = normalize_verdict(verdict)
    if normalized == CONFIRMED:
        return 100.0
    if normalized == LOW_LEVEL_TRUE_POSITIVE:
        return 65.0
    if normalized == NEEDS_REVIEW:
        return 50.0
    return 0.0

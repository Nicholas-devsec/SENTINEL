"""Replay evaluation for the source Karpathy loop.

The previous live metric relied on thresholded alert decisions alone, which
made the learning surface flat whenever a trust edit failed to flip any alerts.
This evaluator keeps the same replay mechanics but optimizes a continuous
proper-scoring objective instead:

1. Load the feedback-labeled IOC window (analyst verdicts are ground truth).
2. Recompute each IOC's risk score under the *current* skill-file trust
   scores. The enrichment scoring formula is linear in source trust
   (risk = 100 * (w_vt*vt + w_abuse*abuse + w_trust*trust + w_recency*rec)),
   so the exact replayed score is
       risk_new = risk_stored + w_trust * 100 * (trust_skill - trust_stored)
   using the per-IOC trust snapshot stored at ingestion time.
3. Convert replayed risk into a pseudo-probability `p = risk / 100` and score
   it against analyst verdict targets using a weighted Brier-style loss:
   confirmed=1.0, low_level_true_positive=0.65, false_positive=0.0.

Thresholded confusion statistics are still recorded as guardrails, but the loop
learns from continuous score improvement even when no hard alert flips occur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select

from sentinel.alert_policy import AlertPolicy
from sentinel.db.models import IOC, FeedbackRecord
from sentinel.feedback import FALSE_POSITIVE, LEARNING_VERDICTS, normalize_verdict, positive_weight, scoring_target


TRUST_SCORE_LINE_RE = re.compile(
    r"^-\s+(?P<name>[a-zA-Z0-9_:-]+):\s*(?P<value>[0-9]*\.?[0-9]+)\s*$", re.MULTILINE
)


@dataclass(slots=True)
class ReplayEvalResult:
    metric: float
    brier_score: float
    precision: float
    recall: float
    true_positive: float
    false_positive: float
    false_negative: float
    true_negative: float
    total_labeled: int
    window_hours: int
    alert_threshold: float
    trust_weight: float
    trust_scores: dict[str, float] = field(default_factory=dict)
    per_source: dict[str, dict[str, float]] = field(default_factory=dict)

    def to_details(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "brier_score": self.brier_score,
            "precision": self.precision,
            "recall": self.recall,
            "confusion": {
                "tp": self.true_positive,
                "fp": self.false_positive,
                "fn": self.false_negative,
                "tn": self.true_negative,
            },
            "total_labeled": self.total_labeled,
            "window_hours": self.window_hours,
            "alert_threshold": self.alert_threshold,
            "trust_weight": self.trust_weight,
            "trust_scores": self.trust_scores,
            "per_source": self.per_source,
        }


def parse_trust_scores(skill_text: str) -> dict[str, float]:
    return {
        match.group("name").lower(): float(match.group("value"))
        for match in TRUST_SCORE_LINE_RE.finditer(skill_text)
    }


@dataclass(slots=True)
class LabeledIOC:
    """The minimum needed to replay one labeled indicator."""

    source: str
    source_trust_stored: float
    risk_score_stored: float
    verdict: str


class ReplayEvaluator:
    def __init__(
        self,
        *,
        session_factory: Any,
        skill_path: str | Path,
        alert_policy: AlertPolicy,
        trust_weight: float,
        window_hours: int = 14 * 24,
        beta: float = 0.5,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.skill_path = Path(skill_path)
        self.alert_policy = alert_policy
        self.alert_threshold = float(alert_policy.immediate_min_score)
        self.trust_weight = float(trust_weight)
        self.window_hours = window_hours
        self.beta = beta
        self.now_fn = now_fn or (lambda: datetime.now(UTC))

    async def _load_labeled(self) -> list[LabeledIOC]:
        cutoff = self.now_fn() - timedelta(hours=self.window_hours)
        async with self.session_factory() as session:
            if hasattr(session, "labeled_rows"):
                return [
                    LabeledIOC(**{**row, "verdict": normalize_verdict(row["verdict"])})
                    for row in session.labeled_rows
                    if normalize_verdict(row["verdict"]) in LEARNING_VERDICTS
                ]
            query = (
                select(IOC, FeedbackRecord)
                .join(FeedbackRecord, FeedbackRecord.ioc_id == IOC.id)
                .where(FeedbackRecord.timestamp >= cutoff)
                .where(FeedbackRecord.verdict.in_(sorted(LEARNING_VERDICTS)))
                .order_by(FeedbackRecord.timestamp)
            )
            rows = (await session.execute(query)).all()
        # Latest verdict wins when an IOC has been re-triaged.
        latest: dict[Any, LabeledIOC] = {}
        for ioc, feedback in rows:
            latest[ioc.id] = LabeledIOC(
                source=(feedback.source or ioc.source),
                source_trust_stored=float(ioc.source_trust or 0.0),
                risk_score_stored=float(ioc.risk_score or 0.0),
                verdict=feedback.verdict,
            )
        return list(latest.values())

    def _replay_score(self, item: LabeledIOC, trust_scores: dict[str, float]) -> float:
        trust_now = trust_scores.get(item.source.lower(), item.source_trust_stored)
        adjusted = item.risk_score_stored + self.trust_weight * 100.0 * (trust_now - item.source_trust_stored)
        return max(0.0, min(100.0, adjusted))

    def _weighted_brier_metric(self, labeled: list[LabeledIOC], trust_scores: dict[str, float]) -> float:
        weighted_error = 0.0
        total_weight = 0.0
        for item in labeled:
            predicted_probability = self._replay_score(item, trust_scores) / 100.0
            target_probability = scoring_target(item.verdict) / 100.0
            if item.verdict == FALSE_POSITIVE:
                sample_weight = 1.0
            else:
                sample_weight = max(positive_weight(item.verdict), 1e-9)
            weighted_error += sample_weight * ((predicted_probability - target_probability) ** 2)
            total_weight += sample_weight
        if total_weight <= 0.0:
            return 0.0
        brier_score = weighted_error / total_weight
        return 1.0 - brier_score

    async def sweep(self, source: str, candidate_trusts: list[float]) -> dict[float, float]:
        """Replay metric for each candidate trust value of one source.

        This is the deterministic baseline the LLM proposal is judged against:
        because the replay metric is directly computable for any trust value,
        the grid optimum is known, and an experiment log can show whether the
        proposed trust matched it.
        """
        trust_scores = parse_trust_scores(self.skill_path.read_text(encoding="utf-8"))
        labeled = await self._load_labeled()
        results: dict[float, float] = {}
        for candidate in candidate_trusts:
            clamped = round(max(0.0, min(1.0, float(candidate))), 2)
            overridden = {**trust_scores, source.lower(): clamped}
            results[clamped] = self._weighted_brier_metric(labeled, overridden)
        return results

    async def evaluate(self) -> ReplayEvalResult:
        trust_scores = parse_trust_scores(self.skill_path.read_text(encoding="utf-8"))
        labeled = await self._load_labeled()
        tp = fp = fn = tn = 0.0
        per_source: dict[str, dict[str, float]] = {}
        for item in labeled:
            predicted_alert = self._replay_score(item, trust_scores) >= self.alert_threshold
            pos_weight = positive_weight(item.verdict)
            bucket = per_source.setdefault(
                item.source, {"tp": 0.0, "fp": 0.0, "fn": 0.0, "tn": 0.0}
            )
            if predicted_alert and pos_weight > 0.0:
                tp += pos_weight
                bucket["tp"] += pos_weight
            elif predicted_alert and item.verdict == FALSE_POSITIVE:
                fp += 1.0
                bucket["fp"] += 1.0
            elif not predicted_alert and pos_weight > 0.0:
                fn += pos_weight
                bucket["fn"] += pos_weight
            else:
                tn += 1.0
                bucket["tn"] += 1.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        metric = self._weighted_brier_metric(labeled, trust_scores)
        brier_score = 1.0 - metric
        return ReplayEvalResult(
            metric=metric,
            brier_score=brier_score,
            precision=precision,
            recall=recall,
            true_positive=tp,
            false_positive=fp,
            false_negative=fn,
            true_negative=tn,
            total_labeled=len(labeled),
            window_hours=self.window_hours,
            alert_threshold=self.alert_threshold,
            trust_weight=self.trust_weight,
            trust_scores=trust_scores,
            per_source=per_source,
        )

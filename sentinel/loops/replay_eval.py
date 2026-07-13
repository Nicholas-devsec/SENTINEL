"""Replay evaluation for the source Karpathy loop.

The previous live metric was the historical confirmed/false_positive ratio for
a source — a number that cannot change when a trust score is edited, so the
loop could never actually learn. This evaluator makes trust edits observable:

1. Load the feedback-labeled IOC window (analyst verdicts are ground truth).
2. Recompute each IOC's risk score under the *current* skill-file trust
   scores. The enrichment scoring formula is linear in source trust
   (risk = 100 * (w_vt*vt + w_abuse*abuse + w_trust*trust + w_recency*rec)),
   so the exact replayed score is
       risk_new = risk_stored + w_trust * 100 * (trust_skill - trust_stored)
   using the per-IOC trust snapshot stored at ingestion time.
3. Re-apply the alert threshold and score would-have-alerted against verdicts
   with F-beta (beta=0.5: precision-weighted, because alert noise is the cost
   analysts actually feel, but recall still counts so the loop cannot win by
   muting every source).

Raising a noisy source's trust pushes its false positives back above the
threshold and the metric drops; lowering it suppresses them and the metric
rises — unless it also suppresses confirmed threats, which recall penalizes.
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


TRUST_SCORE_LINE_RE = re.compile(
    r"^-\s+(?P<name>[a-zA-Z0-9_:-]+):\s*(?P<value>[0-9]*\.?[0-9]+)\s*$", re.MULTILINE
)


@dataclass(slots=True)
class ReplayEvalResult:
    metric: float
    precision: float
    recall: float
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    total_labeled: int
    window_hours: int
    alert_threshold: float
    trust_weight: float
    trust_scores: dict[str, float] = field(default_factory=dict)
    per_source: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_details(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
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


def _f_beta(precision: float, recall: float, beta: float) -> float:
    if precision == 0.0 and recall == 0.0:
        return 0.0
    beta_sq = beta * beta
    return (1 + beta_sq) * precision * recall / (beta_sq * precision + recall)


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
                return [LabeledIOC(**row) for row in session.labeled_rows]
            query = (
                select(IOC, FeedbackRecord)
                .join(FeedbackRecord, FeedbackRecord.ioc_id == IOC.id)
                .where(FeedbackRecord.timestamp >= cutoff)
                .where(FeedbackRecord.verdict.in_(["confirmed", "false_positive"]))
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

    async def evaluate(self) -> ReplayEvalResult:
        trust_scores = parse_trust_scores(self.skill_path.read_text(encoding="utf-8"))
        labeled = await self._load_labeled()
        tp = fp = fn = tn = 0
        per_source: dict[str, dict[str, int]] = {}
        for item in labeled:
            predicted_alert = self._replay_score(item, trust_scores) >= self.alert_threshold
            actually_bad = item.verdict == "confirmed"
            bucket = per_source.setdefault(
                item.source, {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
            )
            if predicted_alert and actually_bad:
                tp += 1
                bucket["tp"] += 1
            elif predicted_alert and not actually_bad:
                fp += 1
                bucket["fp"] += 1
            elif not predicted_alert and actually_bad:
                fn += 1
                bucket["fn"] += 1
            else:
                tn += 1
                bucket["tn"] += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        metric = _f_beta(precision, recall, self.beta)
        return ReplayEvalResult(
            metric=metric,
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

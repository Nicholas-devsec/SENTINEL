from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sqlalchemy import select

from sentinel.alert_policy import build_alert_policy
from sentinel.db.models import FeedbackRecord, IOC
from sentinel.feedback import FALSE_POSITIVE, LEARNING_VERDICTS, normalize_verdict, positive_weight
from sentinel.loops.karpathy_loop import ExperimentProposal, KeepDecision, ThreatIntelLoop
from sentinel.loops.replay_eval import ReplayEvaluator


TRUST_SCORE_LINE_RE = re.compile(r"^(-\s+)(?P<name>[a-zA-Z0-9_:-]+)(:\s*)(?P<value>[0-9]*\.?[0-9]+)\s*$", re.MULTILINE)


@dataclass(slots=True)
class SourceFeedbackStats:
    source_name: str
    confirmed: int
    low_level_true_positive: int
    false_positive: int

    @property
    def feedback_count(self) -> int:
        return self.confirmed + self.low_level_true_positive + self.false_positive

    @property
    def positive_weight(self) -> float:
        return self.confirmed + 0.5 * self.low_level_true_positive

    @property
    def precision(self) -> float:
        total = self.positive_weight + self.false_positive
        return self.positive_weight / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = self.positive_weight + self.false_positive
        return self.false_positive / total if total else 0.0


class SourceQualityLoop(ThreatIntelLoop):
    loop_type = "source"
    eval_mode = "replay"

    def __init__(self, *args, target_source: str | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.target_source = target_source
        self._last_feedback_count: int | None = None
        self._last_source_feedback_stats: SourceFeedbackStats | None = None
        self._last_trust_before: float | None = None
        self._last_trust_after: float | None = None
        self._last_eval_details: dict | None = None

    async def _source_feedback_stats(self) -> SourceFeedbackStats:
        if self.target_source is None:
            raise ValueError("SourceQualityLoop requires a target_source for live optimization.")
        async with self.session_factory() as session:
            if hasattr(session, "feedback_rows"):
                rows = [
                    {**row, "verdict": normalize_verdict(row["verdict"])}
                    for row in session.feedback_rows
                    if row.get("source") == self.target_source and normalize_verdict(row["verdict"]) in LEARNING_VERDICTS
                ]
            else:
                cutoff = self.now_fn() - __import__("datetime").timedelta(hours=48)
                query = (
                    select(FeedbackRecord.verdict, FeedbackRecord.source, IOC.source)
                    .join(IOC, FeedbackRecord.ioc_id == IOC.id)
                    .where(FeedbackRecord.timestamp >= cutoff)
                    .where(FeedbackRecord.verdict.in_(sorted(LEARNING_VERDICTS)))
                )
                rows = [
                    {"verdict": verdict, "source": (feedback_source or ioc_source)}
                    for verdict, feedback_source, ioc_source in (await session.execute(query)).all()
                ]
                rows = [row for row in rows if row.get("source") == self.target_source]
        confirmed = sum(1 for row in rows if positive_weight(row["verdict"]) == 1.0)
        low_level_true_positive = sum(1 for row in rows if 0.0 < positive_weight(row["verdict"]) < 1.0)
        false_positive = sum(1 for row in rows if row["verdict"] == FALSE_POSITIVE)
        stats = SourceFeedbackStats(
            source_name=self.target_source,
            confirmed=confirmed,
            low_level_true_positive=low_level_true_positive,
            false_positive=false_positive,
        )
        self._last_feedback_count = stats.feedback_count
        self._last_source_feedback_stats = stats
        return stats

    def current_trust(self, source_name: str | None = None) -> float:
        target = source_name or self.target_source
        if target is None:
            raise ValueError("SourceQualityLoop requires a target_source to read trust scores.")
        content = self.skill_path.read_text(encoding="utf-8")
        for match in TRUST_SCORE_LINE_RE.finditer(content):
            if match.group("name") == target:
                return float(match.group("value"))
        raise ValueError(f"Trust score for source '{target}' not found in {self.skill_path}")

    def _build_replay_evaluator(self) -> ReplayEvaluator:
        return ReplayEvaluator(
            session_factory=self.session_factory,
            skill_path=self.skill_path,
            alert_policy=build_alert_policy(self.settings),
            trust_weight=float(self.settings.enrichment.weights.source_trust),
            window_hours=int(self.settings.karpathy.replay_window_hours),
            now_fn=self.now_fn,
        )

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        # Replay: recompute labeled-window alerting under the trust scores
        # currently in the skill file, so a trust patch changes this number.
        evaluator = self._build_replay_evaluator()
        result = await evaluator.evaluate()
        self._last_eval_details = result.to_details()
        if self.target_source is not None:
            current_trust = result.trust_scores.get(self.target_source)
            if current_trust is not None:
                # Deterministic baseline: sweep the same +/-0.05 action space
                # the LLM is allowed, so every experiment log records how the
                # proposal compares to the known grid optimum.
                grid = sorted(
                    {
                        round(max(0.0, min(1.0, current_trust + step / 100.0)), 2)
                        for step in range(-5, 6)
                    }
                )
                sweep = await evaluator.sweep(self.target_source, grid)
                best_trust = max(
                    sweep,
                    key=lambda trust: (sweep[trust], -abs(trust - current_trust)),
                )
                self._last_eval_details["trust_sweep"] = {
                    "grid": {f"{trust:.2f}": round(metric, 4) for trust, metric in sweep.items()},
                    "grid_best_trust": best_trust,
                    "grid_best_metric": round(sweep[best_trust], 4),
                }
            # Keep feedback_count reporting for the run report.
            await self._source_feedback_stats()
        return result.metric

    def _build_prompt(self, experiment_number: int, current_skill: str, history: list[dict[str, object]]) -> str:
        if self.target_source is None:
            raise ValueError("SourceQualityLoop requires a target_source for prompt building.")
        current_trust = self.current_trust(self.target_source)
        details = dict(self._last_eval_details or {})
        stats = self._last_source_feedback_stats
        feedback_snapshot = (
            {
                "confirmed": stats.confirmed,
                "low_level_true_positive": stats.low_level_true_positive,
                "false_positive": stats.false_positive,
                "weighted_precision": round(stats.precision, 4),
                "false_positive_rate": round(stats.false_positive_rate, 4),
                "feedback_count": stats.feedback_count,
            }
            if stats is not None
            else {}
        )
        replay_snapshot = {
            "current_metric": details.get("metric"),
            "precision": details.get("precision"),
            "recall": details.get("recall"),
            "target_source_confusion": (details.get("per_source") or {}).get(self.target_source, {}),
            "total_labeled": details.get("total_labeled"),
            "alert_threshold": details.get("alert_threshold"),
            "trust_weight": details.get("trust_weight"),
            "trust_sweep": details.get("trust_sweep", {}),
            "keep_policy": {
                "min_keep_delta": float(self.settings.karpathy.min_keep_delta),
                "min_labeled_samples": int(self.settings.karpathy.min_labeled_samples),
                "max_true_positive_drop": int(self.settings.karpathy.max_true_positive_drop),
                "max_false_positive_increase": int(self.settings.karpathy.max_false_positive_increase),
            },
        }
        return (
            f"Loop type: {self.loop_type}\n"
            f"Experiment number: {experiment_number}\n"
            f"Target source: {self.target_source}\n"
            f"Current trust: {current_trust:.2f}\n"
            "Return JSON with keys: source_name, new_trust, reasoning, expected_effect.\n"
            "Return only valid JSON, with no markdown fences or extra prose.\n"
            "Only optimize the trust score for the target source. Do not propose any other edits.\n"
            "The absolute trust change must be <= 0.05 and the value must stay within 0.0 and 1.0.\n\n"
            "Use the replay snapshot as the evidence for the next bounded experiment. "
            "Prefer the trust_sweep grid_best_trust only when it improves current_metric by at least "
            "min_keep_delta without violating the keep_policy. If the sweep is flat, keep current trust "
            "and explain that no safe source-trust update is supported yet.\n\n"
            f"Target feedback snapshot:\n{json.dumps(feedback_snapshot, indent=2, sort_keys=True)}\n\n"
            f"Replay evaluation snapshot:\n{json.dumps(replay_snapshot, indent=2, sort_keys=True)}\n\n"
            f"Current skill file:\n{current_skill}\n\n"
            f"Recent history:\n{json.dumps(history[-5:], indent=2)}\n"
        )

    def _parse_proposal(self, raw_response: str) -> ExperimentProposal:
        try:
            payload = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise ValueError("LLM provider returned invalid JSON for a Karpathy experiment.") from exc
        if self.target_source is None:
            raise ValueError("SourceQualityLoop requires a target_source for live optimization.")
        source_name = str(payload["source_name"]).strip().lower()
        if source_name != self.target_source:
            raise ValueError(f"Karpathy source loop must target '{self.target_source}', got '{source_name}'.")
        new_trust = round(float(payload["new_trust"]), 2)
        trust_before = self.current_trust(source_name)
        if abs(new_trust - trust_before) > 0.050001:
            raise ValueError("Karpathy source loop trust changes must stay within +/- 0.05 per experiment.")
        new_trust = max(0.0, min(1.0, new_trust))
        reasoning = str(payload["reasoning"]).strip()
        expected_effect = str(payload["expected_effect"]).strip()
        if not reasoning or not expected_effect:
            raise ValueError("Karpathy source loop proposals require reasoning and expected_effect.")
        return ExperimentProposal(
            description=f"Adjust trust for {source_name}",
            patch=f"trust_score: {source_name} -> {new_trust:.2f}",
            section="Trust Scores",
            reasoning=reasoning,
            source_name=source_name,
            new_trust=new_trust,
            expected_effect=expected_effect,
        )

    def apply_patch(self, proposal: ExperimentProposal) -> str:
        if proposal.source_name is None or proposal.new_trust is None:
            raise ValueError("Source Karpathy proposals require source_name and new_trust.")
        original = self.skill_path.read_text(encoding="utf-8")
        target = proposal.source_name
        replaced = False

        def replace(match: re.Match[str]) -> str:
            nonlocal replaced
            if match.group("name") != target:
                return match.group(0)
            replaced = True
            old_value = float(match.group("value"))
            self._last_trust_before = old_value
            self._last_trust_after = proposal.new_trust
            return f"{match.group(1)}{target}{match.group(3)}{proposal.new_trust:.2f}"

        updated = TRUST_SCORE_LINE_RE.sub(replace, original)
        if not replaced:
            raise ValueError(f"Trust score for source '{target}' not found in {self.skill_path}")
        self.skill_path.write_text(updated, encoding="utf-8")
        return original

    def decide_keep(
        self,
        *,
        proposal: ExperimentProposal,
        metric_before: float,
        metric_after: float,
        eval_details_before: dict | None,
        eval_details_after: dict | None,
    ) -> KeepDecision:
        # Fail closed on tiny labeled windows: with a handful of labels a
        # +0.01 metric delta is indistinguishable from noise. Only enforced
        # when replay details are present (metric_override paths skip it).
        total_labeled = (eval_details_after or {}).get("total_labeled")
        min_labeled = int(self.settings.karpathy.min_labeled_samples)
        if total_labeled is not None and int(total_labeled) < min_labeled:
            return KeepDecision(
                kept=False,
                reason=f"insufficient_labeled_data:{total_labeled}<{min_labeled}",
                details={
                    "total_labeled": int(total_labeled),
                    "min_labeled_samples": min_labeled,
                },
            )
        base = super().decide_keep(
            proposal=proposal,
            metric_before=metric_before,
            metric_after=metric_after,
            eval_details_before=eval_details_before,
            eval_details_after=eval_details_after,
        )
        if not base.kept:
            return base

        before_confusion = (eval_details_before or {}).get("confusion", {})
        after_confusion = (eval_details_after or {}).get("confusion", {})
        true_positive_drop = int(before_confusion.get("tp", 0)) - int(after_confusion.get("tp", 0))
        false_positive_increase = int(after_confusion.get("fp", 0)) - int(before_confusion.get("fp", 0))
        max_tp_drop = int(self.settings.karpathy.max_true_positive_drop)
        max_fp_increase = int(self.settings.karpathy.max_false_positive_increase)
        if true_positive_drop > max_tp_drop:
            return KeepDecision(
                kept=False,
                reason=f"true_positive_drop_exceeded:{true_positive_drop}>{max_tp_drop}",
                details={
                    "true_positive_drop": true_positive_drop,
                    "max_true_positive_drop": max_tp_drop,
                },
            )
        if false_positive_increase > max_fp_increase:
            return KeepDecision(
                kept=False,
                reason=f"false_positive_increase_exceeded:{false_positive_increase}>{max_fp_increase}",
                details={
                    "false_positive_increase": false_positive_increase,
                    "max_false_positive_increase": max_fp_increase,
                },
            )
        return KeepDecision(
            kept=True,
            reason="delta_and_replay_guardrails_passed",
            details={
                **(base.details or {}),
                "true_positive_drop": true_positive_drop,
                "max_true_positive_drop": max_tp_drop,
                "false_positive_increase": false_positive_increase,
                "max_false_positive_increase": max_fp_increase,
            },
        )

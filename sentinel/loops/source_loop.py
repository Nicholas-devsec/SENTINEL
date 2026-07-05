from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sqlalchemy import select

from sentinel.db.models import FeedbackRecord, IOC
from sentinel.loops.karpathy_loop import ExperimentProposal, ThreatIntelLoop
from sentinel.loops.replay_eval import ReplayEvaluator


TRUST_SCORE_LINE_RE = re.compile(r"^(-\s+)(?P<name>[a-zA-Z0-9_:-]+)(:\s*)(?P<value>[0-9]*\.?[0-9]+)\s*$", re.MULTILINE)


@dataclass(slots=True)
class SourceFeedbackStats:
    source_name: str
    confirmed: int
    false_positive: int

    @property
    def feedback_count(self) -> int:
        return self.confirmed + self.false_positive

    @property
    def precision(self) -> float:
        total = self.feedback_count
        return self.confirmed / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = self.feedback_count
        return self.false_positive / total if total else 0.0


class SourceQualityLoop(ThreatIntelLoop):
    loop_type = "source"
    eval_mode = "replay"

    def __init__(self, *args, target_source: str | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.target_source = target_source
        self._last_feedback_count: int | None = None
        self._last_trust_before: float | None = None
        self._last_trust_after: float | None = None
        self._last_eval_details: dict | None = None

    async def _source_feedback_stats(self) -> SourceFeedbackStats:
        if self.target_source is None:
            raise ValueError("SourceQualityLoop requires a target_source for live optimization.")
        async with self.session_factory() as session:
            if hasattr(session, "feedback_rows"):
                rows = [
                    row for row in session.feedback_rows
                    if row.get("source") == self.target_source and row["verdict"] in {"confirmed", "false_positive"}
                ]
            else:
                cutoff = self.now_fn() - __import__("datetime").timedelta(hours=48)
                query = (
                    select(FeedbackRecord, IOC.source)
                    .join(IOC, FeedbackRecord.ioc_id == IOC.id)
                    .where(FeedbackRecord.timestamp >= cutoff)
                    .where(IOC.source == self.target_source)
                    .where(FeedbackRecord.verdict.in_(["confirmed", "false_positive"]))
                )
                rows = [
                    {"verdict": feedback.verdict, "source": source}
                    for feedback, source in (await session.execute(query)).all()
                ]
        confirmed = sum(1 for row in rows if row["verdict"] == "confirmed")
        false_positive = sum(1 for row in rows if row["verdict"] == "false_positive")
        stats = SourceFeedbackStats(
            source_name=self.target_source,
            confirmed=confirmed,
            false_positive=false_positive,
        )
        self._last_feedback_count = stats.feedback_count
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
            alert_threshold=float(self.settings.thresholds.alert_score),
            trust_weight=float(self.settings.enrichment.weights.source_trust),
            now_fn=self.now_fn,
        )

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        # Replay: recompute labeled-window alerting under the trust scores
        # currently in the skill file, so a trust patch changes this number.
        result = await self._build_replay_evaluator().evaluate()
        self._last_eval_details = result.to_details()
        # Keep feedback_count reporting for the run report.
        if self.target_source is not None:
            await self._source_feedback_stats()
        return result.metric

    def _build_prompt(self, experiment_number: int, current_skill: str, history: list[dict[str, object]]) -> str:
        if self.target_source is None:
            raise ValueError("SourceQualityLoop requires a target_source for prompt building.")
        current_trust = self.current_trust(self.target_source)
        return (
            f"Loop type: {self.loop_type}\n"
            f"Experiment number: {experiment_number}\n"
            f"Target source: {self.target_source}\n"
            f"Current trust: {current_trust:.2f}\n"
            "Return JSON with keys: source_name, new_trust, reasoning, expected_effect.\n"
            "Only optimize the trust score for the target source. Do not propose any other edits.\n"
            "The absolute trust change must be <= 0.05 and the value must stay within 0.0 and 1.0.\n\n"
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
        if abs(new_trust - trust_before) > 0.05:
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

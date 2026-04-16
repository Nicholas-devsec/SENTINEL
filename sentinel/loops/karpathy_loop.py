from __future__ import annotations

import asyncio
import json
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

from git import Actor, InvalidGitRepositoryError, Repo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.config import SentinelSettings, get_settings
from sentinel.db.models import ExperimentLog, FeedbackRecord, IOC
from sentinel.loops.providers.base import LLMProvider


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ExperimentProposal:
    description: str
    patch: str
    section: str
    reasoning: str
    source_name: str | None = None
    new_trust: float | None = None
    expected_effect: str | None = None


@dataclass(slots=True)
class ExperimentOutcome:
    experiment_number: int
    metric_before: float
    metric_after: float
    delta: float
    kept: bool
    hypothesis: str
    target_source: str | None = None
    trust_before: float | None = None
    trust_after: float | None = None
    feedback_count: int | None = None


class ThreatIntelLoop:
    """Provider-driven Karpathy loop that patches one skill file and keeps only improvements."""

    loop_type = "base"

    def __init__(
        self,
        *,
        provider: LLMProvider,
        skill_path: str | Path,
        budget_minutes: int,
        settings: SentinelSettings | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        repo_path: str | None = None,
        changelog_path: str = "skills/CHANGELOG.md",
        now_fn: Callable[[], datetime] | None = None,
        metric_override: Callable[[], Awaitable[float]] | None = None,
    ) -> None:
        self.provider = provider
        self.skill_path = Path(skill_path)
        self.budget_minutes = budget_minutes
        self.settings = settings or get_settings()
        if session_factory is None:
            from sentinel.db.session import AsyncSessionFactory

            self.session_factory = AsyncSessionFactory
        else:
            self.session_factory = session_factory
        self.repo_path = Path(repo_path) if repo_path is not None else Path.cwd()
        self.changelog_path = Path(changelog_path)
        self.now_fn = now_fn or (lambda: datetime.now(UTC))
        self.metric_override = metric_override

    async def run_experiment(self, prompt: str) -> dict[str, Any]:
        response = await asyncio.wait_for(
            self.provider.complete(prompt),
            timeout=self.budget_minutes * 60,
        )
        return {"raw_response": response}

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        raise NotImplementedError("Subclasses must implement measure_metric or provide metric_override.")

    def _parse_proposal(self, raw_response: str) -> ExperimentProposal:
        try:
            payload = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise ValueError("LLM provider returned invalid JSON for a Karpathy experiment.") from exc
        section = str(payload["section"]).strip()
        if not section or "\n" in section:
            raise ValueError("Karpathy experiments must target exactly one existing section header.")
        patch = str(payload["patch"]).strip()
        if not patch:
            raise ValueError("Karpathy experiments must provide a non-empty section patch.")
        return ExperimentProposal(
            description=payload["description"],
            patch=patch,
            section=section,
            reasoning=payload["reasoning"],
        )

    def _find_section_bounds(self, content: str, section: str) -> tuple[int, int]:
        header = f"## {section}"
        start = content.find(header)
        if start == -1:
            raise ValueError(f"Section '{section}' not found in {self.skill_path}")
        next_header = content.find("\n## ", start + len(header))
        end = len(content) if next_header == -1 else next_header + 1
        body_start = content.find("\n", start)
        if body_start == -1:
            body_start = len(content)
        return body_start + 1, end

    def apply_patch(self, proposal: ExperimentProposal) -> str:
        original = self.skill_path.read_text(encoding="utf-8")
        body_start, body_end = self._find_section_bounds(original, proposal.section)
        updated = original[:body_start] + proposal.patch.rstrip() + "\n\n" + original[body_end:]
        self.skill_path.write_text(updated, encoding="utf-8")
        return original

    def revert_patch(self, original: str) -> None:
        self.skill_path.write_text(original, encoding="utf-8")

    def _build_prompt(self, experiment_number: int, current_skill: str, history: list[dict[str, Any]]) -> str:
        history_json = json.dumps(history[-5:], indent=2)
        return (
            f"Loop type: {self.loop_type}\n"
            f"Experiment number: {experiment_number}\n"
            "Return JSON with keys description, patch, section, reasoning.\n"
            "Modify one section in the provided skill file.\n\n"
            f"Current skill file:\n{current_skill}\n\n"
            f"Recent history:\n{history_json}\n"
        )

    async def _create_log_row(
        self,
        session: Any,
        *,
        experiment_number: int,
        proposal: ExperimentProposal,
        metric_before: float,
        metric_after: float,
        delta: float,
        kept: bool,
    ) -> None:
        if hasattr(session, "experiment_logs"):
            session.experiment_logs.append(
                {
                    "loop_type": self.loop_type,
                    "experiment_number": experiment_number,
                    "hypothesis": proposal.description,
                    "patch_applied": proposal.patch,
                    "metric_before": metric_before,
                    "metric_after": metric_after,
                    "delta": delta,
                    "kept": kept,
                    "timestamp": self.now_fn(),
                }
            )
            return
        row = ExperimentLog(
            loop_type=self.loop_type,
            experiment_number=experiment_number,
            hypothesis=proposal.description,
            patch_applied=proposal.patch,
            metric_before=metric_before,
            metric_after=metric_after,
            delta=delta,
            kept=kept,
            timestamp=self.now_fn(),
        )
        session.add(row)
        await session.commit()

    def _append_changelog(self, proposal: ExperimentProposal, delta: float, kept: bool) -> None:
        path = self.changelog_path
        if not path.exists():
            return
        entry = (
            f"- {self.now_fn().isoformat()} | actor=karpathy | loop={self.loop_type} | kept={str(kept).lower()} | "
            f"delta={delta:.4f} | section={proposal.section} | description={proposal.description}\n"
        )
        path.write_text(path.read_text(encoding="utf-8") + entry, encoding="utf-8")

    def _commit_skill_change(self, proposal: ExperimentProposal, delta: float) -> None:
        try:
            repo = Repo(self.repo_path, search_parent_directories=True)
        except InvalidGitRepositoryError:
            return
        root = Path(repo.working_tree_dir).resolve()
        files = [self.skill_path.resolve(), self.changelog_path.resolve()]
        repo.index.add([str(path.relative_to(root)) for path in files if path.exists()])
        actor = Actor(self.settings.git.author_name, self.settings.git.author_email)
        message = (
            f"karpathy: {self.now_fn().date().isoformat()} updated {self.skill_path.stem.lower()} - "
            f"{proposal.description} (delta: {delta:.4f})"
        )
        repo.index.commit(message, author=actor, committer=actor)

    async def optimize(self, *, max_experiments: int) -> list[ExperimentOutcome]:
        outcomes: list[ExperimentOutcome] = []
        history: list[dict[str, Any]] = []
        consecutive_small = 0

        for experiment_number in range(1, max_experiments + 1):
            current_skill = self.skill_path.read_text(encoding="utf-8")
            metric_before = await self.measure_metric()
            prompt = self._build_prompt(experiment_number, current_skill, history)
            raw = await self.run_experiment(prompt)
            proposal = self._parse_proposal(raw["raw_response"])
            original = self.apply_patch(proposal)
            try:
                metric_after = await asyncio.wait_for(
                    self.measure_metric(),
                    timeout=self.budget_minutes * 60,
                )
            except Exception:
                self.revert_patch(original)
                raise

            delta = metric_after - metric_before
            kept = delta > 0
            if not kept:
                self.revert_patch(original)
                metric_after = metric_before
                if hasattr(self, "_last_trust_before"):
                    setattr(self, "_last_trust_after", getattr(self, "_last_trust_before", None))

            async with self.session_factory() as session:
                await self._create_log_row(
                    session,
                    experiment_number=experiment_number,
                    proposal=proposal,
                    metric_before=metric_before,
                    metric_after=metric_after,
                    delta=delta,
                    kept=kept,
                )

            if kept:
                self._append_changelog(proposal, delta, kept=True)
                self._commit_skill_change(proposal, delta)

            outcome = ExperimentOutcome(
                experiment_number=experiment_number,
                metric_before=metric_before,
                metric_after=metric_after,
                delta=delta,
                kept=kept,
                hypothesis=proposal.description,
                target_source=getattr(proposal, "source_name", None),
                trust_before=getattr(self, "_last_trust_before", None),
                trust_after=getattr(self, "_last_trust_after", None),
                feedback_count=getattr(self, "_last_feedback_count", None),
            )
            outcomes.append(outcome)
            history.append(
                {
                    "experiment_number": experiment_number,
                    "description": proposal.description,
                    "delta": delta,
                    "kept": kept,
                }
            )
            logger.info(
                "Karpathy loop=%s experiment=%s source=%s trust_before=%s trust_after=%s metric_before=%.4f metric_after=%.4f delta=%.4f kept=%s feedback_count=%s",
                self.loop_type,
                experiment_number,
                getattr(proposal, "source_name", None),
                getattr(self, "_last_trust_before", None),
                getattr(self, "_last_trust_after", None),
                metric_before,
                metric_after,
                delta,
                kept,
                getattr(self, "_last_feedback_count", None),
            )

            if abs(delta) < 0.001:
                consecutive_small += 1
            else:
                consecutive_small = 0
            if consecutive_small >= 3:
                break

        return outcomes

    async def run(self, *args: Any, **kwargs: Any) -> list[ExperimentOutcome]:
        return await self.optimize(max_experiments=self.settings.thresholds.karpathy_experiments)


class MetricBackedLoop(ThreatIntelLoop):
    def __init__(self, *args: Any, metric_field: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.metric_field = metric_field

    async def _fetch_iocs(self, session: Any) -> list[Any]:
        if hasattr(session, "iocs"):
            return list(session.iocs)
        cutoff = self.now_fn() - timedelta(hours=48)
        rows = await session.scalars(select(IOC).where(IOC.last_seen >= cutoff))
        return list(rows.all())


def _spearman(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or len(left) < 2:
        return 0.0

    def rank(values: list[float]) -> list[float]:
        sorted_pairs = sorted((value, idx) for idx, value in enumerate(values))
        ranks = [0.0] * len(values)
        i = 0
        while i < len(sorted_pairs):
            j = i
            while j < len(sorted_pairs) and sorted_pairs[j][0] == sorted_pairs[i][0]:
                j += 1
            avg_rank = (i + j - 1) / 2 + 1
            for _, idx in sorted_pairs[i:j]:
                ranks[idx] = avg_rank
            i = j
        return ranks

    rank_left = rank(left)
    rank_right = rank(right)
    mean_left = sum(rank_left) / len(rank_left)
    mean_right = sum(rank_right) / len(rank_right)
    numerator = sum((a - mean_left) * (b - mean_right) for a, b in zip(rank_left, rank_right, strict=True))
    denom_left = math.sqrt(sum((a - mean_left) ** 2 for a in rank_left))
    denom_right = math.sqrt(sum((b - mean_right) ** 2 for b in rank_right))
    if not denom_left or not denom_right:
        return 0.0
    return numerator / (denom_left * denom_right)

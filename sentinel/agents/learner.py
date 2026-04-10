from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
from typing import Any

from git import Actor, InvalidGitRepositoryError, Repo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.agents.base import BaseAgent
from sentinel.config import SentinelSettings, get_settings
from sentinel.db.models import ExperimentLog, FeedbackRecord, IOC


LEARNER_ANCHOR = "<!-- learner: append here -->"
TRUST_SCORE_LINE_RE = re.compile(r"^(-\s+)(?P<name>[a-zA-Z0-9_:-]+)(:\s*)(?P<value>[0-9]*\.?[0-9]+)\s*$", re.MULTILINE)


@dataclass(slots=True)
class LearnerChange:
    skill_name: str
    skill_path: str
    reason: str
    delta: float
    commit_message: str


class LearnerAgent(BaseAgent):
    def __init__(
        self,
        skill_path: str = "skills/learner/SKILL.md",
        *,
        settings: SentinelSettings | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        skills_root: str = "skills",
        repo_path: str | None = None,
        now_fn=None,
    ) -> None:
        super().__init__(skill_path)
        self.settings = settings or get_settings()
        if session_factory is None:
            from sentinel.db.session import AsyncSessionFactory

            self.session_factory = AsyncSessionFactory
        else:
            self.session_factory = session_factory
        self.skills_root = Path(skills_root)
        self.repo_path = Path(repo_path) if repo_path is not None else Path.cwd()
        self.now_fn = now_fn or (lambda: datetime.now(UTC))

    async def _fetch_feedback_rows(self, session: Any) -> list[dict[str, Any]]:
        if hasattr(session, "feedback_rows"):
            return list(session.feedback_rows)
        cutoff = self.now_fn() - timedelta(hours=48)
        query = (
            select(FeedbackRecord, IOC.source, IOC.value)
            .join(IOC, FeedbackRecord.ioc_id == IOC.id)
            .where(FeedbackRecord.timestamp >= cutoff)
        )
        rows = await session.execute(query)
        result = []
        for feedback, source, value in rows.all():
            result.append(
                {
                    "ioc_id": str(feedback.ioc_id),
                    "source": source,
                    "value": value,
                    "verdict": feedback.verdict,
                    "timestamp": feedback.timestamp,
                }
            )
        return result

    async def _fetch_experiment_rows(self, session: Any) -> list[ExperimentLog | dict[str, Any]]:
        if hasattr(session, "experiment_rows"):
            return list(session.experiment_rows)
        rows = await session.scalars(select(ExperimentLog).where(ExperimentLog.kept.is_(True)))
        return list(rows.all())

    def _sources_skill_path(self) -> Path:
        return self.skills_root / "sources" / "SKILL.md"

    def _validation_skill_path(self) -> Path:
        return self.skills_root / "validation" / "SKILL.md"

    def _detection_skill_path(self) -> Path:
        return self.skills_root / "detection" / "SKILL.md"

    def _changelog_path(self) -> Path:
        return self.skills_root / "CHANGELOG.md"

    def _build_commit_message(self, skill_name: str, reason: str, delta: float) -> str:
        date_str = self.now_fn().date().isoformat()
        return f"learner: {date_str} updated {skill_name} - {reason} (delta: {delta:.2f})"

    def _append_changelog(self, change: LearnerChange) -> None:
        entry = (
            f"- {self.now_fn().isoformat()} | skill={change.skill_name} | "
            f"reason={change.reason} | delta={change.delta:.2f} | commit=\"{change.commit_message}\"\n"
        )
        path = self._changelog_path()
        existing = path.read_text(encoding="utf-8")
        path.write_text(existing + entry, encoding="utf-8")

    def _commit_files(self, files: list[Path], message: str) -> None:
        try:
            repo = Repo(self.repo_path, search_parent_directories=True)
        except InvalidGitRepositoryError:
            self.logger.warning("Skipping git commit because %s is not inside a git repository", self.repo_path)
            return
        root = Path(repo.working_tree_dir).resolve()
        repo.index.add([str(path.resolve().relative_to(root)) for path in files])
        actor = Actor(self.settings.git.author_name, self.settings.git.author_email)
        repo.index.commit(message, author=actor, committer=actor)

    def _finalize_change(self, change: LearnerChange) -> None:
        files = [Path(change.skill_path), self._changelog_path()]
        self._append_changelog(change)
        self._commit_files(files, change.commit_message)

    def _compute_fp_rate_by_source(self, feedback_rows: list[dict[str, Any]]) -> dict[str, float]:
        totals: dict[str, int] = {}
        false_positives: dict[str, int] = {}
        for row in feedback_rows:
            source = row["source"]
            totals[source] = totals.get(source, 0) + 1
            if row["verdict"] == "false_positive":
                false_positives[source] = false_positives.get(source, 0) + 1
        return {
            source: (false_positives.get(source, 0) / total)
            for source, total in totals.items()
            if total > 0
        }

    def _update_source_trust(self, source_name: str, delta: float = -0.05) -> LearnerChange | None:
        path = self._sources_skill_path()
        content = path.read_text(encoding="utf-8")

        def replace(match: re.Match[str]) -> str:
            if match.group("name") != source_name:
                return match.group(0)
            current = float(match.group("value"))
            new_value = max(0.0, round(current + delta, 2))
            return f"{match.group(1)}{source_name}{match.group(3)}{new_value:.2f}"

        updated = TRUST_SCORE_LINE_RE.sub(replace, content)
        if updated == content:
            return None
        path.write_text(updated, encoding="utf-8")
        reason = f"reduced {source_name} trust after elevated false-positive rate"
        commit_message = self._build_commit_message("sources", reason, delta)
        change = LearnerChange("sources", str(path), reason, delta, commit_message)
        self._finalize_change(change)
        return change

    def _append_at_anchor(self, path: Path, addition: str) -> bool:
        content = path.read_text(encoding="utf-8")
        if addition.strip() in content:
            return False
        if LEARNER_ANCHOR not in content:
            raise ValueError(f"Learner anchor missing in {path}")
        updated = content.replace(LEARNER_ANCHOR, f"{addition.rstrip()}\n{LEARNER_ANCHOR}")
        path.write_text(updated, encoding="utf-8")
        return True

    def _learn_validation_patterns(self, feedback_rows: list[dict[str, Any]]) -> LearnerChange | None:
        fp_counts: dict[str, int] = {}
        for row in feedback_rows:
            if row["verdict"] == "false_positive":
                fp_counts[row["value"].lower()] = fp_counts.get(row["value"].lower(), 0) + 1
        repeated = sorted(value for value, count in fp_counts.items() if count >= 3)
        if not repeated:
            return None
        path = self._validation_skill_path()
        lines = [f"- pattern: {value}" for value in repeated]
        changed = self._append_at_anchor(path, "\n".join(lines))
        if not changed:
            return None
        delta = float(len(repeated))
        reason = f"added {len(repeated)} repeated false-positive patterns"
        commit_message = self._build_commit_message("validation", reason, delta)
        change = LearnerChange("validation", str(path), reason, delta, commit_message)
        self._finalize_change(change)
        return change

    def _append_detection_optimizations(self, experiment_rows: list[ExperimentLog | dict[str, Any]]) -> LearnerChange | None:
        entries: list[str] = []
        for row in experiment_rows:
            kept = row["kept"] if isinstance(row, dict) else row.kept
            if not kept:
                continue
            loop_type = row["loop_type"] if isinstance(row, dict) else row.loop_type
            if loop_type != "detection":
                continue
            hypothesis = row["hypothesis"] if isinstance(row, dict) else row.hypothesis
            delta = row["delta"] if isinstance(row, dict) else row.delta
            entries.append(f"- optimization: {hypothesis} (delta: {float(delta):.3f})")
        if not entries:
            return None
        path = self._detection_skill_path()
        changed = self._append_at_anchor(path, "\n".join(entries))
        if not changed:
            return None
        avg_delta = sum(
            float((row["delta"] if isinstance(row, dict) else row.delta))
            for row in experiment_rows
            if (row["loop_type"] if isinstance(row, dict) else row.loop_type) == "detection"
            and (row["kept"] if isinstance(row, dict) else row.kept)
        ) / max(len(entries), 1)
        reason = f"appended {len(entries)} successful detection optimizations"
        commit_message = self._build_commit_message("detection", reason, avg_delta)
        change = LearnerChange("detection", str(path), reason, avg_delta, commit_message)
        self._finalize_change(change)
        return change

    async def run(self, *args: Any, **kwargs: Any) -> list[LearnerChange]:
        self.reload_skill()
        async with self.session_factory() as session:
            feedback_rows = await self._fetch_feedback_rows(session)
            experiment_rows = await self._fetch_experiment_rows(session)

        changes: list[LearnerChange] = []
        fp_rates = self._compute_fp_rate_by_source(feedback_rows)
        for source_name, rate in fp_rates.items():
            if rate > 0.15:
                change = self._update_source_trust(source_name, delta=-0.05)
                if change is not None:
                    changes.append(change)

        validation_change = self._learn_validation_patterns(feedback_rows)
        if validation_change is not None:
            changes.append(validation_change)

        detection_change = self._append_detection_optimizations(experiment_rows)
        if detection_change is not None:
            changes.append(detection_change)

        return changes

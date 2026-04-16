from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
import json
import subprocess
import tempfile
from typing import Any, Sequence

from git import GitCommandError, InvalidGitRepositoryError, Repo
from sqlalchemy import case, func, select

from sentinel.agents.scorer import build_external_links_for_ioc
from sentinel.config import SentinelSettings
from sentinel.db.models import FeedbackRecord, IOC
from sentinel.db.session import AsyncSessionFactory
from sentinel.loops.detection_loop import DetectionEffectivenessLoop
from sentinel.loops.karpathy_loop import ExperimentOutcome
from sentinel.loops.providers.openai_provider import OpenAIProvider
from sentinel.loops.scoring_loop import ScoreCalibrationLoop
from sentinel.loops.source_loop import SourceQualityLoop

LOOP_SKILL_PATHS = {
    "source": Path("skills/sources/SKILL.md"),
    "scoring": Path("skills/mitre/SKILL.md"),
    "detection": Path("skills/detection/SKILL.md"),
}

LOOP_PRIMARY_SECTIONS = {
    "source": "Trust Scores",
    "scoring": "Severity Weights",
    "detection": "Templates",
}

LIVE_DATA_THRESHOLDS = {
    "source": {"feedback_rows": 5, "distinct_sources": 2},
    "scoring": {"analyst_verdicts": 10},
    "detection": {"generated_rules": 10, "pushed_rules": 1},
}


@dataclass(slots=True)
class KarpathyCheck:
    name: str
    passed: bool
    detail: str


@dataclass(slots=True)
class KarpathyReadinessReport:
    loop_type: str
    ready: bool
    skill_path: str
    changelog_path: str
    checks: list[KarpathyCheck]
    counts: dict[str, int] = field(default_factory=dict)
    current_branch: str | None = None
    target_source: str | None = None


@dataclass(slots=True)
class KarpathyRunReport:
    loop_type: str
    mode: str
    experiments_attempted: int
    kept: int
    reverted: int
    metric_before: float | None
    metric_after: float | None
    affected_sections: list[str]
    commit_hashes: list[str]
    branch_name: str | None = None
    worktree_path: str | None = None
    scenario: str | None = None
    error: str | None = None
    outcomes: list[ExperimentOutcome] = field(default_factory=list)
    target_source: str | None = None
    feedback_count: int | None = None
    trust_before: float | None = None
    trust_after: float | None = None


class _ScriptedProvider:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)

    async def complete(self, prompt: str) -> str:
        if not self.responses:
            raise RuntimeError("No scripted Karpathy responses remain.")
        return self.responses.pop(0)


class _SequencedMetric:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)

    async def __call__(self) -> float:
        if not self.values:
            raise RuntimeError("No scripted metric values remain.")
        return self.values.pop(0)


class _ShadowLogSession:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.experiment_logs = rows

    async def __aenter__(self) -> _ShadowLogSession:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


class _ShadowLogSessionFactory:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def __call__(self) -> _ShadowLogSession:
        return _ShadowLogSession(self.rows)


def _loop_class_for(loop_type: str):
    if loop_type == "source":
        return SourceQualityLoop
    if loop_type == "scoring":
        return ScoreCalibrationLoop
    if loop_type == "detection":
        return DetectionEffectivenessLoop
    raise ValueError(f"Unsupported karpathy loop type: {loop_type}")


def _build_branch_name(loop_type: str, *, now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d%H%M%S")
    return f"karpathy-{loop_type}-{stamp}"


def _build_source_branch_name(source_name: str, *, now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d%H%M%S")
    normalized = source_name.lower().replace(" ", "-")
    return f"karpathy-source-{normalized}-{stamp}"


def _resolve_repo_root() -> Path:
    repo = Repo(Path.cwd(), search_parent_directories=True)
    return Path(repo.working_tree_dir).resolve()


def build_karpathy_loop(
    *,
    loop_type: str,
    settings: SentinelSettings,
    provider: Any | None = None,
    skill_path: str | Path | None = None,
    repo_path: str | Path | None = None,
    changelog_path: str | Path = "skills/CHANGELOG.md",
    session_factory: Any | None = None,
    metric_override: Any | None = None,
    target_source: str | None = None,
):
    loop_cls = _loop_class_for(loop_type)
    resolved_repo = Path(repo_path) if repo_path is not None else Path.cwd()
    resolved_skill = Path(skill_path) if skill_path is not None else resolved_repo / LOOP_SKILL_PATHS[loop_type]
    resolved_changelog = Path(changelog_path)
    if not resolved_changelog.is_absolute():
        resolved_changelog = resolved_repo / resolved_changelog
    loop_provider = provider or OpenAIProvider(settings.openai)
    common_kwargs = {
        "provider": loop_provider,
        "skill_path": resolved_skill,
        "settings": settings,
        "budget_minutes": settings.thresholds.karpathy_budget_mins,
        "repo_path": str(resolved_repo),
        "changelog_path": str(resolved_changelog),
    }
    if session_factory is not None:
        common_kwargs["session_factory"] = session_factory
    if metric_override is not None:
        common_kwargs["metric_override"] = metric_override
    if target_source is not None and loop_type == "source":
        common_kwargs["target_source"] = target_source
    return loop_cls(**common_kwargs)


def format_karpathy_outcomes(outcomes: list[Any]) -> str:
    if not outcomes:
        return "No Karpathy experiments were run."
    lines = ["Karpathy loop results:"]
    for outcome in outcomes:
        if hasattr(outcome, "__dataclass_fields__"):
            payload = asdict(outcome)
        elif hasattr(outcome, "__dict__"):
            payload = vars(outcome)
        else:
            payload = dict(outcome)
        lines.append(
            f"- experiment={payload['experiment_number']} kept={str(payload['kept']).lower()} "
            f"delta={payload['delta']:.4f} hypothesis={payload['hypothesis']}"
        )
    return "\n".join(lines)


def format_karpathy_report(report: KarpathyRunReport) -> str:
    lines = [
        f"Karpathy {report.mode} report:",
        f"- loop={report.loop_type}",
    ]
    if getattr(report, "scenario", None):
        lines.append(f"- scenario={report.scenario}")
    if getattr(report, "branch_name", None):
        lines.append(f"- branch={report.branch_name}")
    if getattr(report, "target_source", None):
        lines.append(f"- target_source={report.target_source}")
    if getattr(report, "worktree_path", None):
        lines.append(f"- worktree={report.worktree_path}")
    lines.extend(
        [
            f"- experiments_attempted={report.experiments_attempted}",
            f"- kept={report.kept}",
            f"- reverted={report.reverted}",
            f"- metric_before={report.metric_before if report.metric_before is not None else 'n/a'}",
            f"- metric_after={report.metric_after if report.metric_after is not None else 'n/a'}",
            f"- feedback_count={getattr(report, 'feedback_count', None) if getattr(report, 'feedback_count', None) is not None else 'n/a'}",
            f"- trust_before={getattr(report, 'trust_before', None) if getattr(report, 'trust_before', None) is not None else 'n/a'}",
            f"- trust_after={getattr(report, 'trust_after', None) if getattr(report, 'trust_after', None) is not None else 'n/a'}",
            f"- affected_sections={', '.join(report.affected_sections) if report.affected_sections else 'none'}",
            f"- commit_hashes={', '.join(report.commit_hashes) if report.commit_hashes else 'none'}",
        ]
    )
    if getattr(report, "error", None):
        lines.append(f"- error={report.error}")
    if getattr(report, "outcomes", None):
        lines.append(format_karpathy_outcomes(report.outcomes))
    return "\n".join(lines)


def format_karpathy_readiness(report: KarpathyReadinessReport) -> str:
    lines = [f"Karpathy preflight for {report.loop_type}:"]
    if getattr(report, "current_branch", None):
        lines.append(f"- current_branch={report.current_branch}")
    if getattr(report, "target_source", None):
        lines.append(f"- target_source={report.target_source}")
    lines.append(f"- skill_path={report.skill_path}")
    lines.append(f"- changelog_path={report.changelog_path}")
    for check in report.checks:
        status = "pass" if check.passed else "fail"
        lines.append(f"- {check.name}: {status} ({check.detail})")
    if report.counts:
        counts = ", ".join(f"{key}={value}" for key, value in sorted(report.counts.items()))
        lines.append(f"- counts: {counts}")
    lines.append(f"- ready={'yes' if report.ready else 'no'}")
    return "\n".join(lines)


def _build_shadow_scenario(loop_type: str, scenario: str) -> tuple[list[str], list[float], int]:
    section = LOOP_PRIMARY_SECTIONS[loop_type]
    if scenario == "improve":
        proposal = (
            {
                "source_name": "threatfox",
                "new_trust": 0.89,
                "reasoning": "Recent analyst feedback shows elevated false positives for this source.",
                "expected_effect": "Improve source precision by reducing noisy indicators.",
            }
            if loop_type == "source"
            else {
                "description": f"Improve {loop_type} guidance",
                "patch": "updated body with tighter rules\n",
                "section": section,
                "reasoning": "Expected to improve the live metric.",
            }
        )
        return [json.dumps(proposal)], [0.40, 0.58], 1
    if scenario == "decline":
        proposal = (
            {
                "source_name": "threatfox",
                "new_trust": 0.89,
                "reasoning": "Lower confidence might remove useful data.",
                "expected_effect": "This is expected to regress.",
            }
            if loop_type == "source"
            else {
                "description": f"Bad {loop_type} change",
                "patch": "worse body\n",
                "section": section,
                "reasoning": "Expected to regress.",
            }
        )
        return [json.dumps(proposal)], [0.60, 0.48], 1
    if scenario == "invalid-json":
        return ["not-json"], [0.50], 1
    if scenario == "missing-section":
        proposal = (
            {
                "source_name": "not-target",
                "new_trust": 0.50,
                "reasoning": "Wrong source.",
                "expected_effect": "Should fail closed.",
            }
            if loop_type == "source"
            else {
                "description": "Missing section",
                "patch": "body",
                "section": "Does Not Exist",
                "reasoning": "Should fail closed.",
            }
        )
        return [json.dumps(proposal)], [0.50], 1
    if scenario == "tiny-deltas":
        proposals = (
            [
                {
                    "source_name": "threatfox",
                    "new_trust": 0.94,
                    "reasoning": f"Tiny delta {index}",
                    "expected_effect": "Very small change.",
                }
                for index in range(1, 4)
            ]
            if loop_type == "source"
            else [
                {
                    "description": f"Tiny delta {index}",
                    "patch": f"small tweak {index}\n",
                    "section": section,
                    "reasoning": "Very small change.",
                }
                for index in range(1, 4)
            ]
        )
        return [json.dumps(item) for item in proposals], [0.50, 0.5004, 0.50, 0.5002, 0.50, 0.5001], 10
    raise ValueError(f"Unsupported Karpathy validation scenario: {scenario}")


def _init_shadow_repo(loop_type: str) -> tuple[Path, Path, Path]:
    repo_root = Path(tempfile.mkdtemp(prefix=f"sentinel-karpathy-{loop_type}-"))
    skill_rel = LOOP_SKILL_PATHS[loop_type]
    skill_path = repo_root / skill_rel
    changelog_path = repo_root / "skills/CHANGELOG.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    changelog_path.parent.mkdir(parents=True, exist_ok=True)
    source_root = _resolve_repo_root()
    skill_path.write_text((source_root / skill_rel).read_text(encoding="utf-8"), encoding="utf-8")
    changelog_path.write_text((source_root / "skills/CHANGELOG.md").read_text(encoding="utf-8"), encoding="utf-8")
    (repo_root / "README.md").write_text("shadow karpathy repo\n", encoding="utf-8")
    repo = Repo.init(repo_root)
    repo.index.add(
        [
            "README.md",
            str(skill_rel),
            "skills/CHANGELOG.md",
        ]
    )
    repo.index.commit("init shadow repo")
    return repo_root, skill_path, changelog_path


async def run_shadow_karpathy_validation(
    *,
    loop_type: str,
    settings: SentinelSettings,
    scenario: str = "improve",
    max_experiments: int | None = None,
) -> KarpathyRunReport:
    repo_root, skill_path, changelog_path = _init_shadow_repo(loop_type)
    responses, metric_values, default_max = _build_shadow_scenario(loop_type, scenario)
    provider = _ScriptedProvider(responses)
    metric = _SequencedMetric(metric_values)
    session_factory = _ShadowLogSessionFactory()
    loop = build_karpathy_loop(
        loop_type=loop_type,
        settings=settings,
        provider=provider,
        repo_path=repo_root,
        skill_path=skill_path,
        changelog_path=changelog_path,
        session_factory=session_factory,
        metric_override=metric,
        target_source="threatfox" if loop_type == "source" else None,
    )
    repo = Repo(repo_root)
    baseline_head = repo.head.commit.hexsha
    try:
        outcomes = await loop.optimize(max_experiments=max_experiments or default_max)
        head_after = repo.head.commit.hexsha
        commits = [] if head_after == baseline_head else [head_after]
        metric_before = outcomes[0].metric_before if outcomes else None
        metric_after = outcomes[-1].metric_after if outcomes else None
        return KarpathyRunReport(
            loop_type=loop_type,
            mode="shadow",
            scenario=scenario,
            experiments_attempted=len(outcomes),
            kept=sum(1 for outcome in outcomes if outcome.kept),
            reverted=sum(1 for outcome in outcomes if not outcome.kept),
            metric_before=metric_before,
            metric_after=metric_after,
            affected_sections=[LOOP_PRIMARY_SECTIONS[loop_type]] if outcomes else [],
            commit_hashes=commits,
            worktree_path=str(repo_root),
            outcomes=outcomes,
            target_source="threatfox" if loop_type == "source" else None,
            feedback_count=outcomes[-1].feedback_count if outcomes else None,
            trust_before=outcomes[0].trust_before if outcomes else None,
            trust_after=outcomes[-1].trust_after if outcomes else None,
        )
    except Exception as exc:
        return KarpathyRunReport(
            loop_type=loop_type,
            mode="shadow",
            scenario=scenario,
            experiments_attempted=0,
            kept=0,
            reverted=0,
            metric_before=None,
            metric_after=None,
            affected_sections=[],
            commit_hashes=[],
            worktree_path=str(repo_root),
            error=str(exc),
            outcomes=[],
        )


async def inspect_live_karpathy_readiness(
    *,
    loop_type: str,
    settings: SentinelSettings,
    session_factory: Any | None = None,
) -> KarpathyReadinessReport:
    skill_path = LOOP_SKILL_PATHS[loop_type]
    changelog_path = Path("skills/CHANGELOG.md")
    checks: list[KarpathyCheck] = []
    counts: dict[str, int] = {}
    target_source: str | None = None
    cwd_root = Path.cwd().resolve()

    if loop_type != "source":
        reason = (
            "Live scoring optimization is disabled until scoring behavior is directly skill-driven."
            if loop_type == "scoring"
            else "Live detection optimization is disabled until downstream detection outcomes are meaningful."
        )
        checks.append(KarpathyCheck(name="live_supported", passed=False, detail=reason))
        return KarpathyReadinessReport(
            loop_type=loop_type,
            ready=False,
            skill_path=str(cwd_root / skill_path),
            changelog_path=str(cwd_root / changelog_path),
            checks=checks,
            counts=counts,
            current_branch=None,
            target_source=None,
        )

    checks.append(
        KarpathyCheck(
            name="openai_api_key",
            passed=bool(settings.openai.api_key.strip()) and not settings.openai.api_key.startswith("${"),
            detail="OpenAI provider key is configured." if not settings.openai.api_key.startswith("${") else "OPENAI_API_KEY is missing.",
        )
    )

    try:
        repo = Repo(Path.cwd(), search_parent_directories=True)
        repo_root = Path(repo.working_tree_dir).resolve()
        current_branch = repo.active_branch.name if not repo.head.is_detached else "DETACHED"
        checks.append(KarpathyCheck(name="git_repo", passed=True, detail=f"Detected git repo at {repo_root}"))
    except InvalidGitRepositoryError:
        repo = None
        repo_root = Path.cwd().resolve()
        current_branch = None
        checks.append(KarpathyCheck(name="git_repo", passed=False, detail="No git repository detected."))

    resolved_skill = repo_root / skill_path
    resolved_changelog = repo_root / changelog_path
    checks.append(
        KarpathyCheck(
            name="skill_file",
            passed=resolved_skill.exists(),
            detail=f"{resolved_skill} exists" if resolved_skill.exists() else f"{resolved_skill} is missing",
        )
    )
    checks.append(
        KarpathyCheck(
            name="skills_changelog",
            passed=resolved_changelog.exists(),
            detail=f"{resolved_changelog} exists" if resolved_changelog.exists() else f"{resolved_changelog} is missing",
        )
    )

    if repo is not None and resolved_skill.exists() and resolved_changelog.exists():
        for path, name in ((resolved_skill, "tracked_skill"), (resolved_changelog, "tracked_changelog")):
            relative = str(path.relative_to(repo_root))
            try:
                repo.git.ls_files("--error-unmatch", relative)
                checks.append(KarpathyCheck(name=name, passed=True, detail=f"{relative} is tracked"))
            except GitCommandError:
                checks.append(KarpathyCheck(name=name, passed=False, detail=f"{relative} must be committed before live loop runs"))
        dirty_paths = {item.a_path for item in repo.index.diff(None)}
        for path, name in ((resolved_skill, "clean_skill"), (resolved_changelog, "clean_changelog")):
            relative = str(path.relative_to(repo_root))
            checks.append(
                KarpathyCheck(
                    name=name,
                    passed=relative not in dirty_paths,
                    detail=f"{relative} is clean" if relative not in dirty_paths else f"{relative} has uncommitted tracked changes",
                )
            )

    if not all(check.passed for check in checks):
        return KarpathyReadinessReport(
            loop_type=loop_type,
            ready=False,
            skill_path=str(resolved_skill),
            changelog_path=str(resolved_changelog),
            checks=checks,
            counts=counts,
            current_branch=current_branch,
            target_source=target_source,
        )

    active_session_factory = session_factory or AsyncSessionFactory
    cutoff = datetime.now(UTC) - timedelta(hours=48)
    async with active_session_factory() as session:
        if loop_type == "source":
            if hasattr(session, "feedback_rows"):
                feedback_rows = [row for row in session.feedback_rows if row["verdict"] in {"confirmed", "false_positive"}]
            else:
                query = (
                    select(FeedbackRecord.verdict, IOC.source)
                    .select_from(FeedbackRecord)
                    .join(IOC, IOC.id == FeedbackRecord.ioc_id)
                    .where(FeedbackRecord.timestamp >= cutoff)
                    .where(FeedbackRecord.verdict.in_(["confirmed", "false_positive"]))
                )
                feedback_rows = [
                    {"verdict": verdict, "source": source}
                    for verdict, source in (await session.execute(query)).all()
                ]
            counts["feedback_rows"] = len(feedback_rows)
            counts["distinct_sources"] = len({row.get("source", "unknown") for row in feedback_rows})
            per_source: dict[str, dict[str, int]] = {}
            for row in feedback_rows:
                source = row.get("source") or "unknown"
                bucket = per_source.setdefault(source, {"confirmed": 0, "false_positive": 0})
                bucket[row["verdict"]] += 1
            minimums = LIVE_DATA_THRESHOLDS["source"]
            candidates: list[tuple[str, float, int]] = []
            for source, stats in per_source.items():
                total = stats["confirmed"] + stats["false_positive"]
                if total < minimums["feedback_rows"]:
                    continue
                if not stats["confirmed"] or not stats["false_positive"]:
                    continue
                fp_rate = stats["false_positive"] / total
                candidates.append((source, fp_rate, total))
            if candidates:
                target_source, _, feedback_count = sorted(candidates, key=lambda item: (-item[1], -item[2], item[0]))[0]
                counts["target_source_feedback_rows"] = feedback_count
            minimums = LIVE_DATA_THRESHOLDS["source"]
            checks.append(
                KarpathyCheck(
                    name="feedback_window",
                    passed=counts["feedback_rows"] >= minimums["feedback_rows"],
                    detail=f"Need >= {minimums['feedback_rows']} recent confirmed/false_positive rows.",
                )
            )
            checks.append(
                KarpathyCheck(
                    name="source_diversity",
                    passed=counts["distinct_sources"] >= minimums["distinct_sources"],
                    detail=f"Need >= {minimums['distinct_sources']} distinct sources in the 48h window.",
                )
            )
            checks.append(
                KarpathyCheck(
                    name="target_source_selected",
                    passed=target_source is not None,
                    detail="Selected highest-false-positive eligible source for optimization." if target_source else "No source met the live source-loop eligibility threshold.",
                )
            )
            if target_source is not None:
                skill_text = resolved_skill.read_text(encoding="utf-8") if resolved_skill.exists() else ""
                checks.append(
                    KarpathyCheck(
                        name="target_source_in_skill",
                        passed=f"- {target_source}:" in skill_text,
                        detail=f"{target_source} exists in the Trust Scores section." if f"- {target_source}:" in skill_text else f"{target_source} is missing from Trust Scores.",
                    )
                )
            checks.append(
                KarpathyCheck(
                    name="verdict_mix",
                    passed=target_source is not None,
                    detail="Target source has both confirmed and false_positive verdicts." if target_source else "Need both confirmed and false_positive verdicts for at least one source.",
                )
            )

    ready = all(check.passed for check in checks)
    return KarpathyReadinessReport(
        loop_type=loop_type,
        ready=ready,
        skill_path=str(resolved_skill),
        changelog_path=str(resolved_changelog),
        checks=checks,
        counts=counts,
        current_branch=current_branch,
        target_source=target_source,
    )


def prepare_ephemeral_loop_workspace(*, loop_type: str, target_source: str | None = None) -> tuple[str, Path]:
    repo = Repo(Path.cwd(), search_parent_directories=True)
    repo_root = Path(repo.working_tree_dir).resolve()
    runs_dir = repo_root / ".karpathy_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    branch_name = _build_source_branch_name(target_source, now=datetime.now(UTC)) if loop_type == "source" and target_source else _build_branch_name(loop_type)
    worktree_path = runs_dir / branch_name
    subprocess.run(
        ["git", "worktree", "add", "-b", branch_name, str(worktree_path), "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return branch_name, worktree_path


async def run_live_karpathy_loop(
    *,
    loop_type: str,
    settings: SentinelSettings,
    max_experiments: int | None = None,
    session_factory: Any | None = None,
) -> tuple[KarpathyReadinessReport, KarpathyRunReport | None]:
    readiness = await inspect_live_karpathy_readiness(
        loop_type=loop_type,
        settings=settings,
        session_factory=session_factory,
    )
    if not readiness.ready:
        return readiness, None
    branch_name, worktree_path = prepare_ephemeral_loop_workspace(loop_type=loop_type, target_source=readiness.target_source)
    loop = build_karpathy_loop(
        loop_type=loop_type,
        settings=settings,
        repo_path=worktree_path,
        skill_path=worktree_path / LOOP_SKILL_PATHS[loop_type],
        changelog_path=worktree_path / "skills/CHANGELOG.md",
        session_factory=session_factory,
        target_source=readiness.target_source,
    )
    outcomes = await loop.optimize(max_experiments=max_experiments or settings.thresholds.karpathy_experiments)
    repo = Repo(worktree_path)
    initial_commit = repo.head.commit.hexsha
    commits = [initial_commit] if outcomes and any(outcome.kept for outcome in outcomes) else []
    report = KarpathyRunReport(
        loop_type=loop_type,
        mode="live",
        experiments_attempted=len(outcomes),
        kept=sum(1 for outcome in outcomes if outcome.kept),
        reverted=sum(1 for outcome in outcomes if not outcome.kept),
        metric_before=outcomes[0].metric_before if outcomes else None,
        metric_after=outcomes[-1].metric_after if outcomes else None,
        affected_sections=[LOOP_PRIMARY_SECTIONS[loop_type]] if outcomes else [],
        commit_hashes=commits,
        branch_name=branch_name,
        worktree_path=str(worktree_path),
        outcomes=outcomes,
        target_source=readiness.target_source,
        feedback_count=readiness.counts.get("target_source_feedback_rows"),
        trust_before=outcomes[0].trust_before if outcomes else None,
        trust_after=outcomes[-1].trust_after if outcomes else None,
    )
    return readiness, report


async def load_real_sample_iocs(
    *,
    ioc_types: Sequence[str],
    limit: int,
) -> list[dict[str, Any]]:
    normalized_types = [ioc_type.lower() for ioc_type in ioc_types]
    async with AsyncSessionFactory() as session:
        rows = list(
            (
                await session.scalars(
                    select(IOC)
                    .where(IOC.type.in_(normalized_types))
                    .order_by(IOC.risk_score.desc().nullslast(), IOC.last_seen.desc())
                    .limit(limit)
                )
            ).all()
        )
    items: list[dict[str, Any]] = []
    for row in rows:
        payload = {
            "id": str(row.id),
            "value": row.value,
            "type": row.type,
            "source": row.source,
            "risk_score": float(row.risk_score or 0.0),
            "severity": row.severity or "informational",
            "source_title": row.source_title,
            "reference_url": row.reference_url,
            "related_cves": list(row.related_cves or []),
            "vt_detections": row.vt_detections,
            "abuse_confidence": row.abuse_confidence,
            "shodan_ports": list(row.shodan_ports or []),
            "mitre_techniques": list(row.mitre_techniques or []),
            "mitre_tactics": list(row.mitre_tactics or []),
            "last_seen": row.last_seen,
        }
        payload["external_links"] = build_external_links_for_ioc(payload)
        items.append(payload)
    return items

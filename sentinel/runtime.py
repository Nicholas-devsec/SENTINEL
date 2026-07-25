from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
import json
import socket
import subprocess
import tempfile
import uuid
from typing import Any, Sequence

from git import GitCommandError, InvalidGitRepositoryError, Repo
from sqlalchemy import case, func, select

from sentinel.agents.scorer import build_external_links_for_ioc
from sentinel.config import SentinelSettings
from sentinel.db.models import (
    AlertEvent,
    ExperimentLog,
    FeedbackRecord,
    IOC,
    IOCSighting,
    PipelineRun,
    ServiceLease,
    SourceMaterial,
)
from sentinel.db.session import AsyncSessionFactory
from sentinel.loops.detection_loop import DetectionEffectivenessLoop
from sentinel.loops.karpathy_loop import ExperimentOutcome
from sentinel.loops.providers.openai_provider import OpenAIProvider
from sentinel.loops.scoring_loop import ScoreCalibrationLoop
from sentinel.loops.source_loop import SourceQualityLoop
from sentinel.feedback import DISCOVERY_MEMORY_VERDICTS, FALSE_POSITIVE, LEARNING_VERDICTS, normalize_verdict, positive_weight

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


def _sample_campaign_key(item: dict[str, Any]) -> str:
    reference_url = str(item.get("reference_url") or "").strip().lower()
    if reference_url:
        return f"reference:{reference_url}"
    source = str(item.get("source") or "").strip().lower()
    source_title = str(item.get("source_title") or "").strip().lower()
    if source_title:
        return f"title:{source}:{source_title}"
    return f"ioc:{source}:{item.get('type')}:{item.get('value')}"


def _diversify_ioc_samples(items: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    seen_campaigns: set[str] = set()
    for item in items:
        item_id = str(item.get("id") or f"{item.get('type')}|{item.get('value')}")
        campaign_key = _sample_campaign_key(item)
        if campaign_key in seen_campaigns or item_id in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(item_id)
        seen_campaigns.add(campaign_key)
        if len(selected) >= limit:
            return selected
    for item in items:
        item_id = str(item.get("id") or f"{item.get('type')}|{item.get('value')}")
        if item_id in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(item_id)
        if len(selected) >= limit:
            break
    return selected


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
    merged_commit_hashes: list[str] = field(default_factory=list)
    cleanup_status: str | None = None
    lock_status: str | None = None


@dataclass(slots=True)
class KarpathyStatusEntry:
    loop_type: str
    experiment_number: int
    kept: bool
    delta: float
    timestamp: datetime
    target: str | None
    eval_mode: str | None
    details: dict[str, Any]


@dataclass(slots=True)
class KarpathyStatusReport:
    readiness: KarpathyReadinessReport
    active_lease: dict[str, Any] | None
    recent_runs: list[KarpathyStatusEntry]


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
            + (f" keep_reason={payload.get('keep_reason')}" if payload.get("keep_reason") else "")
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
    if getattr(report, "merged_commit_hashes", None):
        lines.append(f"- merged_commit_hashes={', '.join(report.merged_commit_hashes)}")
    if getattr(report, "cleanup_status", None):
        lines.append(f"- cleanup={report.cleanup_status}")
    if getattr(report, "lock_status", None):
        lines.append(f"- lock_status={report.lock_status}")
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


def format_karpathy_status(report: KarpathyStatusReport) -> str:
    lines = [format_karpathy_readiness(report.readiness)]
    if report.active_lease is not None:
        lines.append(
            "Active lease: "
            f"name={report.active_lease['lease_name']} holder={report.active_lease['holder_id']} "
            f"expires_at={report.active_lease['expires_at']}"
        )
    else:
        lines.append("Active lease: none")
    if not report.recent_runs:
        lines.append("Recent runs: none")
        return "\n".join(lines)
    lines.append("Recent runs:")
    for entry in report.recent_runs:
        keep_reason = str(entry.details.get("keep_decision", {}).get("reason") or "n/a")
        lines.append(
            f"- {entry.timestamp.isoformat()} loop={entry.loop_type} experiment={entry.experiment_number} "
            f"kept={str(entry.kept).lower()} delta={entry.delta:.4f} target={entry.target or 'n/a'} "
            f"mode={entry.eval_mode or 'n/a'} reason={keep_reason}"
        )
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
                feedback_rows = [
                    {**row, "verdict": normalize_verdict(row["verdict"])}
                    for row in session.feedback_rows
                    if normalize_verdict(row["verdict"]) in LEARNING_VERDICTS
                ]
            else:
                query = (
                    select(FeedbackRecord.verdict, FeedbackRecord.source, IOC.source)
                    .select_from(FeedbackRecord)
                    .join(IOC, IOC.id == FeedbackRecord.ioc_id)
                    .where(FeedbackRecord.timestamp >= cutoff)
                    .where(FeedbackRecord.verdict.in_(sorted(LEARNING_VERDICTS)))
                )
                feedback_rows = [
                    {"verdict": verdict, "source": (feedback_source or ioc_source)}
                    for verdict, feedback_source, ioc_source in (await session.execute(query)).all()
                ]
            counts["feedback_rows"] = len(feedback_rows)
            counts["distinct_sources"] = len({row.get("source", "unknown") for row in feedback_rows})
            per_source: dict[str, dict[str, float]] = {}
            for row in feedback_rows:
                source = row.get("source") or "unknown"
                bucket = per_source.setdefault(source, {"positive": 0.0, "false_positive": 0.0, "rows": 0.0})
                bucket["rows"] += 1.0
                if row["verdict"] == FALSE_POSITIVE:
                    bucket["false_positive"] += 1.0
                else:
                    bucket["positive"] += positive_weight(row["verdict"])
            minimums = LIVE_DATA_THRESHOLDS["source"]
            candidates: list[tuple[str, float, int]] = []
            for source, stats in per_source.items():
                total = int(stats["rows"])
                if total < minimums["feedback_rows"]:
                    continue
                if not stats["positive"] or not stats["false_positive"]:
                    continue
                fp_rate = stats["false_positive"] / (stats["positive"] + stats["false_positive"])
                candidates.append((source, fp_rate, total))
            if candidates:
                target_source, _, feedback_count = sorted(candidates, key=lambda item: (-item[1], -item[2], item[0]))[0]
                counts["target_source_feedback_rows"] = feedback_count
            minimums = LIVE_DATA_THRESHOLDS["source"]
            checks.append(
                KarpathyCheck(
                    name="feedback_window",
                    passed=counts["feedback_rows"] >= minimums["feedback_rows"],
                    detail=f"Need >= {minimums['feedback_rows']} recent TP/low-level TP/false_positive rows.",
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
                    detail="Target source has both positive and false_positive verdicts." if target_source else "Need both positive and false_positive verdicts for at least one source.",
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


def _karpathy_lease_name(loop_type: str) -> str:
    return f"karpathy:{loop_type}"


async def _try_acquire_karpathy_lease(
    *,
    loop_type: str,
    settings: SentinelSettings,
    session_factory: Any | None = None,
    now_fn: Any | None = None,
) -> tuple[bool, str]:
    active_session_factory = session_factory or AsyncSessionFactory
    now_provider = now_fn or (lambda: datetime.now(UTC))
    holder_id = f"{socket.gethostname()}:{uuid.uuid4()}"
    lease_name = _karpathy_lease_name(loop_type)
    expires_at = now_provider() + timedelta(seconds=int(settings.karpathy.lease_ttl_seconds))
    async with active_session_factory() as session:
        if hasattr(session, "leases"):
            current = session.leases.get(lease_name)
            if current is not None and current["expires_at"] > now_provider():
                return False, str(current["holder_id"])
            session.leases[lease_name] = {
                "lease_name": lease_name,
                "holder_id": holder_id,
                "acquired_at": now_provider(),
                "expires_at": expires_at,
            }
            return True, holder_id
        row = await session.get(ServiceLease, lease_name)
        if row is not None and row.expires_at > now_provider():
            return False, row.holder_id
        if row is None:
            row = ServiceLease(
                lease_name=lease_name,
                holder_id=holder_id,
                acquired_at=now_provider(),
                expires_at=expires_at,
                metadata_json={"loop_type": loop_type},
            )
            session.add(row)
        else:
            row.holder_id = holder_id
            row.acquired_at = now_provider()
            row.expires_at = expires_at
            row.metadata_json = {"loop_type": loop_type}
        await session.commit()
        return True, holder_id


async def _release_karpathy_lease(
    *,
    loop_type: str,
    holder_id: str,
    session_factory: Any | None = None,
) -> None:
    active_session_factory = session_factory or AsyncSessionFactory
    lease_name = _karpathy_lease_name(loop_type)
    async with active_session_factory() as session:
        if hasattr(session, "leases"):
            current = session.leases.get(lease_name)
            if current is not None and current["holder_id"] == holder_id:
                session.leases.pop(lease_name, None)
            return
        row = await session.get(ServiceLease, lease_name)
        if row is None or row.holder_id != holder_id:
            return
        await session.delete(row)
        await session.commit()


async def inspect_karpathy_status(
    *,
    loop_type: str,
    settings: SentinelSettings,
    session_factory: Any | None = None,
    limit: int | None = None,
) -> KarpathyStatusReport:
    readiness = await inspect_live_karpathy_readiness(
        loop_type=loop_type,
        settings=settings,
        session_factory=session_factory,
    )
    active_session_factory = session_factory or AsyncSessionFactory
    active_lease: dict[str, Any] | None = None
    recent_runs: list[KarpathyStatusEntry] = []
    history_limit = int(limit or settings.karpathy.status_history_limit)
    async with active_session_factory() as session:
        if hasattr(session, "leases"):
            lease = session.leases.get(_karpathy_lease_name(loop_type))
            if lease is not None:
                active_lease = dict(lease)
            rows = list(getattr(session, "experiment_logs", []))[-history_limit:]
            rows.reverse()
            for row in rows:
                if row.get("loop_type") != loop_type:
                    continue
                recent_runs.append(
                    KarpathyStatusEntry(
                        loop_type=row["loop_type"],
                        experiment_number=row["experiment_number"],
                        kept=bool(row["kept"]),
                        delta=float(row["delta"]),
                        timestamp=row["timestamp"],
                        target=row.get("target"),
                        eval_mode=row.get("eval_mode"),
                        details=dict(row.get("details", {})),
                    )
                )
            return KarpathyStatusReport(readiness=readiness, active_lease=active_lease, recent_runs=recent_runs)

        lease = await session.get(ServiceLease, _karpathy_lease_name(loop_type))
        if lease is not None:
            active_lease = {
                "lease_name": lease.lease_name,
                "holder_id": lease.holder_id,
                "expires_at": lease.expires_at.isoformat(),
            }
        query = (
            select(ExperimentLog)
            .where(ExperimentLog.loop_type == loop_type)
            .order_by(ExperimentLog.timestamp.desc())
            .limit(history_limit)
        )
        rows = list((await session.scalars(query)).all())
        for row in rows:
            recent_runs.append(
                KarpathyStatusEntry(
                    loop_type=row.loop_type,
                    experiment_number=row.experiment_number,
                    kept=row.kept,
                    delta=row.delta,
                    timestamp=row.timestamp,
                    target=row.target,
                    eval_mode=row.eval_mode,
                    details=dict(row.details or {}),
                )
            )
    return KarpathyStatusReport(readiness=readiness, active_lease=active_lease, recent_runs=recent_runs)


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


def _commit_range(repo: Repo, *, base_commit: str, branch_name: str) -> list[str]:
    revs = list(repo.iter_commits(f"{base_commit}..{branch_name}"))
    revs.reverse()
    return [commit.hexsha for commit in revs]


def _abort_cherry_pick_if_needed(repo: Repo) -> bool:
    cherry_pick_head = Path(repo.git_dir) / "CHERRY_PICK_HEAD"
    if not cherry_pick_head.exists():
        return False
    repo.git.cherry_pick("--abort")
    return True


def _cleanup_ephemeral_workspace(
    *,
    branch_name: str,
    worktree_path: Path,
    preserve_branch: bool,
) -> str:
    repo = Repo(Path.cwd(), search_parent_directories=True)
    cleanup_notes: list[str] = []
    if worktree_path.exists():
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree_path)],
            cwd=repo.working_tree_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        cleanup_notes.append("worktree-removed")
    else:
        cleanup_notes.append("worktree-missing")
    if preserve_branch:
        cleanup_notes.append("branch-preserved")
    else:
        repo.git.branch("-D", branch_name)
        cleanup_notes.append("branch-deleted")
    return ",".join(cleanup_notes)


def _finalize_live_worktree(
    *,
    loop_type: str,
    branch_name: str,
    worktree_path: Path,
    base_commit: str,
) -> tuple[list[str], str]:
    repo = Repo(Path.cwd(), search_parent_directories=True)
    merged_commit_hashes = _commit_range(repo, base_commit=base_commit, branch_name=branch_name)
    merge_notes: list[str] = []
    preserve_branch = False
    merge_error: str | None = None
    try:
        if merged_commit_hashes:
            for commit_hash in merged_commit_hashes:
                repo.git.cherry_pick(commit_hash)
            merge_notes.append("merged")
        else:
            merge_notes.append(f"no-kept-{loop_type}-commits")
    except GitCommandError as exc:
        aborted = _abort_cherry_pick_if_needed(repo)
        merge_notes.append("merge-conflict-aborted" if aborted else "merge-failed")
        preserve_branch = True
        merge_error = str(exc)
    finally:
        cleanup_status = _cleanup_ephemeral_workspace(
            branch_name=branch_name,
            worktree_path=worktree_path,
            preserve_branch=preserve_branch,
        )
        merge_notes.append(cleanup_status)
    if merge_error:
        merge_notes.append(f"error={merge_error}")
    return merged_commit_hashes, ",".join(merge_notes)


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
    lease_acquired, lease_holder = await _try_acquire_karpathy_lease(
        loop_type=loop_type,
        settings=settings,
        session_factory=session_factory,
    )
    if not lease_acquired:
        return readiness, KarpathyRunReport(
            loop_type=loop_type,
            mode="live",
            experiments_attempted=0,
            kept=0,
            reverted=0,
            metric_before=None,
            metric_after=None,
            affected_sections=[],
            commit_hashes=[],
            branch_name=None,
            worktree_path=None,
            outcomes=[],
            target_source=readiness.target_source,
            feedback_count=readiness.counts.get("target_source_feedback_rows"),
            merged_commit_hashes=[],
            cleanup_status=None,
            error=f"lease-held-by:{lease_holder}",
            lock_status=f"lease-held-by:{lease_holder}",
        )
    branch_name, worktree_path = prepare_ephemeral_loop_workspace(loop_type=loop_type, target_source=readiness.target_source)
    parent_repo = Repo(Path.cwd(), search_parent_directories=True)
    base_commit = parent_repo.head.commit.hexsha
    outcomes: list[ExperimentOutcome] = []
    commits: list[str] = []
    merged_commit_hashes: list[str] = []
    cleanup_status: str | None = None
    error: str | None = None
    try:
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
        worktree_repo = Repo(worktree_path)
        commits = _commit_range(worktree_repo, base_commit=base_commit, branch_name=branch_name)
        merged_commit_hashes, cleanup_status = _finalize_live_worktree(
            loop_type=loop_type,
            branch_name=branch_name,
            worktree_path=worktree_path,
            base_commit=base_commit,
        )
        if "merge-conflict-aborted" in cleanup_status or "merge-failed" in cleanup_status:
            error = cleanup_status
    except Exception as exc:
        error = str(exc)
        if cleanup_status is None:
            try:
                cleanup_status = _cleanup_ephemeral_workspace(
                    branch_name=branch_name,
                    worktree_path=worktree_path,
                    preserve_branch=bool(commits),
                )
            except Exception as cleanup_exc:
                cleanup_status = f"cleanup-failed:{cleanup_exc}"
    finally:
        await _release_karpathy_lease(
            loop_type=loop_type,
            holder_id=lease_holder,
            session_factory=session_factory,
        )
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
        merged_commit_hashes=merged_commit_hashes,
        cleanup_status=cleanup_status,
        error=error,
        lock_status=f"acquired:{lease_holder}",
    )
    return readiness, report


@dataclass(slots=True)
class OpsStatusReport:
    pipeline_runs: list[dict[str, Any]]
    alerts_24h: dict[str, int]
    feedback_7d: dict[str, int]
    recent_experiments: list[dict[str, Any]]


async def collect_ops_status(*, limit: int = 5, session_factory: Any | None = None) -> OpsStatusReport:
    """One-query-away operational answer to 'is the pipeline healthy?'."""
    factory = session_factory or AsyncSessionFactory
    now = datetime.now(UTC)
    async with factory() as session:
        runs = list(
            (
                await session.scalars(
                    select(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(limit)
                )
            ).all()
        )
        alert_rows = (
            await session.execute(
                select(AlertEvent.alert_kind, func.count())
                .where(AlertEvent.sent_at >= now - timedelta(hours=24))
                .group_by(AlertEvent.alert_kind)
            )
        ).all()
        feedback_rows = (
            await session.execute(
                select(FeedbackRecord.verdict, func.count())
                .where(FeedbackRecord.timestamp >= now - timedelta(days=7))
                .group_by(FeedbackRecord.verdict)
            )
        ).all()
        experiments = list(
            (
                await session.scalars(
                    select(ExperimentLog).order_by(ExperimentLog.timestamp.desc()).limit(limit)
                )
            ).all()
        )
    return OpsStatusReport(
        pipeline_runs=[
            {
                "started_at": run.started_at,
                "finished_at": run.finished_at,
                "status": run.status,
                "counts": dict(run.counts or {}),
                "total_seconds": (run.stage_durations or {}).get("total"),
                "error": run.error,
            }
            for run in runs
        ],
        alerts_24h={kind: int(count) for kind, count in alert_rows},
        feedback_7d={verdict: int(count) for verdict, count in feedback_rows},
        recent_experiments=[
            {
                "timestamp": experiment.timestamp,
                "loop_type": experiment.loop_type,
                "kept": experiment.kept,
                "delta": experiment.delta,
                "target": experiment.target,
            }
            for experiment in experiments
        ],
    )


def format_ops_status(report: OpsStatusReport) -> str:
    lines = ["SENTINEL status", "", "Recent pipeline runs:"]
    if not report.pipeline_runs:
        lines.append("- none recorded")
    for run in report.pipeline_runs:
        counts = run["counts"]
        summary = (
            f"scraped={counts.get('scraped', 0)} validated={counts.get('validated', 0)} "
            f"alerts={counts.get('immediate_alerts', 0)} digest_candidates={counts.get('digest_candidates', 0)}"
        )
        duration = f" duration={run['total_seconds']}s" if run.get("total_seconds") is not None else ""
        error = f" error={run['error']}" if run.get("error") else ""
        lines.append(
            f"- {run['started_at'].isoformat()} status={run['status']} {summary}{duration}{error}"
        )
    lines.append("")
    alerts = ", ".join(f"{kind}={count}" for kind, count in sorted(report.alerts_24h.items())) or "none"
    lines.append(f"Alerts sent (24h): {alerts}")
    feedback = ", ".join(f"{verdict}={count}" for verdict, count in sorted(report.feedback_7d.items())) or "none"
    lines.append(f"Analyst feedback (7d): {feedback}")
    lines.append("")
    lines.append("Recent Karpathy experiments:")
    if not report.recent_experiments:
        lines.append("- none recorded")
    for experiment in report.recent_experiments:
        lines.append(
            f"- {experiment['timestamp'].isoformat()} loop={experiment['loop_type']} "
            f"target={experiment['target'] or 'n/a'} kept={str(experiment['kept']).lower()} delta={experiment['delta']:.4f}"
        )
    return "\n".join(lines)


async def load_real_sample_iocs(
    *,
    ioc_types: Sequence[str],
    limit: int,
    provenance: str | None = None,
) -> list[dict[str, Any]]:
    normalized_types = [ioc_type.lower() for ioc_type in ioc_types]
    candidate_limit = max(limit * 10, limit)
    items: list[dict[str, Any]] = []
    async with AsyncSessionFactory() as session:
        feedback_labeled_ids = select(FeedbackRecord.ioc_id).where(
            FeedbackRecord.verdict.in_(sorted(DISCOVERY_MEMORY_VERDICTS))
        )
        telegram_alerted_ids = select(AlertEvent.ioc_id).where(AlertEvent.channel == "telegram")
        if provenance is None:
            query = (
                select(IOC)
                .where(IOC.type.in_(normalized_types))
                .where(IOC.analyst_verdict.is_(None))
                .where(~IOC.id.in_(feedback_labeled_ids))
                .where(~IOC.id.in_(telegram_alerted_ids))
                .order_by(IOC.risk_score.desc().nullslast(), IOC.last_seen.desc())
                .limit(candidate_limit)
            )
            rows = list((await session.scalars(query)).all())
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
            return _diversify_ioc_samples(items, limit=limit)

        query = (
            select(IOCSighting, IOC, SourceMaterial)
            .join(IOC, IOCSighting.ioc_id == IOC.id)
            .outerjoin(SourceMaterial, IOCSighting.source_material_id == SourceMaterial.id)
            .where(IOC.type.in_(normalized_types))
            .where(IOCSighting.provenance == provenance)
            .where(IOC.analyst_verdict.is_(None))
            .where(~IOC.id.in_(feedback_labeled_ids))
            .where(~IOC.id.in_(telegram_alerted_ids))
            .order_by(IOC.risk_score.desc().nullslast(), IOCSighting.last_seen.desc())
            .limit(candidate_limit)
        )
        rows = list((await session.execute(query)).all())

    for sighting, row, source_material in rows:
        payload = {
            "id": str(row.id),
            "value": row.value,
            "type": row.type,
            "source": sighting.source,
            "risk_score": float(row.risk_score or 0.0),
            "severity": row.severity or "informational",
            "source_title": (source_material.title if source_material else None) or row.source_title,
            "reference_url": sighting.reference_url or row.reference_url,
            "related_cves": list(row.related_cves or []),
            "vt_detections": row.vt_detections,
            "abuse_confidence": row.abuse_confidence,
            "shodan_ports": list(row.shodan_ports or []),
            "mitre_techniques": list(row.mitre_techniques or []),
            "mitre_tactics": list(row.mitre_tactics or []),
            "last_seen": sighting.last_seen,
        }
        payload["external_links"] = build_external_links_for_ioc(payload)
        items.append(payload)
    return _diversify_ioc_samples(items, limit=limit)

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Uuid
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    value: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    dedupe_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source_trust: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    related_cves: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vt_detections: Mapped[int | None] = mapped_column(Integer, nullable=True)
    shodan_ports: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    abuse_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    sigma_rule: Mapped[str | None] = mapped_column(Text, nullable=True)
    crowdstrike_pushed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    analyst_verdict: Mapped[str | None] = mapped_column(String(64), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vt_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Per-component contribution (in score points) of the last computed
    # risk_score, e.g. {"context": 30.0, "corroboration": 10.0, ...}. Makes
    # every score explainable to an analyst and auditable after the fact.
    score_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class SourceMaterial(Base, TimestampMixin):
    """A writeup, blog post, advisory, or report that IOCs can be extracted from.

    Articles are source material, not indicators. IOCs extracted from an article
    link back here through IOCSighting.source_material_id.
    """

    __tablename__ = "source_materials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    content_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    extraction_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    extracted_ioc_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class IOCSighting(Base, TimestampMixin):
    """One source observing one canonical IOC.

    The IOC row stays canonical (unique dedupe_hash); every source occurrence
    lands here instead of being discarded, so lineage and corroboration survive
    deduplication. lineage_hash makes (ioc, source, provenance, reference)
    idempotent across pipeline runs; repeats bump sighting_count/last_seen.
    """

    __tablename__ = "ioc_sightings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(Uuid(), ForeignKey("iocs.id"), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source_trust: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default="feed")
    reference_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    source_material_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(), ForeignKey("source_materials.id"), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sighting_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    lineage_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    @staticmethod
    def build_lineage_hash(
        *, ioc_id: uuid.UUID, source: str, provenance: str, reference_url: str | None
    ) -> str:
        raw = f"{ioc_id}|{source.lower()}|{provenance}|{reference_url or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DiscoveryMemory(Base, TimestampMixin):
    """What the discovery pipeline has learned from analyst verdicts.

    One row per (kind, key, profile) aggregate — e.g. kind="source",
    key="gbhackers_blog", profile="crimeware-fresh" — with TP/FP counts folded
    in from Telegram feedback on discovery-derived alerts. `score` is the
    Laplace-smoothed precision used as a triage weight and as a surface the
    Karpathy loop can optimize against.
    """

    __tablename__ = "discovery_memory"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    key: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confirmed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positive: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    needs_review: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    memory_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    @staticmethod
    def build_memory_hash(*, kind: str, key: str, profile: str | None) -> str:
        raw = f"{kind}|{key.lower()}|{profile or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def laplace_score(confirmed: float, false_positive: float) -> float:
        return (confirmed + 1) / (confirmed + false_positive + 2)


class Source(Base, TimestampMixin):
    __tablename__ = "sources"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    trust: Mapped[float] = mapped_column(Float, nullable=False)
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class FeedbackRecord(Base, TimestampMixin):
    __tablename__ = "feedback_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(Uuid(), ForeignKey("iocs.id"), nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(255), nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    channel: Mapped[str] = mapped_column(String(64), nullable=False)
    # Snapshot of the IOC's originating source at feedback time; survives later
    # corroboration by additional sources.
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ExperimentLog(Base, TimestampMixin):
    __tablename__ = "experiment_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    loop_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    experiment_number: Mapped[int] = mapped_column(Integer, nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    patch_applied: Mapped[str] = mapped_column(Text, nullable=False)
    metric_before: Mapped[float] = mapped_column(Float, nullable=False)
    metric_after: Mapped[float] = mapped_column(Float, nullable=False)
    delta: Mapped[float] = mapped_column(Float, nullable=False)
    kept: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    eval_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class AlertEvent(Base, TimestampMixin):
    """One alert actually delivered for one IOC on one channel.

    The delivery layer consults this ledger before sending so the same
    indicator is never re-alerted across pipeline runs (immediate) or
    double-counted between immediate alerts and the daily digest, until the
    configured resend window has elapsed.
    """

    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(Uuid(), ForeignKey("iocs.id"), index=True, nullable=False)
    channel: Mapped[str] = mapped_column(String(64), nullable=False, default="telegram")
    alert_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="immediate")
    reference_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)


class PipelineRun(Base, TimestampMixin):
    """Operational ledger: one row per pipeline execution.

    Persists what each run actually did (stage counts, durations, outcome) so
    operators can answer "did last night's run work, and what did it send?"
    from the database instead of grepping logs.
    """

    __tablename__ = "pipeline_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    stage_durations: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ServiceLease(Base, TimestampMixin):
    __tablename__ = "service_leases"

    lease_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    holder_id: Mapped[str] = mapped_column(String(255), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

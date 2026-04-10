from __future__ import annotations

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

from __future__ import annotations

from sqlalchemy import select

from sentinel.db.models import FeedbackRecord, IOC
from sentinel.loops.karpathy_loop import ThreatIntelLoop


class SourceQualityLoop(ThreatIntelLoop):
    loop_type = "source"

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        async with self.session_factory() as session:
            if hasattr(session, "feedback_rows"):
                rows = [row for row in session.feedback_rows if row["verdict"] in {"confirmed", "false_positive"}]
                total = len(rows)
                positives = sum(1 for row in rows if row["verdict"] == "confirmed")
                return positives / total if total else 0.0
            cutoff = self.now_fn() - __import__("datetime").timedelta(hours=48)
            query = (
                select(FeedbackRecord)
                .where(FeedbackRecord.timestamp >= cutoff)
                .where(FeedbackRecord.verdict.in_(["confirmed", "false_positive"]))
            )
            rows = list((await session.scalars(query)).all())
            total = len(rows)
            positives = sum(1 for row in rows if row.verdict == "confirmed")
            return positives / total if total else 0.0

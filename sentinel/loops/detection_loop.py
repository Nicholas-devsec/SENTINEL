from __future__ import annotations

from sqlalchemy import select

from sentinel.db.models import IOC
from sentinel.loops.karpathy_loop import ThreatIntelLoop


class DetectionEffectivenessLoop(ThreatIntelLoop):
    loop_type = "detection"

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        async with self.session_factory() as session:
            if hasattr(session, "iocs"):
                rows = [
                    ioc
                    for ioc in session.iocs
                    if getattr(ioc, "sigma_rule", None) is not None
                    and getattr(ioc, "analyst_verdict", None) in {"true_positive", "false_positive"}
                ]
                positives = sum(1 for ioc in rows if ioc.analyst_verdict == "true_positive")
                return positives / len(rows) if rows else 0.0
            rows = list(
                (
                    await session.scalars(
                        select(IOC).where(
                            IOC.sigma_rule.is_not(None),
                            IOC.analyst_verdict.in_(("true_positive", "false_positive")),
                        )
                    )
                ).all()
            )
            positives = sum(1 for row in rows if row.analyst_verdict == "true_positive")
            return positives / len(rows) if rows else 0.0

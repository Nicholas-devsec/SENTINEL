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
                rows = [ioc for ioc in session.iocs if getattr(ioc, "sigma_rule", None) is not None]
                total = len(rows)
                fired = sum(1 for ioc in rows if getattr(ioc, "crowdstrike_pushed", False))
                return fired / total if total else 0.0
            rows = list((await session.scalars(select(IOC).where(IOC.sigma_rule.is_not(None)))).all())
            total = len(rows)
            fired = sum(1 for row in rows if row.crowdstrike_pushed)
            return fired / total if total else 0.0

from __future__ import annotations

from sqlalchemy import select

from sentinel.db.models import IOC
from sentinel.feedback import scoring_target
from sentinel.loops.karpathy_loop import ThreatIntelLoop, _spearman


class ScoreCalibrationLoop(ThreatIntelLoop):
    loop_type = "scoring"

    async def measure_metric(self) -> float:
        if self.metric_override is not None:
            return await self.metric_override()
        async with self.session_factory() as session:
            if hasattr(session, "iocs"):
                rows = [ioc for ioc in session.iocs if getattr(ioc, "analyst_verdict", None)]
            else:
                rows = list((await session.scalars(select(IOC).where(IOC.analyst_verdict.is_not(None)))).all())
            if len(rows) < 2:
                return 0.0
            predicted = [float(row.risk_score or 0.0) for row in rows]
            # Assumption: absent analyst severity scores, verdicts are mapped to proxy numeric values.
            actual = [scoring_target(row.analyst_verdict or "") for row in rows]
            return _spearman(predicted, actual)

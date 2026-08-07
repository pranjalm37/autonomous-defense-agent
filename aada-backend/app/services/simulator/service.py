"""
Runs a staged attack scenario through the live pipeline.

The simulator is deliberately thin: it generates log data and then calls the same
ingestion and detection services the real endpoints use. Every stage it reports
is a stage that actually ran, timed as it ran — nothing is scripted.
"""
from __future__ import annotations

import json
import time
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.schemas.event import LogFormat
from app.services.detection.engine import DetectionEngine
from app.services.ingestion.service import IngestionService
from app.services.simulator.scenarios import SCENARIOS, Scenario, new_run_id

logger = get_logger(__name__)


class SimulatorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def run(self, scenario_id: str) -> dict[str, Any]:
        scenario = SCENARIOS[scenario_id]
        run_id = new_run_id()
        started = time.perf_counter()
        stages: list[dict[str, Any]] = []

        def stage(name: str, detail: str, ok: bool = True, **extra: Any) -> None:
            stages.append({
                "stage": name,
                "detail": detail,
                "ok": ok,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                **extra,
            })

        content = _serialize(scenario)
        stage("staged", f"{scenario.name} generated in {scenario.fmt.value} format")

        ingest = await IngestionService(self.db).ingest(content, scenario.fmt)
        stage(
            "ingested",
            f"{ingest.stored} of {ingest.received} records stored via the {scenario.fmt.value} parser",
            ok=ingest.stored > 0,
            stored=ingest.stored,
            failed=ingest.failed,
        )

        # Flush so detection's query sees the rows this run just inserted; the
        # session commits at the end of the request as usual.
        await self.db.flush()

        summary = await DetectionEngine().run(self.db, lookback_minutes=60, only_unprocessed=True)
        detected = summary.get("alerts_created", 0)
        rules = ", ".join(k for k, v in (summary.get("by_rule") or {}).items() if v) or "none"
        stage(
            "detected",
            f"{summary.get('events_analyzed', 0)} events analyzed → {detected} alert(s) [{rules}]",
            ok=detected > 0,
            alerts_created=detected,
            by_rule=summary.get("by_rule") or {},
        )

        alert_ids = [str(a) for a in (summary.get("alert_ids") or [])]
        expected_fired = scenario.expected_rule in (summary.get("by_rule") or {})

        logger.info(
            "simulation_run", run_id=run_id, scenario=scenario.id,
            stored=ingest.stored, alerts=detected, expected_fired=expected_fired,
        )

        return {
            "run_id": run_id,
            "scenario_id": scenario.id,
            "scenario_name": scenario.name,
            "events_ingested": ingest.stored,
            "alerts_created": detected,
            "alert_ids": alert_ids,
            "expected_rule": scenario.expected_rule,
            "expected_rule_fired": expected_fired,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "stages": stages,
        }


def _serialize(scenario: Scenario) -> str:
    data = scenario.generate()
    if scenario.fmt is LogFormat.JSON:
        return json.dumps(data)
    return data if isinstance(data, str) else "\n".join(data)

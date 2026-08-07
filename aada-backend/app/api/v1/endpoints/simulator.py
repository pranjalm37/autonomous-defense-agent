"""
Attack simulator endpoints.

    GET  /simulator/scenarios              list the staged attacks available
    POST /simulator/scenarios/{id}/run     stage one and walk the live pipeline

Simulated log records only: a run stages synthetic events through the normal
ingestion path and lets detection react. It performs no outbound network
activity and executes no remediation — anything it surfaces still goes through
the usual decision and approval gates.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.logging_config import get_logger
from app.models.user import User
from app.schemas.simulator import ScenarioInfo, SimulationResult
from app.services import audit
from app.services.audit import AuditAction
from app.services.simulator import SCENARIOS, SimulatorService

logger = get_logger(__name__)
router = APIRouter(prefix="/simulator", tags=["simulator"])


@router.get("/scenarios", response_model=list[ScenarioInfo])
async def list_scenarios(_: User = Depends(get_current_user)) -> list[ScenarioInfo]:
    """Every staged attack the simulator can run. Readable by any signed-in user."""
    return [
        ScenarioInfo(
            id=s.id, name=s.name, description=s.description, mitre=s.mitre,
            format=s.fmt.value, target=s.target, expected_rule=s.expected_rule,
        )
        for s in SCENARIOS.values()
    ]


@router.post("/scenarios/{scenario_id}/run", response_model=SimulationResult, status_code=201)
async def run_scenario(
    scenario_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> SimulationResult:
    """Stage the scenario, then ingest and detect it exactly as a real feed would be."""
    if scenario_id not in SCENARIOS:
        raise NotFoundError("Scenario", scenario_id)

    result = await SimulatorService(db).run(scenario_id)

    audit.record(
        db,
        action=AuditAction.SIMULATION_RUN,
        resource_type="simulation",
        ctx=audit.audit_context_from_request(request, user),
        new_value={
            "scenario": scenario_id,
            "run_id": result["run_id"],
            "events_ingested": result["events_ingested"],
            "alerts_created": result["alerts_created"],
        },
    )
    return SimulationResult(**result)

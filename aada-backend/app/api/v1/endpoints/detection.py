"""
Detection endpoints.

    POST /detection/run     run the rule engine over recent events → create Alerts
    GET  /detection/rules   list the active rules and their tunable thresholds

The engine is normally driven by a background worker; this manual trigger is for
on-demand re-analysis and for the dashboard "Run detection now" button.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.user import User
from app.schemas.detection import DetectionRunRequest, DetectionRunResult, RuleInfo
from app.services import audit
from app.services.audit import AuditAction
from app.services.detection import DetectionEngine
from app.services.detection.rules import default_rules

router = APIRouter(prefix="/detection", tags=["detection"])


@router.post("/run", response_model=DetectionRunResult, status_code=201)
async def run_detection(
    params: DetectionRunRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> DetectionRunResult:
    """Analyze recent events and persist any detections as alerts."""
    summary = await DetectionEngine().run(
        db,
        lookback_minutes=params.lookback_minutes,
        limit=params.limit,
        only_unprocessed=params.only_unprocessed,
    )
    audit.record(
        db, action=AuditAction.DETECTION_RUN, resource_type="detection",
        ctx=audit.audit_context_from_request(request, user),
        new_value={k: summary.get(k) for k in ("events_analyzed", "detections", "alerts_created")},
    )
    return DetectionRunResult(**summary)


@router.get("/rules", response_model=list[RuleInfo])
async def list_rules(_: User = Depends(get_current_user)) -> list[RuleInfo]:
    """Expose the active rules and their thresholds (for tuning UIs)."""
    infos: list[RuleInfo] = []
    for rule in default_rules():
        thresholds = {
            k: getattr(rule, k)
            for k in dir(rule)
            if k.isupper() and isinstance(getattr(rule, k), (int, float))
        }
        infos.append(RuleInfo(
            rule_id=rule.rule_id,
            name=rule.name,
            threat_type=rule.threat_type,
            thresholds=thresholds,
        ))
    return infos

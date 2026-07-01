"""
Decision-engine endpoints.

    POST /decision/alerts/{id}/decide   fuse signals for a stored alert and decide
                                        (mode from query or config default)
    POST /decision/evaluate             ad-hoc: decide over supplied signals

The decision engine fuses detection + AI analysis + threat intel + RAG into a
single risk/confidence and applies the operating-mode policy.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.user import User
from app.schemas.decision import AdHocDecisionRequest
from app.services import audit
from app.services.audit import AuditAction
from app.services.decision import (
    Decision, DecisionEngine, DecisionInput, DecisionMode,
    ActionProposal, DetectionSignal, KnowledgeSignal, LLMSignal, ThreatIntelSignal,
)

router = APIRouter(prefix="/decision", tags=["decision"])


def _default_mode() -> DecisionMode:
    try:
        return DecisionMode(get_settings().decision_mode)
    except ValueError:
        return DecisionMode.ASSISTED


@router.post("/alerts/{alert_id}/decide", response_model=Decision, status_code=201)
async def decide_alert(
    alert_id: uuid.UUID,
    request: Request,
    mode: DecisionMode | None = Query(None, description="Override the configured mode"),
    create_actions: bool = Query(False, description="File actions into the approval queue"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> Decision:
    decision = await DecisionEngine().decide_for_alert(
        db, alert_id, mode=mode or _default_mode(), create_actions=create_actions)
    audit.record(
        db, action=AuditAction.AI_DECISION, resource_type="alert", resource_id=alert_id,
        ctx=audit.audit_context_from_request(request, user),
        new_value={
            "verdict": decision.verdict.value, "risk_score": decision.risk_score,
            "confidence": decision.confidence_score, "mode": decision.mode.value,
            "disposition": decision.top_disposition.value,
        },
    )
    return decision


@router.post("/evaluate", response_model=Decision)
async def evaluate(
    body: AdHocDecisionRequest,
    _: User = Depends(get_current_user),
) -> Decision:
    inp = DecisionInput(
        mode=body.mode or _default_mode(),
        detection=DetectionSignal(**body.detection.model_dump()) if body.detection else None,
        llm=LLMSignal(**body.llm.model_dump()) if body.llm else None,
        threat_intel=ThreatIntelSignal(**body.threat_intel.model_dump()) if body.threat_intel else None,
        knowledge=KnowledgeSignal(**body.knowledge.model_dump()) if body.knowledge else None,
        actions=[ActionProposal(**a.model_dump()) for a in body.actions],
    )
    return DecisionEngine().decide(inp)

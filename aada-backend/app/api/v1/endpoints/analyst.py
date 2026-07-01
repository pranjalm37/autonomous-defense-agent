"""
AI SOC analyst endpoints.

    POST /analyst/alerts/{alert_id}/analyze   analyze a stored alert (+ its events
                                              + RAG), persist results, optionally
                                              file remediation actions for approval
    POST /analyst/analyze                     ad-hoc analysis of a supplied alert

Uses the configured LLM (OpenAI when OPENAI_API_KEY is set, else the deterministic
offline provider) and the shared RAG pipeline.
"""
from __future__ import annotations

import uuid
from functools import lru_cache

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.dependencies import get_current_user, require_roles
from app.models.user import User
from app.schemas.analyst import AdHocAnalyzeRequest
from app.services import audit
from app.services.audit import AuditAction
from app.services.ai_analyst import AISOCAnalyst, AIAnalysis
from app.services.ai_analyst.llm import build_llm
from app.services.ai_analyst.schemas import AlertInput, AnalysisContext, EventInput

router = APIRouter(prefix="/analyst", tags=["analyst"])


@lru_cache
def get_analyst() -> AISOCAnalyst:
    s = get_settings()
    llm = build_llm(
        openai_api_key=getattr(s, "openai_api_key", None),
        model=getattr(s, "ai_model", "gpt-4o-mini"),
        temperature=getattr(s, "ai_temperature", 0.1),
    )
    return AISOCAnalyst(llm=llm)


@router.post("/alerts/{alert_id}/analyze", response_model=AIAnalysis, status_code=201)
async def analyze_alert(
    alert_id: uuid.UUID,
    request: Request,
    create_actions: bool = Query(False, description="File executable recommendations as pending actions"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_roles("analyst", "admin")),
) -> AIAnalysis:
    """Run the AI SOC analyst over a stored alert and persist the result."""
    analysis = await get_analyst().analyze_alert(db, alert_id, create_actions=create_actions)
    audit.record(
        db, action=AuditAction.AI_ANALYSIS, resource_type="alert", resource_id=alert_id,
        ctx=audit.audit_context_from_request(request, user),
        new_value={
            "is_true_positive": analysis.is_true_positive, "risk_score": analysis.risk_score,
            "confidence": analysis.confidence, "model": analysis.model,
        },
    )
    return analysis


@router.post("/analyze", response_model=AIAnalysis)
async def analyze_adhoc(
    body: AdHocAnalyzeRequest,
    _: User = Depends(get_current_user),
) -> AIAnalysis:
    """Analyze an alert payload directly (no DB write) — useful for testing/triage."""
    analyst = get_analyst()
    rag_context = ""
    if body.use_rag:
        pipeline = analyst._resolve_rag()
        if pipeline is not None:
            terms = [body.alert.threat_type or ""] + body.alert.mitre_techniques + [body.alert.title]
            rag_context = pipeline.build_context(" ".join(t for t in terms if t), top_k=5, max_chars=3500)

    context = AnalysisContext(
        alert=AlertInput(**body.alert.model_dump()),
        events=[EventInput(**e.model_dump()) for e in body.events],
        rag_context=rag_context,
    )
    return analyst.analyze(context)

"""
AISOCAnalyst — orchestrates one analysis.

    analyze(context)            pure: prompts → LLM → validated AIAnalysis
    analyze_alert(db, alert_id) load alert + evidence events + RAG context,
                                analyze, persist results back onto the alert, and
                                optionally file remediation actions for approval.

Inputs (per the brief): security alert + log events + RAG context.
Outputs: executive summary, technical analysis, MITRE mapping, risk score,
recommended actions — all in the AIAnalysis schema.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.logging_config import get_logger
from app.models.action import Action, ActionStatus, ActionType
from app.models.alert import Alert, AlertStatus
from app.models.event import SecurityEvent
from app.services.ai_analyst.llm import LLMProvider, build_llm
from app.services.ai_analyst.prompts import SYSTEM_PROMPT, build_user_prompt
from app.services.ai_analyst.schemas import (
    AIAnalysis, AlertInput, AnalysisContext, EventInput,
)

logger = get_logger(__name__)

MAX_EVENTS = 50          # cap evidence fed to the model (token budget)
RAG_TOP_K = 5
RAG_MAX_CHARS = 3500

# Which recommended action_types map to executable remediation rows.
_EXECUTABLE: dict[str, ActionType] = {
    "block_ip": ActionType.BLOCK_IP,
    "isolate_host": ActionType.ISOLATE_HOST,
    "disable_user": ActionType.DISABLE_USER,
    "kill_process": ActionType.KILL_PROCESS,
    "quarantine_file": ActionType.QUARANTINE_FILE,
    "revoke_session": ActionType.REVOKE_SESSION,
    "reset_password": ActionType.RESET_PASSWORD,
}
_TARGET_TYPE = {
    ActionType.BLOCK_IP: "ip", ActionType.ISOLATE_HOST: "host",
    ActionType.DISABLE_USER: "user", ActionType.KILL_PROCESS: "process",
    ActionType.QUARANTINE_FILE: "file", ActionType.REVOKE_SESSION: "user",
    ActionType.RESET_PASSWORD: "user",
}


class AISOCAnalyst:
    def __init__(self, llm: LLMProvider | None = None, rag_pipeline=None):
        self.llm = llm or build_llm(openai_api_key=None)   # offline default
        self._rag = rag_pipeline                            # lazy-resolved if None

    # ── Pure ──────────────────────────────────────────────────────────────────
    def analyze(self, context: AnalysisContext) -> AIAnalysis:
        user_prompt = build_user_prompt(context)
        analysis = self.llm.complete(SYSTEM_PROMPT, user_prompt, context)
        logger.info("ai_analysis_done", provider=self.llm.name,
                    true_positive=analysis.is_true_positive, risk=analysis.risk_score)
        return analysis

    # ── DB-backed ───────────────────────────────────────────────────────────--
    async def analyze_alert(
        self, db: AsyncSession, alert_id: uuid.UUID, *, create_actions: bool = False
    ) -> AIAnalysis:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
        if alert is None:
            raise NotFoundError("Alert", str(alert_id))

        events = list((await db.execute(
            select(SecurityEvent).where(SecurityEvent.alert_id == alert_id).limit(MAX_EVENTS)
        )).scalars().all())

        context = AnalysisContext(
            alert=self._alert_input(alert),
            events=[self._event_input(e) for e in events],
            rag_context=self._rag_context(alert),
        )
        analysis = self.analyze(context)
        self._persist(alert, analysis)
        if create_actions:
            self._file_actions(db, alert, analysis)
        return analysis

    # ── Context assembly ────────────────────────────────────────────────────--
    @staticmethod
    def _alert_input(alert: Alert) -> AlertInput:
        meta = (alert.ai_analysis or {}).get("metadata", {}) if alert.ai_analysis else {}
        if alert.ai_analysis:
            meta = {**meta, "risk_score": alert.ai_analysis.get("risk_score"),
                    "confidence": alert.ai_confidence}
        return AlertInput(
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            threat_type=alert.threat_type,
            source_ip=str(alert.source_ip) if alert.source_ip else None,   # INET → str
            dest_ip=str(alert.dest_ip) if alert.dest_ip else None,
            hostname=alert.hostname,
            affected_user=alert.affected_user,
            mitre_techniques=list(alert.mitre_techniques or []),
            detection_rule=(alert.ai_analysis or {}).get("rule_id") if alert.ai_analysis else None,
            rule_metadata={k: v for k, v in meta.items() if v is not None},
        )

    @staticmethod
    def _event_input(e: SecurityEvent) -> EventInput:
        np = e.normalized_payload or {}
        summary = (np.get("message") or e.event_type)
        return EventInput(
            event_type=e.event_type,
            summary=str(summary),
            source_ip=str(e.source_ip) if e.source_ip else None,
            dest_ip=str(e.dest_ip) if e.dest_ip else None,
            username=e.username,
            hostname=e.hostname,
            severity=e.severity.value if e.severity else None,
            timestamp=e.ingested_at.isoformat() if e.ingested_at else None,
            raw=e.raw_payload or {},
        )

    def _rag_context(self, alert: Alert) -> str:
        pipeline = self._resolve_rag()
        if pipeline is None:
            return ""
        terms = [alert.threat_type or ""] + list(alert.mitre_techniques or []) + [alert.title]
        query = " ".join(t for t in terms if t).strip()
        try:
            return pipeline.build_context(query, top_k=RAG_TOP_K, max_chars=RAG_MAX_CHARS)
        except Exception:
            logger.exception("rag_context_failed")
            return ""

    def _resolve_rag(self):
        if self._rag is not None:
            return self._rag
        try:
            from app.services.rag.pipeline import get_default_pipeline
            self._rag = get_default_pipeline()
        except Exception:
            logger.exception("rag_pipeline_unavailable")
            self._rag = None
        return self._rag

    # ── Persistence ───────────────────────────────────────────────────────────
    @staticmethod
    def _persist(alert: Alert, analysis: AIAnalysis) -> None:
        alert.ai_reasoning = analysis.technical_analysis
        alert.ai_confidence = analysis.confidence
        alert.ai_analysis = {**(alert.ai_analysis or {}), "ai_soc_analyst": analysis.model_dump(mode="json")}
        if analysis.mitre_techniques:
            alert.mitre_techniques = [t.technique_id for t in analysis.mitre_techniques]
        if analysis.mitre_tactics:
            alert.mitre_tactics = analysis.mitre_tactics
        alert.status = AlertStatus.CONFIRMED if analysis.is_true_positive else AlertStatus.FALSE_POSITIVE

    @staticmethod
    def _file_actions(db: AsyncSession, alert: Alert, analysis: AIAnalysis) -> None:
        """Turn executable recommendations into PENDING actions for the approval queue."""
        for rec in analysis.recommended_actions:
            atype = _EXECUTABLE.get(rec.action_type)
            if atype is None:
                continue   # 'investigate'/'monitor' are not executable remediations
            db.add(Action(
                action_type=atype,
                status=ActionStatus.PENDING,
                target_type=_TARGET_TYPE.get(atype, "custom"),
                target_value=rec.target,
                parameters={"priority": rec.priority},
                ai_justification=rec.rationale,
                risk_score=analysis.risk_score / 100.0,
                reversible=rec.reversible,
                alert_id=alert.id,
                incident_id=alert.incident_id,
            ))

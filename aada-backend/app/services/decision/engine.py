"""
DecisionEngine — fuse signals, assess false positives, apply the mode policy.

    decide(input)            pure: → Decision (fully testable, no I/O)
    decide_for_alert(db, …)  gather signals for a stored alert from detection,
                             the AI analyst, threat intel, and RAG; decide; persist;
                             and (per disposition) file actions into the queue.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.logging_config import get_logger
from app.services.decision import fusion
from app.services.decision.policy import decide_dispositions
from app.services.decision.schemas import (
    ActionProposal,
    Decision,
    DecisionInput,
    DecisionMode,
    DecisionThresholds,
    DetectionSignal,
    Disposition,
    KnowledgeSignal,
    LLMSignal,
    ThreatIntelSignal,
    Verdict,
)

logger = get_logger(__name__)


class DecisionEngine:
    def __init__(self, thresholds: DecisionThresholds | None = None):
        self.th = thresholds or DecisionThresholds()

    # ── Pure ──────────────────────────────────────────────────────────────────
    def decide(self, inp: DecisionInput) -> Decision:
        risk = fusion.fuse_risk(inp)
        conf = fusion.fuse_confidence(inp)
        is_fp, fp_reasons = fusion.assess_false_positive(inp, risk, conf, self.th)
        verdict = self._verdict(risk, is_fp)

        top, action_decisions = decide_dispositions(
            inp, fused_risk=risk, fused_conf=conf, is_false_positive=is_fp, th=self.th)

        requires_human = any(
            d.disposition in (Disposition.REQUIRE_APPROVAL, Disposition.ESCALATE)
            for d in action_decisions
        ) or inp.mode == DecisionMode.ASSISTED

        decision = Decision(
            risk_score=risk,
            confidence_score=conf,
            verdict=verdict,
            mode=inp.mode,
            is_false_positive=is_fp,
            requires_human=requires_human,
            top_disposition=top,
            action_decisions=action_decisions,
            rationale=self._rationale(inp, risk, conf, verdict, is_fp, fp_reasons, top),
            signal_breakdown={
                "detection_risk": inp.detection.risk_score if inp.detection else None,
                "llm_risk": inp.llm.risk_score if inp.llm else None,
                "threat_intel_score": (inp.threat_intel.malicious_score
                                       if inp.threat_intel else None),
                "knowledge_relevance": round(inp.knowledge.relevance, 2) if inp.knowledge else None,
                "corroborating_sources": fusion.corroborating_sources(inp),
                "false_positive_reasons": fp_reasons,
            },
        )
        logger.info("decision_made", mode=inp.mode.value, risk=risk, confidence=conf,
                    verdict=verdict.value, disposition=top.value, fp=is_fp)
        return decision

    def _verdict(self, risk: int, is_fp: bool) -> Verdict:
        if is_fp:
            return Verdict.FALSE_POSITIVE
        if risk >= 75:
            return Verdict.MALICIOUS
        if risk >= 45:
            return Verdict.SUSPICIOUS
        return Verdict.BENIGN

    @staticmethod
    def _rationale(inp, risk, conf, verdict, is_fp, fp_reasons, top) -> str:
        if is_fp:
            return (f"Assessed as a likely false positive ({'; '.join(fp_reasons)}). "
                    f"No action taken.")
        srcs = fusion.corroborating_sources(inp)
        return (
            f"Fused risk {risk}/100 at confidence {conf:.2f} from {srcs} corroborating "
            f"source(s) → verdict '{verdict.value}'. In {inp.mode.value} mode the engine "
            f"will: {top.value.replace('_', ' ')}."
        )

    # ── DB-backed ───────────────────────────────────────────────────────────────
    async def decide_for_alert(
        self, db: AsyncSession, alert_id: uuid.UUID, *, mode: DecisionMode,
        create_actions: bool = False,
    ) -> Decision:
        from app.models.alert import Alert

        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
        if alert is None:
            raise NotFoundError("Alert", str(alert_id))

        inp = DecisionInput(
            mode=mode,
            detection=self._detection_signal(alert),
            llm=self._llm_signal(alert),
            threat_intel=await self._threat_intel_signal(alert),
            knowledge=self._knowledge_signal(alert),
            actions=self._candidate_actions(alert),
        )
        decision = self.decide(inp)

        # Persist the decision onto the alert.
        alert.ai_analysis = {**(alert.ai_analysis or {}), "decision": decision.model_dump(mode="json")}
        if create_actions:
            self._file_actions(db, alert, decision)
        return decision

    # ── Signal extraction from the stored alert ────────────────────────────────
    @staticmethod
    def _detection_signal(alert) -> DetectionSignal:
        meta = (alert.ai_analysis or {})
        risk = meta.get("risk_score")
        if risk is None:
            risk = {"info": 10, "low": 25, "medium": 50, "high": 70, "critical": 90}.get(
                alert.severity.value, 50)
        return DetectionSignal(
            risk_score=int(risk),
            confidence=float(alert.ai_confidence or 0.7),
            threat_type=alert.threat_type,
            severity=alert.severity.value,
            mitre_techniques=list(alert.mitre_techniques or []),
        )

    @staticmethod
    def _llm_signal(alert) -> LLMSignal | None:
        analysis = (alert.ai_analysis or {}).get("ai_soc_analyst")
        if not analysis:
            return None
        return LLMSignal(
            risk_score=int(analysis.get("risk_score", 50)),
            confidence=float(analysis.get("confidence", 0.7)),
            is_true_positive=bool(analysis.get("is_true_positive", True)),
            recommended_severity=analysis.get("recommended_severity"),
        )

    async def _threat_intel_signal(self, alert) -> ThreatIntelSignal | None:
        if not alert.source_ip:
            return None
        # Offline-safe: use the seeded reputation feed. Production can swap in the
        # EnrichmentService (VirusTotal/AbuseIPDB) here.
        try:
            from app.mcp_server.providers import ReputationFeed
            rec = ReputationFeed.load().lookup(str(alert.source_ip))
            score = rec.get("score")
            return ThreatIntelSignal(
                malicious_score=score,
                allowlisted=("benign" in (rec.get("categories") or [])),
            )
        except Exception:
            logger.exception("threat_intel_signal_failed")
            return None

    @staticmethod
    def _knowledge_signal(alert) -> KnowledgeSignal | None:
        try:
            from app.services.rag.pipeline import get_default_pipeline
            pipeline = get_default_pipeline()
            terms = [alert.threat_type or ""] + list(alert.mitre_techniques or [])
            results = pipeline.retrieve(" ".join(t for t in terms if t) or alert.title, top_k=3)
            if not results:
                return None
            return KnowledgeSignal(
                relevance=results[0].score,
                citations=[r.citation for r in results],
            )
        except Exception:
            logger.exception("knowledge_signal_failed")
            return None

    @staticmethod
    def _candidate_actions(alert) -> list[ActionProposal]:
        analysis = (alert.ai_analysis or {}).get("ai_soc_analyst") or {}
        recs = analysis.get("recommended_actions") or []
        if recs:
            return [
                ActionProposal(
                    title=r.get("title", "action"),
                    action_type=r.get("action_type", "investigate"),
                    target=r.get("target", alert.source_ip or "n/a"),
                    reversible=bool(r.get("reversible", True)),
                    priority=r.get("priority", "medium"),
                    rationale=r.get("rationale", ""),
                )
                for r in recs
            ]
        # Fallback: propose blocking the source IP.
        if alert.source_ip:
            return [ActionProposal(
                title="Block source IP", action_type="block_ip",
                target=str(alert.source_ip), reversible=True, priority="high")]
        return []

    @staticmethod
    def _file_actions(db: AsyncSession, alert, decision: Decision) -> None:
        """Create queue rows for actions the policy did not suppress/monitor."""
        from app.models.action import Action, ActionStatus, ActionType

        type_map = {t.value: t for t in ActionType}
        status_for = {
            Disposition.AUTO_EXECUTE: ActionStatus.APPROVED,   # system-approved
            Disposition.REQUIRE_APPROVAL: ActionStatus.PENDING,
            Disposition.ESCALATE: ActionStatus.PENDING,
        }
        for d in decision.action_decisions:
            status = status_for.get(d.disposition)
            atype = type_map.get(d.action_type)
            if status is None or atype is None:
                continue   # monitor_only / suppress / non-executable → no row
            db.add(Action(
                action_type=atype, status=status,
                target_type="ip" if atype == ActionType.BLOCK_IP else "custom",
                target_value=d.target,
                ai_justification=d.reason,
                risk_score=decision.risk_score / 100.0,
                reversible=True,
                alert_id=alert.id, incident_id=alert.incident_id,
            ))

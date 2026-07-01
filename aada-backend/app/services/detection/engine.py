"""
DetectionEngine — runs the rule set over a batch of events.

Two entry points:
  * `analyze(events)`  — pure, no I/O. Runs every rule, returns Detections.
                         A crash in one rule is isolated so the others still run.
  * `run(db, ...)`     — fetch recent unprocessed events, analyze them, persist
                         Detections as Alert rows, link evidence events, and mark
                         the batch processed so it is never re-analyzed.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models.alert import Alert, AlertStatus
from app.models.event import SecurityEvent
from app.services.detection.base import BaseRule, Detection
from app.services.detection.rules import default_rules

logger = get_logger(__name__)


class DetectionEngine:
    def __init__(self, rules: Sequence[BaseRule] | None = None):
        self.rules = list(rules) if rules is not None else default_rules()

    # ── Pure analysis ─────────────────────────────────────────────────────────
    def analyze(self, events: Sequence) -> list[Detection]:
        detections: list[Detection] = []
        for rule in self.rules:
            try:
                found = rule.evaluate(events)
            except Exception:  # one rule must never sink the whole run
                logger.exception("detection_rule_failed", rule_id=rule.rule_id)
                continue
            detections.extend(found)
        # Highest risk first — drives the triage queue ordering.
        detections.sort(key=lambda d: d.risk_score, reverse=True)
        return detections

    # ── DB-backed run ─────────────────────────────────────────────────────────
    async def run(
        self,
        db: AsyncSession,
        *,
        lookback_minutes: int = 60,
        limit: int = 5000,
        only_unprocessed: bool = True,
    ) -> dict:
        since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        q = select(SecurityEvent).where(SecurityEvent.ingested_at >= since)
        if only_unprocessed:
            q = q.where(SecurityEvent.processed.is_(False))
        q = q.order_by(SecurityEvent.ingested_at.asc()).limit(limit)

        events = list((await db.execute(q)).scalars().all())
        detections = self.analyze(events)

        events_by_id = {e.id: e for e in events}
        alerts: list[Alert] = []
        for d in detections:
            alert = self._to_alert(d)
            db.add(alert)
            await db.flush()  # assign alert.id so we can link evidence events
            for ev_id in d.evidence_event_ids:
                ev = events_by_id.get(ev_id)
                if ev is not None and ev.alert_id is None:
                    ev.alert_id = alert.id
            alerts.append(alert)

        # Mark the whole analyzed batch processed so it isn't re-scanned.
        now = datetime.now(timezone.utc)
        for e in events:
            e.processed = True
            e.processed_at = now

        summary = {
            "events_analyzed": len(events),
            "detections": len(detections),
            "alerts_created": len(alerts),
            "by_rule": dict(Counter(d.rule_id for d in detections)),
            "by_severity": dict(Counter(d.severity.value for d in detections)),
            "alert_ids": [a.id for a in alerts],
        }
        logger.info("detection_run", **{k: v for k, v in summary.items() if k != "alert_ids"})
        return summary

    @staticmethod
    def _to_alert(d: Detection) -> Alert:
        return Alert(
            title=d.title,
            description=d.description,
            severity=d.severity,
            status=AlertStatus.NEW,
            source_ip=d.source_ip,
            dest_ip=d.dest_ip,
            hostname=d.hostname,
            affected_user=d.affected_user,
            threat_type=d.threat_type,
            mitre_tactics=d.mitre_tactics,
            mitre_techniques=d.mitre_techniques,
            ai_confidence=d.confidence,
            ai_reasoning=d.description,
            ai_analysis={
                "engine": "rule-based",
                "rule_id": d.rule_id,
                "risk_score": d.risk_score,
                "metadata": d.metadata,
            },
            iocs=d.iocs,
        )

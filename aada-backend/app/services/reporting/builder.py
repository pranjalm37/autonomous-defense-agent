"""
ReportBuilder — assembles an IncidentReport from the incident's evidence.

It is pure over an `IncidentBundle` (primitive views extracted from the ORM by
the service), so report generation is fully unit-testable without a database.

Where an alert already carries AI-analyst output (executive_summary,
attack_narrative, recommended_actions), the builder reuses it for richer prose;
otherwise it falls back to deterministic templates. Either way the structure is
identical.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.services.detection.mitre import TECHNIQUES, TACTICS
from app.services.reporting.schemas import (
    IncidentReport, IOCSet, MitreRef, Recommendation, TimelineEntry,
)


# ── Input views (the service maps ORM → these) ────────────────────────────────
@dataclass
class AlertView:
    title: str
    severity: str
    threat_type: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    affected_user: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    ai_analysis: dict | None = None     # the AIAnalysis dump, if analyzed
    created_at: datetime | None = None


@dataclass
class EventView:
    event_type: str
    summary: str = ""
    source_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    timestamp: datetime | None = None


@dataclass
class ActionView:
    action_type: str
    target: str
    status: str
    ai_justification: str | None = None
    executed_at: datetime | None = None
    created_at: datetime | None = None


@dataclass
class IncidentBundle:
    title: str
    severity: str
    status: str
    created_at: datetime | None = None
    alerts: list[AlertView] = field(default_factory=list)
    events: list[EventView] = field(default_factory=list)
    actions: list[ActionView] = field(default_factory=list)


# Generic hardening recommendations keyed by threat type.
_PLAYBOOK = {
    "brute_force": ["Enforce MFA on all remote access", "Rate-limit and lock accounts after failed logins"],
    "credential_stuffing": ["Enforce MFA", "Screen passwords against breach corpora"],
    "reconnaissance": ["Tighten egress/ingress firewall rules", "Reduce externally exposed services"],
    "account_takeover": ["Reset affected credentials and revoke sessions", "Deploy impossible-travel alerting"],
    "privilege_escalation": ["Apply least-privilege in sudoers", "Centralize and alert on privileged-command logs"],
    "malware": ["Isolate and reimage affected hosts", "Block C2 indicators at the firewall and DNS"],
}


class ReportBuilder:
    def build(self, bundle: IncidentBundle) -> IncidentReport:
        return IncidentReport(
            report_id=f"IR-{uuid.uuid4().hex[:10].upper()}",
            title=bundle.title,
            severity=bundle.severity,
            status=bundle.status,
            generated_at=datetime.now(timezone.utc),
            executive_summary=self._exec_summary(bundle),
            timeline=self._timeline(bundle),
            iocs=self._iocs(bundle),
            mitre=self._mitre(bundle),
            root_cause=self._root_cause(bundle),
            recommendations=self._recommendations(bundle),
            metrics=self._metrics(bundle),
        )

    # ── Executive summary ──
    def _exec_summary(self, b: IncidentBundle) -> str:
        ai = self._first_ai(b)
        if ai and ai.get("executive_summary"):
            return ai["executive_summary"]
        threats = sorted({a.threat_type for a in b.alerts if a.threat_type})
        threat_str = ", ".join(threats) or "suspicious activity"
        hosts = sorted({a.hostname for a in b.alerts if a.hostname})
        return (
            f"A {b.severity} security incident — '{b.title}' — involving {threat_str} was "
            f"identified. It correlates {len(b.alerts)} alert(s) across {len(b.events)} "
            f"log event(s)" + (f" affecting {', '.join(hosts)}" if hosts else "") + ". "
            f"Current status: {b.status}. "
            + ("Containment actions have been taken." if any(
                a.status in ("completed", "approved") for a in b.actions)
               else "Response actions are pending review.")
        )

    # ── Timeline ──
    def _timeline(self, b: IncidentBundle) -> list[TimelineEntry]:
        entries: list[TimelineEntry] = []
        for a in b.alerts:
            entries.append(TimelineEntry(
                timestamp=a.created_at, category="detection",
                title=f"Alert: {a.title}",
                detail=f"severity={a.severity}" + (f", source={a.source_ip}" if a.source_ip else "")))
        for e in b.events:
            entries.append(TimelineEntry(
                timestamp=e.timestamp, category="event",
                title=e.event_type,
                detail=" ".join(p for p in [e.summary, f"src={e.source_ip}" if e.source_ip else "",
                                            f"user={e.username}" if e.username else ""] if p).strip()))
        for ac in b.actions:
            entries.append(TimelineEntry(
                timestamp=ac.executed_at or ac.created_at, category="response",
                title=f"Response: {ac.action_type} → {ac.target}",
                detail=f"status={ac.status}"))
        # Sort by time; undated entries sink to the end deterministically.
        entries.sort(key=lambda x: (x.timestamp is None, x.timestamp or datetime.max.replace(tzinfo=timezone.utc)))
        return entries

    # ── IOCs ──
    def _iocs(self, b: IncidentBundle) -> IOCSet:
        ips, domains, hashes, urls, accounts = set(), set(), set(), set(), set()
        for a in b.alerts:
            for ip in (a.source_ip, a.dest_ip):
                if ip:
                    ips.add(ip)
            if a.affected_user:
                accounts.add(a.affected_user)
            d = a.iocs or {}
            ips.update(d.get("ips", []) or [])
            domains.update(d.get("domains", []) or [])
            hashes.update(d.get("hashes", []) or [])
            urls.update(d.get("urls", []) or [])
            for v in (d.get("targeted_users") or []):
                accounts.add(v)
        for e in b.events:
            if e.source_ip:
                ips.add(e.source_ip)
            if e.username:
                accounts.add(e.username)
        return IOCSet(ips=sorted(ips), domains=sorted(domains), hashes=sorted(hashes),
                      urls=sorted(urls), accounts=sorted(accounts))

    # ── MITRE ──
    def _mitre(self, b: IncidentBundle) -> list[MitreRef]:
        ids: list[str] = []
        for a in b.alerts:
            for t in (a.mitre_techniques or []):
                if t not in ids:
                    ids.append(t)
        refs = []
        for tid in ids:
            tech = TECHNIQUES.get(tid)
            if tech:
                tactic = TACTICS.get(tech.tactics[0], tech.tactics[0]) if tech.tactics else None
                refs.append(MitreRef(technique_id=tech.id, name=tech.name, tactic=tactic))
            else:
                refs.append(MitreRef(technique_id=tid, name=tid))
        return refs

    # ── Root cause ──
    def _root_cause(self, b: IncidentBundle) -> str:
        ai = self._first_ai(b)
        if ai and ai.get("attack_narrative"):
            return ai["attack_narrative"]
        if ai and ai.get("technical_analysis"):
            return ai["technical_analysis"]
        earliest = min((e for e in b.events if e.timestamp), key=lambda e: e.timestamp, default=None)
        threats = sorted({a.threat_type for a in b.alerts if a.threat_type})
        origin = earliest.source_ip if earliest else (b.alerts[0].source_ip if b.alerts else "an unknown source")
        return (
            f"The incident originated from {origin} and manifested as "
            f"{', '.join(threats) or 'anomalous activity'}. The initial access vector should be "
            "confirmed during eradication; the most likely root cause is an exposed or "
            "weakly-protected service combined with insufficient preventive controls."
        )

    # ── Recommendations ──
    def _recommendations(self, b: IncidentBundle) -> list[Recommendation]:
        recs: list[Recommendation] = []
        seen: set[str] = set()

        def add(title, detail=None, priority="medium"):
            key = title.lower()
            if key not in seen:
                seen.add(key)
                recs.append(Recommendation(title=title, detail=detail, priority=priority))

        ai = self._first_ai(b)
        for r in (ai or {}).get("recommended_actions", []) or []:
            add(r.get("title", "Recommended action"), r.get("rationale"), r.get("priority", "high"))
        for a in b.alerts:
            for tip in _PLAYBOOK.get(a.threat_type or "", []):
                add(tip)
        add("Conduct a lessons-learned review and update detection rules", priority="low")
        return recs[:12]

    def _metrics(self, b: IncidentBundle) -> dict:
        return {
            "alert_count": len(b.alerts),
            "event_count": len(b.events),
            "action_count": len(b.actions),
            "ioc_count": self._iocs(b).total(),
            "techniques": len(self._mitre(b)),
        }

    @staticmethod
    def _first_ai(b: IncidentBundle) -> dict | None:
        for a in b.alerts:
            blob = a.ai_analysis or {}
            ai = blob.get("ai_soc_analyst") if isinstance(blob, dict) else None
            if ai:
                return ai
        return None

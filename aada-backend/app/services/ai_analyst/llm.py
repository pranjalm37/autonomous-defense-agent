"""
LLM providers for the analyst.

  - OpenAILLMProvider   — production. Uses OpenAI *structured outputs* so the
                          model is constrained to the AIAnalysis JSON schema at
                          the API level (no fragile prompt-only "please return
                          JSON"). Low temperature for analytical consistency.
                          (LangChain's ChatOpenAI.with_structured_output wraps the
                          same API; this provider can be swapped for it 1:1.)

  - HeuristicLLMProvider — offline/dev/test. NOT an LLM: it produces a valid,
                          deterministic AIAnalysis from the context using simple
                          rules (reads the alert/threat type, pulls IOCs out of
                          the events, templates the narrative). It exists so the
                          whole analyst pipeline — prompt assembly, schema
                          validation, persistence — is testable with no API key.

Both satisfy the same `complete()` contract, so the analyst never knows which is
in use; `build_llm()` picks based on config.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Protocol

from app.services.ai_analyst.schemas import (
    AIAnalysis, AnalysisContext, MitreTechnique, RecommendedAction,
)
from app.models.alert import Severity

# Map the detector's threat_type → a sensible default remediation.
_ACTION_BY_THREAT = {
    "brute_force": ("block_ip", "Block the attacking source IP", "immediate"),
    "credential_stuffing": ("block_ip", "Block source IP and force password resets", "immediate"),
    "reconnaissance": ("monitor", "Monitor the scanning source and tighten firewall rules", "medium"),
    "account_takeover": ("revoke_session", "Revoke sessions and reset the affected account", "immediate"),
    "privilege_escalation": ("isolate_host", "Isolate the host and review sudoers", "high"),
    "malware": ("isolate_host", "Isolate the host and quarantine the artifact", "immediate"),
}
_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


class LLMProvider(Protocol):
    name: str
    def complete(self, system_prompt: str, user_prompt: str, context: AnalysisContext) -> AIAnalysis: ...


# ──────────────────────────────────────────────────────────────────────────────
# Production
# ──────────────────────────────────────────────────────────────────────────────
class OpenAILLMProvider:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", temperature: float = 0.1):
        from openai import OpenAI  # lazy
        self._client = OpenAI(api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.name = f"openai:{model}"

    def complete(self, system_prompt: str, user_prompt: str, context: AnalysisContext) -> AIAnalysis:
        # Structured Outputs: the API guarantees a response matching AIAnalysis.
        completion = self._client.beta.chat.completions.parse(
            model=self.model,
            temperature=self.temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format=AIAnalysis,
        )
        analysis = completion.choices[0].message.parsed
        analysis.model = self.name
        return analysis


# ──────────────────────────────────────────────────────────────────────────────
# Offline / deterministic
# ──────────────────────────────────────────────────────────────────────────────
class HeuristicLLMProvider:
    """Rule-based stand-in that returns a schema-valid analysis without any API."""

    name = "heuristic:offline"

    _HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    _DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

    def complete(self, system_prompt: str, user_prompt: str, context: AnalysisContext) -> AIAnalysis:
        alert = context.alert
        iocs = self._extract_iocs(context)
        techniques = self._techniques(alert.mitre_techniques)
        tactics = sorted({t.tactic for t in techniques})

        risk = alert.rule_metadata.get("risk_score")
        base_sev = self._severity(alert.severity)
        if not isinstance(risk, int):
            risk = {0: 10, 1: 25, 2: 50, 3: 70, 4: 90}[_SEVERITY_RANK[base_sev]]
        sev = self._severity_from_score(risk)

        actions = self._actions(alert)
        evidence_n = len(context.events)
        true_positive = base_sev != Severity.INFO

        exec_summary = (
            f"A {alert.severity} '{alert.threat_type or 'security'}' event was detected"
            + (f" from {alert.source_ip}" if alert.source_ip else "")
            + (f" affecting {alert.affected_user or alert.hostname}" if (alert.affected_user or alert.hostname) else "")
            + f". {evidence_n} supporting log event(s) were correlated. "
            + ("Immediate review and containment are recommended." if sev in (Severity.HIGH, Severity.CRITICAL)
               else "Review is recommended.")
        )
        tech_analysis = (
            f"The detection rule '{alert.detection_rule or alert.threat_type}' fired on "
            f"{evidence_n} event(s). Title: {alert.title}. "
            + (f"Indicators observed in the evidence: {', '.join(iocs)}. " if iocs else "")
            + (f"Mapped ATT&CK techniques: {', '.join(t.technique_id for t in techniques)}. " if techniques else "")
            + (f"Knowledge-base context was retrieved ({len(context.rag_context)} chars) and "
               "supports this assessment." if context.rag_context else "No knowledge-base context was available.")
        )
        narrative = (
            f"1) Source {alert.source_ip or 'unknown'} generated activity matching "
            f"{alert.threat_type or 'a suspicious pattern'}. "
            f"2) The detection engine correlated {evidence_n} event(s) into this alert. "
            f"3) Affected asset: {alert.hostname or alert.affected_user or 'n/a'}."
        )

        return AIAnalysis(
            is_true_positive=true_positive,
            confidence=float(alert.rule_metadata.get("confidence", 0.7)),
            executive_summary=exec_summary,
            technical_analysis=tech_analysis,
            attack_narrative=narrative,
            mitre_techniques=techniques,
            mitre_tactics=tactics,
            risk_score=int(risk),
            recommended_severity=sev,
            iocs=iocs,
            recommended_actions=actions,
            references=self._citations(context.rag_context),
            model=self.name,
        )

    # ── helpers ──
    def _extract_iocs(self, ctx: AnalysisContext) -> list[str]:
        found: list[str] = []
        for ip in (ctx.alert.source_ip, ctx.alert.dest_ip):
            if ip and ip not in found:
                found.append(ip)
        blob = " ".join(
            f"{e.summary} {e.source_ip or ''} {e.dest_ip or ''} {' '.join(map(str, e.raw.values()))}"
            for e in ctx.events
        )
        for m in self._HASH.findall(blob):
            if m not in found:
                found.append(m)
        for tok in blob.split():
            try:
                ipaddress.ip_address(tok)
                if tok not in found:
                    found.append(tok)
            except ValueError:
                continue
        return found[:25]

    @staticmethod
    def _techniques(ids: list[str]) -> list[MitreTechnique]:
        from app.services.detection.mitre import TECHNIQUES, TACTICS
        out = []
        for tid in ids:
            t = TECHNIQUES.get(tid)
            if t:
                tactic = TACTICS.get(t.tactics[0], t.tactics[0]) if t.tactics else ""
                out.append(MitreTechnique(technique_id=t.id, name=t.name, tactic=tactic))
            else:
                out.append(MitreTechnique(technique_id=tid, name=tid, tactic="Unknown"))
        return out

    def _actions(self, alert) -> list[RecommendedAction]:
        atype, title, prio = _ACTION_BY_THREAT.get(
            alert.threat_type or "", ("investigate", "Investigate the alert", "medium"))
        target = alert.source_ip or alert.hostname or alert.affected_user or "n/a"
        actions = [RecommendedAction(
            title=title, action_type=atype, target=target, priority=prio,
            rationale=f"Mitigates the detected {alert.threat_type or 'threat'} at its source.",
            reversible=atype not in ("delete_file",), requires_approval=True,
        )]
        actions.append(RecommendedAction(
            title="Preserve evidence and document timeline", action_type="investigate",
            target=target, priority="medium",
            rationale="Supports forensics and the post-incident report.",
            reversible=True, requires_approval=False,
        ))
        return actions

    @staticmethod
    def _severity(value: str) -> Severity:
        try:
            return Severity(value)
        except ValueError:
            return Severity.MEDIUM

    @staticmethod
    def _severity_from_score(score: int) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        if score >= 20:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _citations(rag_context: str) -> list[str]:
        # Match only citation-style markers like [sigma_rule:SSH Brute Force],
        # not JSON arrays such as ["a", "b"] embedded in retrieved rule text.
        found = re.findall(r"\[[a-z0-9_]+:[^\]\n]+\]", rag_context)
        seen: list[str] = []
        for c in found:
            if c not in seen:
                seen.append(c)
        return seen[:8]


# ──────────────────────────────────────────────────────────────────────────────
def build_llm(*, openai_api_key: str | None, model: str = "gpt-4o-mini",
              temperature: float = 0.1, force_offline: bool = False) -> LLMProvider:
    if openai_api_key and not force_offline:
        return OpenAILLMProvider(openai_api_key, model=model, temperature=temperature)
    return HeuristicLLMProvider()

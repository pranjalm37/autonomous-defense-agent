"""
The decision tree — mode + risk + confidence + action shape → disposition.

This is a deterministic, auditable policy (not an LLM): given the fused scores and
the operating mode, it decides the disposition of each recommended action. Making
this explicit and rule-based is deliberate — the *analysis* can be probabilistic,
but the *authority to act* must be transparent and reviewable.

    ┌─ false positive? ──────────────► SUPPRESS everything
    │
    ├─ MONITOR mode ────────────────► MONITOR_ONLY everything (advisory)
    │
    ├─ ASSISTED mode ───────────────► REQUIRE_APPROVAL everything (human-in-loop)
    │
    └─ AUTONOMOUS mode
         ├─ confidence < min OR risk < act_min ─► MONITOR_ONLY (too unsure to act)
         └─ per action:
              ├─ not reversible OR not auto-safe ─► REQUIRE_APPROVAL / ESCALATE
              ├─ confidence ≥ auto AND risk ≥ auto ─► AUTO_EXECUTE
              └─ otherwise ───────────────────────► REQUIRE_APPROVAL

Autonomous mode therefore auto-runs only cheap, reversible, low-blast-radius
actions (e.g. block an IP) when both confidence AND risk clear a high bar.
Isolating a host, disabling a user, or anything irreversible always routes to a
human — even in full autonomous mode.
"""
from __future__ import annotations

from app.services.decision.schemas import (
    ActionDecision, ActionProposal, AUTONOMOUS_SAFE_ACTIONS,
    DecisionInput, DecisionMode, DecisionThresholds, Disposition,
)


def decide_dispositions(
    inp: DecisionInput, *, fused_risk: int, fused_conf: float,
    is_false_positive: bool, th: DecisionThresholds,
) -> tuple[Disposition, list[ActionDecision]]:
    actions = inp.actions

    if is_false_positive:
        return Disposition.SUPPRESS, [
            _d(a, Disposition.SUPPRESS, "Suppressed: assessed as a likely false positive.")
            for a in actions
        ]

    if inp.mode == DecisionMode.MONITOR:
        return Disposition.MONITOR_ONLY, [
            _d(a, Disposition.MONITOR_ONLY, "Monitor mode: recorded as a recommendation only.")
            for a in actions
        ]

    if inp.mode == DecisionMode.ASSISTED:
        return Disposition.REQUIRE_APPROVAL, [
            _d(a, Disposition.REQUIRE_APPROVAL, "Assisted mode: queued for human approval.")
            for a in actions
        ]

    # ── AUTONOMOUS ──
    if fused_conf < th.min_confidence or fused_risk < th.act_risk_min:
        why = (f"Autonomous: below action threshold "
               f"(confidence {fused_conf:.2f} < {th.min_confidence} "
               f"or risk {fused_risk} < {th.act_risk_min}).")
        return Disposition.MONITOR_ONLY, [_d(a, Disposition.MONITOR_ONLY, why) for a in actions]

    decisions: list[ActionDecision] = []
    for a in actions:
        auto_safe = a.action_type in AUTONOMOUS_SAFE_ACTIONS and a.reversible
        if not auto_safe:
            decisions.append(_d(
                a, Disposition.ESCALATE,
                "Irreversible or high-impact action — requires human approval even in autonomous mode."))
        elif fused_conf >= th.auto_confidence and fused_risk >= th.auto_risk_min:
            decisions.append(_d(
                a, Disposition.AUTO_EXECUTE,
                f"Autonomous: reversible low-blast action with high confidence "
                f"({fused_conf:.2f}) and risk ({fused_risk})."))
        else:
            decisions.append(_d(
                a, Disposition.REQUIRE_APPROVAL,
                f"Autonomous: confidence/risk below auto-execute bar "
                f"({th.auto_confidence}/{th.auto_risk_min}) — routing to a human."))

    return _rollup(decisions), decisions


def _rollup(decisions: list[ActionDecision]) -> Disposition:
    """Pick the most action-forward disposition to summarize the whole decision."""
    order = [
        Disposition.AUTO_EXECUTE, Disposition.ESCALATE,
        Disposition.REQUIRE_APPROVAL, Disposition.MONITOR_ONLY, Disposition.SUPPRESS,
    ]
    present = {d.disposition for d in decisions}
    for disp in order:
        if disp in present:
            return disp
    return Disposition.MONITOR_ONLY


def _d(a: ActionProposal, disp: Disposition, reason: str) -> ActionDecision:
    return ActionDecision(
        title=a.title, action_type=a.action_type, target=a.target,
        disposition=disp, reason=reason,
    )

"""
Incident-reporting tests — section assembly, IOC/MITRE aggregation, timeline
ordering, AI reuse vs. template fallback, and JSON/PDF export validity (incl.
pagination). Offline: builds reports from in-memory bundles, no DB.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.services.reporting import (
    ActionView, AlertView, EventView, IncidentBundle, ReportBuilder, to_json, to_pdf,
)
from app.services.reporting.schemas import IncidentReport

T0 = datetime(2026, 1, 10, 13, 55, 0, tzinfo=timezone.utc)
BUILDER = ReportBuilder()


def _bundle(**over):
    base = dict(
        title="SSH brute force on web01", severity="critical", status="contained",
        created_at=T0,
        alerts=[AlertView(
            title="SSH brute force succeeded", severity="critical", threat_type="brute_force",
            source_ip="45.77.12.9", hostname="web01", affected_user="root",
            mitre_techniques=["T1110", "T1078"],
            iocs={"ips": ["45.77.12.9"], "hashes": ["abc123"], "domains": ["evil.example.com"]},
            created_at=T0,
        )],
        events=[
            EventView(event_type="ssh_login_failed", source_ip="45.77.12.9", username="root",
                      hostname="web01", timestamp=T0 + timedelta(seconds=i * 2))
            for i in range(3)
        ] + [EventView(event_type="ssh_login_success", source_ip="45.77.12.9", username="root",
                       hostname="web01", timestamp=T0 + timedelta(seconds=30))],
        actions=[ActionView(action_type="block_ip", target="45.77.12.9", status="completed",
                            executed_at=T0 + timedelta(minutes=2))],
    )
    base.update(over)
    return IncidentBundle(**base)


# ── Section assembly ──────────────────────────────────────────────────────────
def test_report_has_all_six_sections():
    r = BUILDER.build(_bundle())
    assert r.executive_summary
    assert r.timeline
    assert r.iocs.total() > 0
    assert r.mitre
    assert r.root_cause
    assert r.recommendations
    assert r.report_id.startswith("IR-")


def test_iocs_aggregated_and_deduped():
    r = BUILDER.build(_bundle())
    assert "45.77.12.9" in r.iocs.ips
    assert r.iocs.ips.count("45.77.12.9") == 1     # deduped across alert + events
    assert "abc123" in r.iocs.hashes
    assert "evil.example.com" in r.iocs.domains
    assert "root" in r.iocs.accounts


def test_mitre_expanded_with_names_and_tactics():
    r = BUILDER.build(_bundle())
    ids = {m.technique_id for m in r.mitre}
    assert {"T1110", "T1078"} <= ids
    t1110 = next(m for m in r.mitre if m.technique_id == "T1110")
    assert t1110.name == "Brute Force" and t1110.tactic == "Credential Access"


def test_timeline_is_chronological():
    r = BUILDER.build(_bundle())
    times = [e.timestamp for e in r.timeline if e.timestamp]
    assert times == sorted(times)
    assert {e.category for e in r.timeline} >= {"detection", "event", "response"}


def test_metrics_counts():
    r = BUILDER.build(_bundle())
    assert r.metrics["alert_count"] == 1
    assert r.metrics["event_count"] == 4
    assert r.metrics["action_count"] == 1
    assert r.metrics["techniques"] == 2


# ── AI reuse vs. template fallback ────────────────────────────────────────────
def test_reuses_ai_analyst_summary_when_present():
    ai = {"ai_soc_analyst": {
        "executive_summary": "Custom AI exec summary.",
        "attack_narrative": "Custom AI attack narrative.",
        "recommended_actions": [{"title": "Block 45.77.12.9", "priority": "immediate", "rationale": "C2"}],
    }}
    b = _bundle(alerts=[AlertView(title="x", severity="critical", threat_type="brute_force",
                                  mitre_techniques=["T1110"], ai_analysis=ai, created_at=T0)])
    r = BUILDER.build(b)
    assert r.executive_summary == "Custom AI exec summary."
    assert r.root_cause == "Custom AI attack narrative."
    assert r.recommendations[0].title == "Block 45.77.12.9"


def test_template_fallback_without_ai():
    r = BUILDER.build(_bundle())   # no ai_analysis
    assert "brute_force" in r.executive_summary
    assert "originated from" in r.root_cause
    # playbook recommendations for brute_force are present
    assert any("MFA" in rec.title for rec in r.recommendations)


# ── Exports ───────────────────────────────────────────────────────────────────
def test_json_export_roundtrips():
    r = BUILDER.build(_bundle())
    js = to_json(r)
    data = json.loads(js)                     # valid JSON
    assert data["report_id"] == r.report_id
    again = IncidentReport.model_validate_json(js)   # round-trips to the model
    assert again.iocs.total() == r.iocs.total()


def test_pdf_export_is_valid():
    pdf = to_pdf(BUILDER.build(_bundle()))
    assert pdf[:4] == b"%PDF"
    assert b"%%EOF" in pdf[-32:]
    assert b"xref" in pdf
    assert b"/Type /Catalog" in pdf


def test_pdf_paginates_for_large_reports():
    # 200 events should overflow a single page → multiple /Page objects.
    events = [EventView(event_type="ssh_login_failed", source_ip="45.77.12.9",
                        username="root", hostname="web01", timestamp=T0 + timedelta(seconds=i))
              for i in range(200)]
    pdf = to_pdf(BUILDER.build(_bundle(events=events)))
    page_count = pdf.count(b"/Type /Page ")
    assert page_count >= 2
    assert pdf[:4] == b"%PDF" and b"%%EOF" in pdf[-32:]


def test_pdf_has_no_question_mark_fallbacks_for_ascii():
    pdf = to_pdf(BUILDER.build(_bundle()))
    # The bullet (0x95) and em-dash (0x97) should be encoded, not replaced.
    assert b"\x95" in pdf      # bullet glyph
    assert b"\x97" in pdf      # em-dash glyph


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))

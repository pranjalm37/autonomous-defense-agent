"""
Exporters — render an IncidentReport to JSON or PDF.

JSON is the source-of-truth serialization (SIEM/GRC ingestion, archival). PDF is
the human-distribution artifact, laid out section by section. Both derive from the
same IncidentReport, so they never disagree.
"""
from __future__ import annotations

from app.services.reporting.pdf import CYAN, DARK, GREY, PDFWriter
from app.services.reporting.schemas import IncidentReport


def to_json(report: IncidentReport) -> str:
    return report.model_dump_json(indent=2)


def to_pdf(report: IncidentReport) -> bytes:
    pdf = PDFWriter()

    # Title block
    pdf.heading("AADA — Security Incident Report", size=18, top_gap=0)
    pdf.rule()
    pdf.kv("Report ID", report.report_id)
    pdf.kv("Title", report.title)
    pdf.kv("Severity", report.severity.upper())
    pdf.kv("Status", report.status)
    pdf.kv("Generated", report.generated_at.strftime("%Y-%m-%d %H:%M UTC"))
    pdf.spacer(8)

    # 1. Executive summary
    pdf.heading("1. Executive Summary")
    pdf.paragraph(report.executive_summary)

    # 2. Timeline
    pdf.heading("2. Timeline")
    if not report.timeline:
        pdf.paragraph("No timeline entries.", color=GREY)
    for e in report.timeline:
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "—"
        pdf.subheading(f"{ts}  ·  [{e.category}]  {e.title}", size=10)
        if e.detail:
            pdf.paragraph(e.detail, size=9.5, color=GREY, indent=10, gap=3)

    # 3. Indicators of Compromise
    pdf.heading("3. Indicators of Compromise (IOCs)")
    iocs = report.iocs
    if iocs.total() == 0:
        pdf.paragraph("No indicators extracted.", color=GREY)
    for label, items in (("IP addresses", iocs.ips), ("Domains", iocs.domains),
                         ("File hashes", iocs.hashes), ("URLs", iocs.urls),
                         ("Accounts", iocs.accounts)):
        if items:
            pdf.subheading(f"{label} ({len(items)})", size=10)
            for it in items:
                pdf.bullet(it, size=9.5)

    # 4. MITRE ATT&CK
    pdf.heading("4. MITRE ATT&CK Mapping")
    if not report.mitre:
        pdf.paragraph("No techniques mapped.", color=GREY)
    for m in report.mitre:
        tactic = f"  —  {m.tactic}" if m.tactic else ""
        pdf.bullet(f"{m.technique_id}  {m.name}{tactic}")

    # 5. Root cause
    pdf.heading("5. Root Cause")
    pdf.paragraph(report.root_cause)

    # 6. Recommendations
    pdf.heading("6. Recommendations")
    if not report.recommendations:
        pdf.paragraph("None.", color=GREY)
    for r in report.recommendations:
        pdf.bullet(f"[{r.priority}] {r.title}")
        if r.detail:
            pdf.paragraph(r.detail, size=9, color=GREY, indent=16, gap=3)

    # Footer metrics
    pdf.spacer(8)
    pdf.rule(color=DARK)
    m = report.metrics
    pdf.paragraph(
        f"Alerts: {m.get('alert_count', 0)}  ·  Events: {m.get('event_count', 0)}  ·  "
        f"Actions: {m.get('action_count', 0)}  ·  IOCs: {m.get('ioc_count', 0)}  ·  "
        f"Techniques: {m.get('techniques', 0)}",
        size=9, color=GREY,
    )
    return pdf.build()

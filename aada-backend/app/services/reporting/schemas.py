"""
Incident-report structure — the canonical shape every report takes.

The six sections map to what a SOC and its stakeholders need:
  executive_summary  for leadership: what happened, impact, status (no jargon)
  timeline           the ordered sequence of events + responses (the "story")
  iocs               indicators to block/hunt and to share with peers
  mitre              ATT&CK techniques/tactics for coverage + correlation
  root_cause         the underlying failure that let it happen
  recommendations    concrete follow-ups to prevent recurrence

The same structure serializes to JSON (machine/SIEM ingestion) and renders to PDF
(human distribution), so one report has one source of truth.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    timestamp: datetime | None = None
    category: str            # detection | event | analysis | response | approval
    title: str
    detail: str | None = None


class IOCSet(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)

    def total(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes) + len(self.urls) + len(self.accounts)


class MitreRef(BaseModel):
    technique_id: str
    name: str
    tactic: str | None = None


class Recommendation(BaseModel):
    title: str
    detail: str | None = None
    priority: str = "medium"


class IncidentReport(BaseModel):
    report_id: str
    title: str
    severity: str
    status: str
    generated_at: datetime

    executive_summary: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    iocs: IOCSet = Field(default_factory=IOCSet)
    mitre: list[MitreRef] = Field(default_factory=list)
    root_cause: str
    recommendations: list[Recommendation] = Field(default_factory=list)

    metrics: dict = Field(default_factory=dict)   # counts, time-to-detect, etc.

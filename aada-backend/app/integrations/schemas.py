"""
Normalized integration results.

Each provider returns its own JSON shape; we map all of them onto these common
models (same philosophy as the log normalizer). The rest of the app — MCP tools,
the analyst, the dashboard — only ever sees `IPReputation` / `FileReport` /
`CVERecord`, never a vendor-specific blob. `raw` keeps the original response for
drill-down and re-normalization.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


def verdict_for(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "clean"


class IPReputation(BaseModel):
    ip: str
    malicious_score: int = Field(ge=0, le=100)   # 0 clean … 100 malicious
    verdict: str
    categories: list[str] = Field(default_factory=list)
    total_reports: int | None = None
    country: str | None = None
    sources: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class FileReport(BaseModel):
    sha256: str | None = None
    malicious: int = 0
    suspicious: int = 0
    total_engines: int = 0
    verdict: str = "unknown"
    names: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class CVERecord(BaseModel):
    id: str
    cvss: float | None = None
    severity: str | None = None
    description: str = ""
    products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published: str | None = None
    source: str = "NVD"
    raw: dict = Field(default_factory=dict)

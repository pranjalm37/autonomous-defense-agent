# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
below are inferred from commit history, not tagged releases — no git tags exist
yet, so treat these as milestones rather than published versions.

## [Unreleased]

### Added
- `.gitattributes` — LF line endings on shell/Python files, binary handling
  for fonts and images.
- `.editorconfig` — 4-space indent for Python, 2-space for TS/JSON/YAML.
- `CONTRIBUTING.md` — setup, backend/frontend conventions, PR expectations.
- `SECURITY.md` — reporting process and scope notes.
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1.
- `.github/ISSUE_TEMPLATE/bug_report.yml` — structured bug report form.

### Changed
- Rewrote the README in plainer language.
- Corrected the offline test count across README, TESTING.md, and
  ARCHITECTURE.md (docs disagreed with each other — 165 vs. 169 — and both
  were stale; real count is 188).
- Shrank the README's Contributing section to a pointer at CONTRIBUTING.md
  instead of duplicating it.

## [1.1.0] - 2026-08-07

### Added
- Attack simulator API for staging scenarios through the pipeline.
- Attack simulator UI with a live pipeline trace.
- Operator-console design tokens and self-hosted typography.

### Changed
- Redesigned the dashboard theme: neutral dark palette, dropped the
  glow/glassmorphism look.
- Replaced the dashboard with a triage view built on time and flow.
- Rebuilt the application shell on the new design system and carried it
  across the remaining pages.

### Fixed
- Frontend healthcheck was probing the IPv6 loopback address.
- ChromaDB telemetry was logging errors on every RAG request.
- `ALLOWED_HOSTS` wasn't pinned in the test environment.
- TypeScript build output was leaking into the frontend source tree.

## [1.0.0] - 2026-07-01

Initial release. Full backend + frontend stack:

- FastAPI backend with async PostgreSQL (11-table schema), JWT auth, and
  role-based access control.
- Multi-format event ingestion (JSON/CSV/SSH/auth/web) with normalization.
- Detection engine — 6 rules, risk scoring, MITRE ATT&CK mapping.
- RAG knowledge base (MITRE/OWASP/Sigma/NIST/IR) on ChromaDB, offline
  fallback when no OpenAI key is set.
- AI SOC analyst producing structured, RAG-grounded LLM analysis.
- MCP server exposing 6 security tools (IP reputation, CVE search, GeoIP,
  log search, firewall action, threat intel).
- External integrations: VirusTotal, AbuseIPDB, NVD, with caching, rate
  limiting, and retry/backoff.
- Decision engine fusing detection + LLM + threat intel + RAG into one
  risk/confidence score across Monitor/Assisted/Autonomous modes.
- Response engine — 5 remediation actions, approval workflow, rollback,
  safety guardrails.
- Incident reporting with PDF/JSON export.
- React + TypeScript dashboard.
- Docker Compose deployment for the full stack.

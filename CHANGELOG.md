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
- `.github/ISSUE_TEMPLATE/feature_request.yml` — structured feature request form.
- `.github/PULL_REQUEST_TEMPLATE.md` — checklist matching CONTRIBUTING.md.
- `.github/dependabot.yml` — weekly version updates for pip (aada-backend) and npm (aada-frontend).
- `.github/workflows/backend-tests.yml` — runs the offline pytest suite on push/PR.
- GitHub Actions ecosystem block in `dependabot.yml` — keeps action versions
  (e.g. `actions/checkout`, `actions/setup-python`) up to date too.
- `.github/workflows/frontend-build.yml` — `npm ci` + typecheck + Vite build
  on push/PR (Node 20, matching the Dockerfile).
- `target-version` and an `alembic/versions` exclude in the Ruff config, and
  moved `select` into `[tool.ruff.lint]` (the old top-level location is
  deprecated). Ran it against the codebase: 216 outstanding issues, 108
  auto-fixable — ruff's been a declared dependency but never actually
  wired into anything, so nothing's enforced it until now. Cleanup is a
  separate step (#17).
- `lint` job in `backend-tests.yml` (renamed to "Backend CI") — runs
  `ruff check .` on push/PR. This will fail right now: 216 outstanding
  issues from before Ruff was ever actually wired in. #17 cleans those up.
- Status badges in the README: Backend CI, Frontend build, Python 3.11,
  MIT license. Fills the placeholder that was there before CI existed.
- Roadmap section in the README — 4 items, checked against the actual code
  rather than copied from an old plan: no WebSocket/Redis/ARQ/Celery
  anywhere in the backend, and the MCP tools exist but the analyst doesn't
  call them itself yet.
- `.github/workflows/docker-build.yml` — `docker compose build` on push/PR
  when backend, frontend, or the compose file changes.

  First push of this broke CI: `docker-compose.yml`'s `${VAR:?...}` checks
  turned out to interpolate the *whole* file up front, so they fire even on
  a build-only run that never touches `services.backend.environment`. My
  "verified locally" claim in that commit was wrong — I had a real `.env`
  sitting in the repo already, so the no-secrets case was never actually
  exercised. Fixed by reproducing the failure locally first (temporarily
  moved `.env` aside, confirmed the same error), then setting two
  placeholder env vars on the step — never used to run anything, just
  satisfies the interpolation check — and re-verifying against that same
  broken state before pushing again.
- `aada-backend/poetry.lock` — never existed before, so every CI run
  re-resolved dependencies from scratch and caching had nothing reliable
  to key off. Generated with Poetry 2.4.1; `python-versions = "^3.11"` in
  the lock's metadata matches the project constraint even though the
  generating interpreter was 3.14 (Poetry resolves against declared
  markers, not the host interpreter).
- Poetry virtualenv caching in both `test` and `lint` jobs
  (`POETRY_VIRTUALENVS_IN_PROJECT`, `actions/cache` keyed on the new
  lock file's hash, separate keys per job since `lint` only installs
  the dev dependency group).
- `pytest-cov` + `[tool.coverage]` config, wired into the `test` job — runs
  with `--cov=app --cov-report=term-missing` and writes the coverage table
  to the job's step summary. Excludes `mcp_server/server.py` (the stdio
  entrypoint, not something the offline suite ever runs) from the report.
- Four real screenshots in `docs/images/` (Triage dashboard, AI analysis,
  incident report, alerts list), replacing the "Coming soon" placeholder.
  Captured from an actual local run — `docker compose up -d --build`,
  `./demo_attack.sh`, plus a few more scenarios staged through the attack
  simulator — not mocked up.

### Removed
- Unused `langchain` dependency from `aada-backend/pyproject.toml`. It was
  never actually imported anywhere in the codebase (the RAG pipeline uses
  its own vector store and embedding providers), and a critical CVE
  (GHSA-c67j-w6g6-q2cm, langchain-core serialization injection) was flagged
  against it. Not exploitable here since it was dead code, but no reason to
  keep unused, vulnerable dependencies around.

### Fixed
- Applied Ruff's safe autofixes across the backend (import sorting, unused
  imports) — 109 of the 216 issues found in #15/#16. Verified every touched
  `__init__.py` for net-removed re-exports before trusting it (found none —
  all reordering, no names actually dropped).
- Bumped Ruff's `line-length` from 100 to 120 after checking the remaining
  107 line-too-long violations: 105 of them were within 20 characters of
  the old limit, and running the formatter to reflow everything would have
  touched 133 files / ~8,200 lines for a codebase that was never run
  through one — not worth that blast radius for a lint config mismatch.
  Fixed the 2 real outliers by hand: wrapped a long `logger.info(...)`
  call, and added a per-file `E501` ignore for a parser docstring that
  quotes a literal example log line (wrapping it would misrepresent the
  format it documents).
- Renamed an ambiguous loop variable (`l` → `line`) flagged by E741.
- `ruff check .` is now clean.

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

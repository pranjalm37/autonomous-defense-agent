# AADA — Autonomous Defense Agent

An end-to-end, AI-powered **Security Operations Center (SOC) agent**. AADA ingests
security telemetry, detects attacks, reasons about them with an LLM grounded in a
cybersecurity knowledge base, fuses every signal into a risk-scored decision, and
proposes — or, within policy, executes — remediation behind a human-in-the-loop
gate. Every step is audited.

<!-- Badges (optional): add build/coverage/license badges once CI is set up. -->

---

## Overview

AADA models the full triage workflow a SOC analyst performs, as a chain of
independent, single-responsibility services:

```
ingest → detect → analyze (LLM + RAG) → enrich (threat intel) → decide → respond → report
  │         │            │                      │                  │         │         │
 logs    6 rules     SOC analyst          VT/AbuseIPDB/NVD    fuse risk   approval   PDF/JSON
 (5 fmt) +MITRE     (structured output)   (cache+ratelimit)  +confidence  +rollback  +timeline
                                                                          +guardrails
                            ▲ every step writes an immutable audit log ▲
```

The system runs fully offline out of the box — deterministic local providers stand
in for the LLM, embeddings, and threat-intel feeds — so the entire pipeline works
without any API keys. Supplying keys switches to live providers with no code change.

> **Note:** This is an educational / research project. The remediation backends ship
> as safe in-memory simulations; wire real ones in only behind the approval workflow.

## Features

- **Multi-format ingestion** — JSON, CSV, SSH, auth, and web logs normalized to one
  ECS-subset event schema.
- **Detection engine** — 6 rules (SSH brute force, port scan, credential stuffing,
  impossible travel, privilege escalation, malware/IOC) with risk scoring and full
  **MITRE ATT&CK** mapping.
- **RAG knowledge base** — MITRE / OWASP / Sigma / NIST / IR playbooks in a vector
  store (ChromaDB), with pluggable OpenAI or offline embeddings.
- **SOC analyst** — structured-output LLM analysis (executive summary, technical
  detail, MITRE, risk, recommended actions) grounded in retrieved context.
- **Decision engine** — fuses detection + LLM + threat-intel + RAG into one
  risk/confidence score across **Monitor / Assisted / Autonomous** operating modes.
- **Response engine** — 5 remediation actions (alert, block IP, disable account,
  ticket, increase logging) with an **approval workflow**, **rollback**, and **safety
  guardrails** (refuses to block internal IPs or disable protected accounts).
- **External integrations** — VirusTotal, AbuseIPDB, and NVD clients with caching,
  client-side rate limiting, retry/backoff, and graceful degradation.
- **Auth & RBAC** — JWT (access + refresh), three roles (viewer / analyst / admin),
  a permission map, and startup seeding.
- **Immutable audit trail** — every user, model, remediation, and tool action recorded.
- **Web dashboard** — React + TypeScript + Tailwind (Dashboard, Alerts,
  Investigations, Reports, Settings).

## Architecture

The backend is organized as pure-core services (rules, fusion, decision policy, and
report building are pure functions over plain inputs) behind thin I/O edges, with
provider interfaces that swap between live and offline implementations by
configuration. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system-context,
pipeline, and data-model diagrams.

| Concern | Component |
|---|---|
| API | FastAPI (async), 42 REST endpoints across 13 modules |
| Persistence | PostgreSQL 16 (11-table schema, SQLAlchemy 2.0 async) |
| Retrieval | ChromaDB vector store + embedding providers |
| Tooling | Model Context Protocol (MCP) server exposing 6 security tools |
| Frontend | React SPA served by nginx, reverse-proxying the API (single origin) |

## Installation

### Prerequisites
- Docker + Docker Compose (recommended path), **or**
- Python 3.11 + Poetry and Node.js 18+ for local development.

### Run with Docker (recommended)

```bash
cp .env.example .env          # then edit .env — see Configuration below
docker compose up -d --build
docker compose ps             # services should report healthy
```

| Service | URL |
|---|---|
| Dashboard (SPA) | http://localhost:8080 |
| API docs (Swagger) | http://localhost:8000/docs |
| Health | http://localhost:8000/api/v1/health |

Log in with the `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` you set in `.env`.

Stop with `docker compose down` (add `-v` to also remove the database volume).

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and
set the required values; the rest have sensible defaults.

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — generate with `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | ✅ | database password |
| `DEFAULT_ADMIN_PASSWORD` | ✅ | bootstrap admin password (seeded on first start) |
| `DEFAULT_ADMIN_EMAIL` | | bootstrap admin email (default `admin@aada.io`) |
| `OPENAI_API_KEY` | | enables live LLM + embeddings; offline fallback if unset |
| `VIRUSTOTAL_API_KEY` | | enables live IP/file reputation enrichment |
| `ABUSEIPDB_API_KEY` | | enables live IP abuse enrichment |
| `NVD_API_KEY` | | raises the NVD CVE rate limit |

`.env` files are git-ignored and must never be committed — only `.env.example`
(placeholders) is tracked.

## Usage

Once the stack is running, drive the full attack → detection → defense loop with the
included demo script:

```bash
./demo_attack.sh
```

It stages a live SSH brute-force attack and walks every stage — ingest, detect, AI
analysis, decision, approval, block, rollback, and audit. Point it at an internal IP
to watch the safety guardrail refuse the action:

```bash
ATTACKER_IP=10.0.0.9 ./demo_attack.sh
```

You can also drive everything from the dashboard (http://localhost:8080) or the
Swagger explorer (http://localhost:8000/docs). See [DEMO.md](DEMO.md) for a full
walkthrough and [docs/API.md](docs/API.md) for the endpoint reference.

### Local development

```bash
# Backend
cd aada-backend && poetry install
uvicorn app.main:app --reload                    # http://localhost:8000/docs
pytest tests/ -q --ignore=tests/test_auth.py     # 169 offline tests

# Frontend
cd aada-frontend && npm install && npm run dev   # http://localhost:5173
```

## Screenshots

<!-- Add dashboard screenshots here, e.g.:
![Dashboard](docs/images/dashboard.png)
![Investigation](docs/images/investigation.png)
-->

_Screenshots coming soon._

## Project structure

```
.
├── docker-compose.yml          full-stack orchestration (db, chroma, backend, frontend)
├── demo_attack.sh              end-to-end attack → defense demo
├── docs/                       architecture + API reference
├── aada-backend/               FastAPI service
│   ├── app/
│   │   ├── api/v1/endpoints/    REST endpoints (auth, events, detection, …)
│   │   ├── services/            detection · rag · ai_analyst · decision · response · reporting
│   │   ├── integrations/        VirusTotal / AbuseIPDB / NVD clients
│   │   ├── mcp_server/          MCP tool server (6 security tools)
│   │   ├── models/              SQLAlchemy models (source of truth for the schema)
│   │   └── core/, db/, schemas/
│   └── tests/                   unit · API · attack-simulation suites
└── aada-frontend/              React + TypeScript + Tailwind dashboard
```

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI (async), SQLAlchemy 2.0, Pydantic v2 |
| Data | PostgreSQL 16 (asyncpg), ChromaDB |
| AI | OpenAI API (chat + embeddings), RAG, deterministic offline fallbacks |
| Integrations | httpx clients (VirusTotal / AbuseIPDB / NVD), MCP tool server |
| Frontend | React 18, TypeScript, Vite, Tailwind, shadcn/ui, React Query, Zustand |
| Infra | Docker multi-stage builds, docker-compose, nginx |
| Quality | pytest (169 tests), structlog (JSON logs), 42 REST endpoints |

## Contributing

Contributions are welcome. To get started:

1. Fork the repository and create a feature branch.
2. Set up the backend and frontend as shown under **Local development**.
3. Keep changes focused and covered by tests — run `pytest tests/` before opening a PR.
4. Follow the existing conventions (async DB access, typed schemas, structured logging).

Please open an issue to discuss significant changes before submitting a large PR.

## License

Released under the [MIT License](LICENSE).

## Further reading

- [DEMO.md](DEMO.md) — run, use, and demo the attack → defense loop
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design + diagrams
- [docs/API.md](docs/API.md) — REST API reference (42 endpoints)
- [aada-backend/TESTING.md](aada-backend/TESTING.md) — testing strategy
- [DEPLOYMENT.md](DEPLOYMENT.md) — deployment & operations

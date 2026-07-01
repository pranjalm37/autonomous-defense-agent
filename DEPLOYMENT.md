# AADA — Deployment

Full-stack containerized deployment of the AI Autonomous Defense Agent.

## Quickstart

```bash
cp .env.example .env
# REQUIRED: set SECRET_KEY (openssl rand -hex 32) and DEFAULT_ADMIN_PASSWORD
docker compose up -d --build
```

| Service  | URL | Notes |
|----------|-----|-------|
| Frontend | http://localhost:8080 | React SPA (nginx) — log in with the bootstrap admin |
| API docs | http://localhost:8000/docs | Swagger (dev only) |
| Health   | http://localhost:8000/api/v1/health | DB connectivity probe |

Stop / wipe:
```bash
docker compose down            # stop, keep data
docker compose down -v         # stop and delete volumes (Postgres + Chroma data)
```

## The four containers

| Container | Image | Role | Port (host→container) |
|---|---|---|---|
| `db` | postgres:16-alpine | Relational store (11 tables) | — (internal) |
| `chroma` | chromadb/chroma:0.5.5 | Vector store for RAG | — (internal) |
| `backend` | built from `aada-backend/` | FastAPI agent API | 8000→8000 |
| `frontend` | built from `aada-frontend/` | nginx + SPA, proxies `/api` | 8080→80 |

## Explanation

### Containers
Each service is an isolated, immutable image with only what it needs:
- **Backend** — a **multi-stage** build: stage 1 (poetry) resolves the virtualenv;
  stage 2 copies just that venv + source into a slim runtime that runs as a
  **non-root** user. Multi-stage keeps build tools out of the shipped image (smaller,
  smaller attack surface). An entrypoint waits for Postgres, applies Alembic
  migrations if any exist, then launches uvicorn. A `HEALTHCHECK` hits `/health`.
- **Frontend** — multi-stage too: Node builds the static bundle, then it's served by
  a tiny nginx image with **no Node runtime** shipped.
- **State lives in volumes, not containers** (`pgdata`, `chromadata`), so containers
  stay disposable — you can rebuild/replace them without losing data. Config comes
  in through environment variables (12-factor), never baked into the image; `.env`
  and secrets are excluded via `.dockerignore`.

### Networking
- All services share one **user-defined bridge network** (`aada`). On it, Docker's
  embedded DNS resolves services by name — the backend reaches Postgres at `db:5432`
  and Chroma at `chroma:8000`; nginx proxies to `backend:8000`. No IPs hard-coded.
- **Only two ports are published to the host** (frontend 8080, backend 8000 for
  docs). Postgres and Chroma have **no host ports** — they're reachable only from
  inside the network, which is the main reason to use a private network: the data
  tier is never exposed to the host/internet.
- The browser talks to a **single origin** (the frontend); nginx reverse-proxies
  `/api/*` to the backend, so there's **no CORS** and the backend port needn't be
  public in production.

### Deployment
- **Startup ordering** uses `depends_on` + healthchecks: backend waits for Postgres
  to be *healthy* (accepting queries), not merely started; frontend waits for the
  backend. The backend entrypoint additionally polls the DB before serving.
- **First-boot schema**: `schema.sql` is mounted into Postgres'
  `/docker-entrypoint-initdb.d`, so all tables + extensions + the three seed roles
  are created automatically on the first `up`. The backend also seeds roles +
  bootstrap admin idempotently on startup (`AUTO_SEED`).
- **Resilience**: `restart: unless-stopped` revives crashed containers; healthchecks
  let an orchestrator replace unhealthy ones.

## Production notes
- Set a strong `SECRET_KEY` and `DEFAULT_ADMIN_PASSWORD`; rotate the admin password
  after first login. Inject secrets via your platform's secret manager, not `.env`.
- Put a TLS-terminating reverse proxy / load balancer in front of `frontend`.
- Don't publish `BACKEND_PORT` publicly — the SPA reaches the API through nginx.
- Once you generate Alembic migrations, they take over from `schema.sql` (the
  entrypoint runs `alembic upgrade head` when `alembic/versions/` is non-empty).
- This compose targets a single host. For multi-node, translate to Kubernetes
  (Deployments + Services + a StatefulSet/managed Postgres + PVCs for Chroma).

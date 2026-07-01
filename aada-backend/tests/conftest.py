"""
Shared pytest fixtures + test environment.

Sets dummy env BEFORE the app is imported so config validates without real
secrets/DB, then exposes:
  - `client`           a FastAPI TestClient (no auth)
  - `as_role`          factory → TestClient authenticated as viewer/analyst/admin
  - domain factories   make_user / make_event / make_alert (in-memory ORM objects)

The TestClient is used WITHOUT the lifespan context manager, so startup seeding is
not triggered — these tests never need a live database. Endpoints that don't touch
the DB (decision/evaluate, knowledge/query, analyst/analyze, detection/rules) run
fully end-to-end; DB-backed endpoints are exercised only for their auth guards.
"""
from __future__ import annotations

import os
import uuid

# ── Test environment (must be set before importing app config) ────────────────
# These OVERRIDE any aada-backend/.env (env vars beat the .env file in pydantic),
# pinning the suite to the offline providers — no OpenAI, no ChromaDB, no real DB.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("AUTO_SEED", "false")
os.environ.setdefault("LOG_FORMAT", "console")
os.environ.setdefault("OPENAI_API_KEY", "")        # → offline hashing embeddings + heuristic LLM
os.environ.setdefault("CHROMA_HOST", "")           # → in-memory vector store
os.environ.setdefault("CHROMA_PERSIST_DIR", "")

import pytest  # noqa: E402


# ── Domain factories (in-memory ORM objects; no session needed) ───────────────
def make_user(role: str = "analyst", *, email: str | None = None):
    """Duck-typed current-user for dependency overrides.

    Deliberately NOT a real `User` ORM instance — assigning a fake to the mapped
    `role` relationship would trip SQLAlchemy's backref machinery. The auth guards
    only read `.id`, `.email`, `.is_active`, and `.role.name`, so a namespace is
    all they need.
    """
    from types import SimpleNamespace
    return SimpleNamespace(
        id=uuid.uuid4(),
        email=email or f"{role}@test.io",
        username=role,
        full_name=role.title(),
        is_active=True,
        role=SimpleNamespace(name=role, id=uuid.uuid4()),
    )


def make_event(event_type: str, *, t=None, **fields):
    """Lightweight SecurityEvent-shaped object for detection/pipeline tests."""
    from datetime import datetime, timezone, timedelta
    base = datetime(2026, 1, 10, 14, 0, 0, tzinfo=timezone.utc)
    obj = type("Ev", (), {})()
    obj.id = uuid.uuid4()
    obj.event_type = event_type
    obj.ingested_at = base + timedelta(seconds=t or 0)
    obj.created_at = obj.ingested_at
    obj.normalized_payload = {"event_type": event_type, **fields}
    obj.raw_payload = {"event_type": event_type, **fields}
    for k, v in fields.items():
        setattr(obj, k, v)
    return obj


# ── App / client fixtures ─────────────────────────────────────────────────────
@pytest.fixture
def app_instance():
    from app.main import app
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def client(app_instance):
    from fastapi.testclient import TestClient
    return TestClient(app_instance, raise_server_exceptions=False)


@pytest.fixture
def as_role(app_instance):
    """Return a TestClient authenticated as the given role via dependency override."""
    from fastapi.testclient import TestClient
    from app.dependencies import get_current_user

    def _as(role: str) -> "TestClient":
        app_instance.dependency_overrides[get_current_user] = lambda: make_user(role)
        return TestClient(app_instance, raise_server_exceptions=False)

    return _as

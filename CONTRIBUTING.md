# Contributing

PRs welcome. This is a small project, so the process is lightweight — but a few
conventions keep the codebase consistent.

## Getting set up

```bash
# Backend
cd aada-backend && poetry install
uvicorn app.main:app --reload                    # http://localhost:8000/docs
pytest tests/ -q --ignore=tests/test_auth.py     # offline test suite

# Frontend
cd aada-frontend && npm install && npm run dev   # http://localhost:5173
```

Full setup (Docker, env vars, service URLs) is in the [README](README.md).

## Before opening a PR

- Fork the repo and branch off `main`.
- Run `pytest tests/` — keep it green.
- Keep the change focused. Split unrelated fixes into separate PRs.
- For anything bigger than a small fix, open an issue first so we can talk
  through the approach before you put the work in.

## Backend conventions

These aren't stylistic preferences — the app is built around them, so
breaking one usually breaks something downstream.

- **Never call `db.commit()` in an endpoint.** `app/db/session.py`'s `get_db()`
  auto-commits on success and rolls back on error.
- **Never raise `HTTPException` in business logic.** Use the exception types
  in `app/core/exceptions.py` (`NotFoundError`, `UnauthorizedError`, etc.) —
  they're mapped to HTTP responses centrally.
- **All DB queries are async.** `await db.execute(...)`, never sync SQLAlchemy.
- **Logging:** `from app.logging_config import get_logger; logger = get_logger(__name__)`.
  No `print()`.
- **Config:** `from app.config import get_settings; settings = get_settings()`.
  No `os.getenv()`.
- **RBAC:** `Depends(require_roles("admin", ...))` — no inline role checks.
- **Response schemas:** `ConfigDict(from_attributes=True)` for ORM compatibility.
- **Model changes:** run `alembic revision --autogenerate -m "description"`,
  then `alembic upgrade head`, and commit the generated migration alongside
  the model change.

## Frontend conventions

- Server state goes through React Query (`src/hooks/queries.ts`); client state
  (token, defense mode) goes through the Zustand store (`src/store/appStore.ts`).
- All API calls go through the typed client in `src/lib/api.ts` — don't call
  `fetch` directly from a component.

## Commit messages

Short, plain, describes what changed and why if it's not obvious. `type: summary`
(`feat:`, `fix:`, `docs:`, `chore:`, `ci:`) is the pattern used in this repo's
history — not a hard rule, just keep it consistent with what's there.

## Tests

New logic needs tests. The suite is fully offline (deterministic providers stand
in for the LLM, embeddings, and threat-intel feeds — see
[aada-backend/TESTING.md](aada-backend/TESTING.md)), so there's no excuse for a
flaky one. `test_auth.py` is the one exception — it needs a live Postgres and is
excluded from the default run.

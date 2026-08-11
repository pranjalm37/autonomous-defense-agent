## What does this change, and why?

<!-- A couple sentences is enough. Link an issue if there is one. -->

## Checklist

- [ ] `pytest tests/` passes locally
- [ ] Ran a model change through `alembic revision --autogenerate` (if applicable) and committed the migration
- [ ] Followed the backend conventions in [CONTRIBUTING.md](../CONTRIBUTING.md) (async DB access, no `db.commit()` in endpoints, no `HTTPException` in business logic, etc.)
- [ ] No secrets, API keys, or `.env` values in the diff

## How did you test this?

<!-- Commands you ran, or what you clicked through in the dashboard. -->

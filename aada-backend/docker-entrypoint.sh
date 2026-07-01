#!/bin/sh
# Backend container entrypoint: wait for Postgres, apply migrations if any exist,
# then start the API. (On first boot the schema is created by schema.sql, mounted
# into Postgres' init dir; once Alembic migrations are generated they take over.)
set -e

DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"

echo "[entrypoint] waiting for Postgres at ${DB_HOST}:${DB_PORT} ..."
python - "$DB_HOST" "$DB_PORT" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(60):
    try:
        socket.create_connection((host, port), 2).close()
        print("[entrypoint] Postgres is up"); break
    except OSError:
        time.sleep(1)
else:
    print("[entrypoint] Postgres unreachable", file=sys.stderr); sys.exit(1)
PY

if ls alembic/versions/*.py >/dev/null 2>&1; then
  echo "[entrypoint] applying Alembic migrations ..."
  alembic upgrade head || echo "[entrypoint] alembic upgrade failed (continuing)"
else
  echo "[entrypoint] no Alembic migrations — relying on schema.sql init"
fi

echo "[entrypoint] starting uvicorn (workers=${UVICORN_WORKERS:-2}) ..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers "${UVICORN_WORKERS:-2}"

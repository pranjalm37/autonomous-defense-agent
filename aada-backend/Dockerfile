# ── Stage 1: Dependencies ─────────────────────────────
# Build the virtualenv in an isolated layer so app-code changes don't re-install deps.
FROM python:3.11-slim AS deps
WORKDIR /app
RUN pip install --no-cache-dir poetry==1.8.0
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.in-project true \
 && poetry install --only=main --no-root --no-interaction

# ── Stage 2: Runtime ──────────────────────────────────
FROM python:3.11-slim AS runtime
WORKDIR /app

# Non-root user — never run the API as root.
RUN addgroup --system aada && adduser --system --group aada

# Virtualenv from the deps stage + application source.
COPY --from=deps /app/.venv /app/.venv
COPY --chown=aada:aada . .
RUN chmod +x docker-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UVICORN_WORKERS=2

USER aada
EXPOSE 8000

# Liveness + DB connectivity probe (no curl needed in the slim image).
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/v1/health',timeout=3).status==200 else 1)" || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]

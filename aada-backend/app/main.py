import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.router import router as v1_router
from app.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.logging_config import get_logger, setup_logging

settings = get_settings()


# ── Lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown logic. Replaces deprecated @app.on_event."""
    setup_logging(log_level=settings.log_level, log_format=settings.log_format)
    logger = get_logger(__name__)
    logger.info("startup", env=settings.app_env, debug=settings.debug)

    # Ensure the schema exists. The ORM models are the single source of truth —
    # create_all builds every table + enum type consistently, avoiding drift from
    # a hand-maintained schema.sql. (Once Alembic migrations exist they take over;
    # create_all is a no-op for already-present tables.) Guarded so a missing DB
    # at startup doesn't crash the app.
    if getattr(settings, "auto_seed", True):
        try:
            import app.models  # noqa: F401 — register all tables on Base.metadata
            from app.db.base import Base
            from app.db.session import engine
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception as e:  # noqa: BLE001
            logger.warning("startup_create_all_skipped", error=str(e))

    # Best-effort role seeding so login works out of the box. Guarded: a missing
    # or unmigrated DB at startup must not crash the app.
    if getattr(settings, "auto_seed", True):
        try:
            from app.db.seed import seed
            from app.db.session import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                await seed(session)
                await session.commit()
        except Exception as e:  # noqa: BLE001
            logger.warning("startup_seed_skipped", error=str(e))

    yield
    logger.info("shutdown")


# ── App Factory ───────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        docs_url="/docs" if not settings.is_production else None,   # hide Swagger in prod
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters: first added = outermost) ───────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts,
    )

    # ── Request ID middleware ─────────────────────────────────────────────────
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id, path=request.url.path)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Exception Handlers ───────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(v1_router, prefix=settings.api_v1_prefix)

    return app


app = create_app()

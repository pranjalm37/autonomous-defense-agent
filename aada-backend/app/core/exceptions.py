from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


# ── Domain Exceptions ────────────────────────────────────────────────────────

class AADAException(Exception):
    """Base exception. All domain errors extend this."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class NotFoundError(AADAException):
    def __init__(self, resource: str, identifier: str | int):
        super().__init__(f"{resource} '{identifier}' not found", "NOT_FOUND")


class UnauthorizedError(AADAException):
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(detail, "UNAUTHORIZED")


class ForbiddenError(AADAException):
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(detail, "FORBIDDEN")


class ConflictError(AADAException):
    def __init__(self, detail: str):
        super().__init__(detail, "CONFLICT")


class ValidationError(AADAException):
    def __init__(self, detail: str):
        super().__init__(detail, "VALIDATION_ERROR")


# ── HTTP Status Mapping ───────────────────────────────────────────────────────

# Starlette >=0.47 renamed HTTP_422_UNPROCESSABLE_ENTITY -> HTTP_422_UNPROCESSABLE_CONTENT
# (same 422 code). Touching the old name on newer Starlette emits a
# StarletteDeprecationWarning. We must read the new name without eagerly accessing
# the old one — a `getattr(..., status.HTTP_422_UNPROCESSABLE_ENTITY)` default would
# still trip the warning because Python evaluates the default argument regardless.
try:
    _HTTP_422 = status.HTTP_422_UNPROCESSABLE_CONTENT
except AttributeError:  # older Starlette without the new constant
    _HTTP_422 = status.HTTP_422_UNPROCESSABLE_ENTITY

_STATUS_MAP: dict[type, int] = {
    NotFoundError:    status.HTTP_404_NOT_FOUND,
    UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
    ForbiddenError:   status.HTTP_403_FORBIDDEN,
    ConflictError:    status.HTTP_409_CONFLICT,
    ValidationError:  _HTTP_422,
}


# ── FastAPI Handler Registration ─────────────────────────────────────────────

def register_exception_handlers(app: FastAPI) -> None:
    """Call once in main.py to attach all handlers."""

    @app.exception_handler(AADAException)
    async def aada_exception_handler(request: Request, exc: AADAException) -> JSONResponse:
        http_status = _STATUS_MAP.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
        return JSONResponse(
            status_code=http_status,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log the full traceback but return a safe message
        from app.logging_config import get_logger
        get_logger(__name__).exception("unhandled_error", path=str(request.url), exc=str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred"}},
        )

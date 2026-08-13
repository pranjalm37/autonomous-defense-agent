import logging
import sys

import structlog


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """
    Configure structlog once at startup.
    - json  → machine-readable, ideal for log aggregators (Splunk, Datadog)
    - console → human-readable colored output for development
    """

    # Shared processors run on every log event
    shared_processors: list = [
        structlog.contextvars.merge_contextvars,        # request-scoped fields (request_id, user_id)
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_logger_name,
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level.upper())
        ),
        context_class=dict,
        # stdlib factory (NOT PrintLogger): the ProcessorFormatter pattern +
        # add_logger_name need a stdlib-backed logger that has a .name attribute.
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (uvicorn, SQLAlchemy) through structlog
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level.upper())

    # Silence noisy loggers in production
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    # chromadb 0.5.x calls posthog.capture(id, name, props), but posthog 7.x
    # accepts a single positional arg, so every client start logs a TypeError at
    # error level. Telemetry is already disabled at the client (see
    # rag/vectorstore.py), so nothing is sent — this only drops the false alarm.
    logging.getLogger("chromadb.telemetry").setLevel(logging.CRITICAL)


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """Import and call this anywhere: logger = get_logger(__name__)"""
    return structlog.get_logger(name)

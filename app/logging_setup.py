"""structlog en JSON (stdout + logs/app.jsonl) para eventos consultables."""
from __future__ import annotations

import logging
import sys

import structlog

from .config import settings


def configure_logging() -> None:
    settings.log_file.parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(settings.log_file, encoding="utf-8"),
    ]
    logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=handlers, force=True)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


log = structlog.get_logger("spti")

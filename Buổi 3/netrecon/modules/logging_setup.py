"""Structured logging with a strict allowlist for safe event records."""

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
import re


_SAFE_EVENT = re.compile(r"event=[a-z][a-z0-9_]* count=[0-9]+ status=[1-5][0-9]{2}\Z")


class _SafeEventFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return bool(_SAFE_EVENT.fullmatch(record.getMessage()))
        except (TypeError, ValueError):
            return False


def configure_logging(log_dir: Path) -> logging.Logger:
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("netrecon")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for existing in logger.handlers[:]:
        logger.removeHandler(existing)
        existing.close()

    handler = TimedRotatingFileHandler(
        directory / "netrecon.log",
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
        utc=True,
    )
    handler.addFilter(_SafeEventFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger

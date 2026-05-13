"""
GhostTrace — Application Logger
Centralised logging with file + console output.
"""

import logging
import os
from pathlib import Path
from datetime import datetime

LOG_DIR = Path(__file__).parent.parent / "data" / "logs"


def get_logger(name: str = "ghosttrace") -> logging.Logger:
    """
    Get a configured logger instance.
    Creates a console handler + daily rotating file handler.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured — return as-is

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    # Console handler (INFO+ only)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (DEBUG+)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / f"ghosttrace_{datetime.now().strftime('%Y%m%d')}.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception as e:
        logger.warning(f"Could not create log file: {e}")

    return logger


# ── Module-level convenience ──────────────────────────────────────────────────
log = get_logger("ghosttrace")

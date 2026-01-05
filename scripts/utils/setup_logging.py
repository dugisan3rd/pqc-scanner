#!/usr/bin/env python3

''' Logging setup using Loguru '''

# ---------- IMPORT PACKAGES ----------
from pathlib import Path
from loguru import logger

# ---------- SETUP LOGGING ----------
def setup_logging(ROOT: Path, LEVEL: str = "DEBUG") -> None:
    log_dir = ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(
        (log_dir / "app.log").resolve(),
        level=LEVEL,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        colorize=False,
        backtrace=True,
        diagnose=True,
        serialize=True,
    )
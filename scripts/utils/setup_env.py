#!/usr/bin/env python3

''' Setup environment variables from .env file '''

# ---------- IMPORT PACKAGES ----------
from pathlib import Path
from dotenv import load_dotenv
from loguru import logger

# ---------- LOAD ENV ----------
def load_env(root: Path, filename: str = ".env", required: bool = True) -> Path:
    env_path = (root / filename).resolve()

    if not env_path.exists():
        msg = f"{filename} file not found at {env_path}"
        if required:
            raise FileNotFoundError(msg)
        logger.warning(msg)
        return env_path

    load_dotenv(env_path, override=False)
    # logger.info(f"Loaded env from: {env_path}")
    return env_path

#!/usr/bin/env python3

''' Check python packages (requirements.txt) are installed '''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import sys
import subprocess
import os

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[2]

# ---------- INSTALL PACKAGES ----------
def install_packages(root: Path) -> Path:
    requirements_file = (root / os.getenv("PYTHON_REQUIREMENTS")).resolve()
    if not requirements_file.exists():
        raise FileNotFoundError(f"Requirements file not found at: {requirements_file}")
    cmd = [sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                str(requirements_file),
                "--upgrade"]
    
    try:
        # Execute command
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("Timed out after 1 hour") from e

    if output.returncode == 0:
        return requirements_file
    
    stderr = (output.stderr or "").lower()
    pep668 = any(
        s in stderr
        for s in (
            "externally managed environment",
            "this environment is externally managed",
            "externally-managed-environment",
            "pep 668",
        )
    )

    if pep668:
        retry_cmd = cmd + ["--break-system-packages"]
        try:
            output2 = subprocess.run(retry_cmd, capture_output=True, text=True, check=False, timeout=3600)
        except subprocess.TimeoutExpired as e:
            raise TimeoutError("Timed out after 1 hour") from e

        if output2.returncode == 0:
            return requirements_file
        raise RuntimeError(f"Failed to install packages ({output2.returncode}): {output2.stderr.strip()}")

    raise RuntimeError(f"Failed to install packages ({output.returncode}): {output.stderr.strip()}")

def main() -> None:
    try:
        # ---------- LOGGING ----------
        from loguru import logger
        from setup_logging import setup_logging
        setup_logging(ROOT, LEVEL="DEBUG")

        # ---------- READ ENV ----------
        from setup_env import load_env
        load_env(ROOT, ".env", required=True)

        requirements_file = install_packages(ROOT)
        if requirements_file:
            logger.success(f"Python packages installed or updated successfully from: '{requirements_file}'")
    except KeyboardInterrupt:
        logger.error("Package installation interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error installing packages: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
    
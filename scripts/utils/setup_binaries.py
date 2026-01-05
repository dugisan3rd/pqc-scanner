#!/usr/bin/env python3

''' Collect and display system information '''

# ---------- START IMPORT PACKAGES ----------
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import shutil

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[2]

def get_binary_path(os_version: str, root: Path, binary_name: str) -> Path:
    """Get the path to a binary, installing it if necessary on Linux."""
    
    # Determine platform and environment variable key
    os_lower = os_version.lower()
    if os_lower.startswith("windows"):
        env_key = f"WINDOWS_BIN_{binary_name.upper()}"
    elif os_lower.startswith("linux"):
        env_key = f"LINUX_BIN_{binary_name.upper()}"
    else:
        raise RuntimeError(f"Unsupported platform: {os_version}")

    # Resolve binary path from environment variable
    rel_path = os.getenv(env_key)
    if not rel_path:
        raise RuntimeError(f"Missing environment variable: {env_key} (set it in .env)")

    binary_path = (root / rel_path).resolve()
    
    # Install binary if missing (Linux only)
    if not binary_path.exists():
        if os_lower.startswith("linux") and binary_name.upper() in {"SYFT", "GRYPE"}:
            install_commands = {
                "SYFT": "curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin",
                "GRYPE": "curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin",
            }
            
            cmd = install_commands.get(binary_name.upper())
            if cmd:
                try:
                    subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=3600
                    )
                except subprocess.TimeoutExpired as e:
                    raise TimeoutError(f"{binary_name} installation timed out after 1 hour") from e
                except subprocess.CalledProcessError as e:
                    raise RuntimeError(f"Failed to install {binary_name}: {e.stderr}") from e
        elif os_lower.startswith("windows") and binary_name.upper().startswith('SEMGREP'):
            found = shutil.which("semgrep")
            if found:
                binary_path = Path(found).resolve()

        # Raise error if binary still doesn't exist after install attempt
        if not binary_path.exists():
            raise FileNotFoundError(f"{binary_name} binary not found at: {binary_path}")

    return binary_path

def main():
    try:
        # ---------- CHECK OS ----------
        from setup_os import system_info_simplified
        OS_VERSION = system_info_simplified()

        # ---------- LOGGING ----------
        from loguru import logger
        from setup_logging import setup_logging
        setup_logging(ROOT, LEVEL="DEBUG")

        # ---------- READ ENV ----------
        from setup_env import load_env
        load_env(ROOT, ".env", required=True)
            
        logger.info(f"OS Version: {OS_VERSION}")
        logger.info(f"SYFT: {get_binary_path(OS_VERSION, ROOT, "syft")}")
        logger.info(f"GRYPE: {get_binary_path(OS_VERSION, ROOT, "grype")}")
        logger.info(f"MINI-PQC-SCANNER: {get_binary_path(OS_VERSION, ROOT, "mini_pqc_scanner")}")
        logger.info(f"SEMGREP: {get_binary_path(OS_VERSION, ROOT, "semgrep")}")

    except KeyboardInterrupt:
        logger.error("Binary installation interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error installing binary: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
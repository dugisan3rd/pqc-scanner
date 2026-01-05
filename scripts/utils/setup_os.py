#!/usr/bin/env python3

''' Collect and display system information '''

# ---------- START IMPORT PACKAGES ----------
from __future__ import annotations
import platform
import struct
import sys
from pathlib import Path

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[2]

# ---------- SYSTEM FINGERPRINT (FULL) ----------
def system_info_full() -> dict[str, str | int | tuple]:
    u = platform.uname()
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "kernel_release": u.release,
        "kernel_version": u.version,
        "architecture": platform.machine(),
        "arch_bits": struct.calcsize("P") * 8,
        "processor": platform.processor() or u.processor,
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "python_build": platform.python_build(),
        "python_compiler": platform.python_compiler(),
        "platform_string": platform.platform(),
    }

# ---------- SYSTEM FINGERPRINT (SIMPLIFIED) ----------
def system_info_simplified() -> str:
    return f"{platform.system()} {platform.release()} ({platform.version()}) [{platform.machine()}]"


def main() -> int:
    try:
        # ---------- LOGGING ----------
        from loguru import logger
        from setup_logging import setup_logging
        setup_logging(ROOT, LEVEL="DEBUG")

        info = system_info_full()
        for k, v in info.items():
            logger.info(f"{k:15}: {v}")

        logger.info(f"{'Simplified':15}: {system_info_simplified()}")

        return 0
    
    except KeyboardInterrupt:
        logger.error("Package installation interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error installing packages: {e}")
        sys.exit(1)

if __name__ == "__main__":
    raise SystemExit(main())

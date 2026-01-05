#!/usr/bin/env python3

'''3. Run mini-pqc-scan'''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import subprocess
import sys
from loguru import logger

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[1]

# ---------- SCAN MINI-PQC ----------
def scan_minipqc(mini_pqc_bin: Path, timestamp: int, random_suffix: str) -> Path:
    mini_pqc_bin = Path(mini_pqc_bin).resolve()
    if not mini_pqc_bin.exists():
        raise FileNotFoundError(f"mini-pqc-scanner binary not found: {mini_pqc_bin}")

    out_dir = (ROOT / "output" / "raw").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    output_filename = (out_dir / f"3_mini_pqc_{timestamp}_{random_suffix}.json").resolve()

    # NOTE: Keep args as list; no shell redirection.
    # mini-pqc-scanner typically prints JSON to stdout when -json is used.
    cmd = [str(mini_pqc_bin), "all", "-json"]

    try:
        with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
            proc = subprocess.run(
                cmd,
                stdout=f,                 # write JSON directly to file
                stderr=subprocess.PIPE,   # keep stderr for troubleshooting
                text=True,
                check=False,
                timeout=3600,
            )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("Mini-PQC scan timed out after 1 hour") from e

    if proc.returncode != 0:
        # If it failed, remove partial output to avoid confusing downstream parsers
        try:
            if output_filename.exists():
                output_filename.unlink()
        except Exception:
            pass
        raise RuntimeError(f"Mini-PQC failed ({proc.returncode}): {proc.stderr.strip()}")

    # sanity check: avoid “success” with empty file
    if not output_filename.exists() or output_filename.stat().st_size == 0:
        raise RuntimeError(
            "Mini-PQC returned success but output file is empty. "
            "Check whether '-json' is the correct flag for your binary."
        )

    logger.success(f"Mini-PQC scan completed. Output saved to: '{output_filename}'")
    return output_filename

# ---------- MAIN ----------
def main() -> None:
    try:
        # ---------- LOGGING ----------
        from utils.setup_logging import setup_logging
        setup_logging(ROOT, LEVEL="DEBUG")

        # ---------- READ ENV ----------
        from utils.setup_env import load_env
        load_env(ROOT, ".env", required=True)

        # ---------- UTILITIES ----------
        from utils.setup_timestamp import get_timestamp, get_random_suffix
        TIMESTAMP = get_timestamp()
        RANDOM_SUFFIX = get_random_suffix(6)

        # ---------- CHECK PYTHON PACKAGES ----------
        from utils.setup_packages import install_packages
        check_python_pkg = install_packages(ROOT)

        # ---------- CHECK OS ----------
        from utils.setup_os import system_info_simplified
        OS_VERSION = system_info_simplified()

        # ---------- CHECK BINARIES ----------
        from utils.setup_binaries import get_binary_path
        MINIPQC_BIN = get_binary_path(OS_VERSION, ROOT, "mini_pqc_scanner")

        if check_python_pkg:
            logger.info(f"Python packages installed or updated successfully from: '{check_python_pkg}'")
            scan_minipqc(MINIPQC_BIN, TIMESTAMP, RANDOM_SUFFIX)
    except KeyboardInterrupt:
        logger.error("Mini-PQC scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error during Mini-PQC scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
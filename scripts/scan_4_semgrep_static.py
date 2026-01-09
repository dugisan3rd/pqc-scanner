#!/usr/bin/env python3

'''4. Run SEMGREP CBOM scan to check for PQS readiness'''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import subprocess
import argparse
import sys
from loguru import logger
import os 

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[1]

# ---------- SCAN SEMGREP CBOM ----------
def scan_semgrep_cbom(semgrep_bin: Path, target_path: str, timestamp: int, random_suffix: str) -> Path:
    # Validate target path
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    
    # Semgrep config
    SEMGREP_CONF = os.getenv("SEMGREP_CONF")
    if not SEMGREP_CONF:
        raise RuntimeError("Missing SEMGREP_CONF in .env (path/URL to semgrep ruleset)")
    elif Path(SEMGREP_CONF).exists():
        SEMGREP_CONF = str(Path(SEMGREP_CONF).resolve())

    # Prepare output directory and file
    (ROOT / "output" / "raw").mkdir(parents=True, exist_ok=True)
    output_filename = (ROOT / "output" / "raw" / f"4_semgrep_cbom_{timestamp}_{random_suffix}.json").resolve()

    # Build command
    cmd = [
        str(semgrep_bin),
        "--config",
        SEMGREP_CONF,
        "--scan-unknown-extensions",
        "--no-git-ignore",
        "--verbose",
        "--json-output",
        str(output_filename),
        str(target)
    ]
    try:
        # Execute command
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
            encoding="utf-8",     # <--- force UTF-8 decoding
            errors="replace"     # <--- never crash on odd bytes
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("Semgrep scan timed out after 1 hour") from e

    if output.returncode in (0, 1):
        logger.success(f"Semgrep scan completed successfully. Semgrep CBOM saved to: '{output_filename}'")
    else:
        raise RuntimeError(f"Semgrep failed ({output.returncode}): {output.stderr.strip()}")
    
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
        SEMGREP_BIN = get_binary_path(OS_VERSION, ROOT, "SEMGREP")

        parser = argparse.ArgumentParser(description="4. Run SEMGREP CBOM scan to check for PQS readiness",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog="""Examples:\n  - Linux: python3 %(prog)s --path "/var/www/html"\n  - Windows: python3 %(prog)s --path "C:\\inetpub\\wwwroot"
                                          """)
        parser.add_argument("--path", type=str, help="Target directory to scan", default="./testing/DVWA")
        args = parser.parse_args()
        if check_python_pkg:
            logger.info(f"Python packages installed or updated successfully from: '{check_python_pkg}'")
            scan_semgrep_cbom(SEMGREP_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)
    except KeyboardInterrupt:
        logger.error("Semgrep CBOM scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error during semgrep CBOM scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
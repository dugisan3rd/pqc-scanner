#!/usr/bin/env python3

'''1. Syft SBOM Scanner - Generates Software Bill of Materials (SBOM) using Syft.'''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import subprocess
import argparse
import sys
from loguru import logger

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[1]

# ---------- SCAN SYFT SBOM ----------
def scan_syft_sbom(syft_bin: Path, target_path: str, timestamp: int, random_suffix: str) -> Path:
    # Validate target path
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    # Prepare output directory and file
    (ROOT / "output" / "raw").mkdir(parents=True, exist_ok=True)
    output_filename = (ROOT / "output" / "raw" / f"1_syft_sbom_{timestamp}_{random_suffix}.json").resolve()

    # Build command
    cmd = [
        str(syft_bin),
        "scan",
        str(target),
        "--output",
        "syft-json",
        "--file",
        str(output_filename)
    ]
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
        raise TimeoutError("Syft scan timed out after 1 hour") from e

    if output.returncode == 0:
        logger.success(f"Syft scan completed successfully. SBOM saved to: '{output_filename}'")
    else:
        raise RuntimeError(f"Syft failed ({output.returncode}): {output.stderr.strip()}")
    
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
        SYFT_BIN = get_binary_path(OS_VERSION, ROOT, "SYFT")

        parser = argparse.ArgumentParser(description="1. Run Syft SBOM scan to generate Software Bill of Materials (SBOM)",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog="""Examples:\n  - Linux: python3 %(prog)s --path "/var/www/html"\n  - Windows: python3 %(prog)s --path "C:\\inetpub\\wwwroot"
                                          """)
        parser.add_argument("--path", type=str, help="Target directory to scan", default="./testing/DVWA")
        args = parser.parse_args()
        if check_python_pkg:
            logger.info(f"Python packages installed or updated successfully from: '{check_python_pkg}'")
            scan_syft_sbom(SYFT_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)
    except KeyboardInterrupt:
        logger.error("Syft SBOM scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error during Syft SBOM scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
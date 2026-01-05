#!/usr/bin/env python3

'''2. Run Grype on a Syft SBOM JSON to generate Vulnerability Assessment (VA)'''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import subprocess
import argparse
import sys
from loguru import logger

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[1]

# ---------- SCAN GRYPE VA ----------
def scan_grype_va(grype_bin: Path, syft_output: Path, timestamp: int, random_suffix: str) -> Path:
    # Validate target path
    target = Path(syft_output).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Syft output file does not exist: {target}")
    
    # Update grype database before scanning
    update_cmd = [str(grype_bin), "db", "update"]
    try:
        update_db = subprocess.run(
            update_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("Grype database update timed out after 1 hour") from e

    if update_db.returncode != 0:
        raise RuntimeError(f"Grype DB update failed ({update_db.returncode}): {update_db.stderr.strip()}")

    # Prepare output directory and file
    (ROOT / "output" / "raw").mkdir(parents=True, exist_ok=True)
    output_filename = (ROOT / "output" / "raw" / f"2_grype_va_{timestamp}_{random_suffix}.json").resolve()

    # Build command
    cmd = [
        str(grype_bin),
        str(target),
        "--output",
        "json",
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
        raise TimeoutError("Grype scan timed out after 1 hour") from e

    if output.returncode == 0:
        logger.success(f"Grype scan completed successfully. VA saved to: '{output_filename}'")
    else:
        raise RuntimeError(f"Grype failed ({output.returncode}): {output.stderr.strip()}")
    
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
        GRYPE_BIN = get_binary_path(OS_VERSION, ROOT, "GRYPE")

        parser = argparse.ArgumentParser(description="1. Run Grype on a Syft SBOM JSON to generate Vulnerability Assessment (VA)",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog="""Examples:\n  - python3 %(prog)s --path "./output/raw/1_syft_sbom.json"
                                          """)
        parser.add_argument("--path", type=str, help="Target SYFT (SBOM) JSON file", default="./output/raw/1_syft_sbom.json")
        args = parser.parse_args()
        if check_python_pkg:
            logger.info(f"Python packages installed or updated successfully from: '{check_python_pkg}'")
            scan_grype_va(GRYPE_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)
    except KeyboardInterrupt:
        logger.error("Grype VA scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error during Grype VA scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
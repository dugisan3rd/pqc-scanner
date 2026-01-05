#!/usr/bin/env python3

# ---------- IMPORT PACKAGES ----------
import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[0]

# ---------- LOGGING ----------
from loguru import logger
from scripts.utils.setup_logging import setup_logging
setup_logging(ROOT, LEVEL="DEBUG")

# ---------- READ ENV ----------
from scripts.utils.setup_env import load_env
load_env(ROOT, ".env", required=True)

# ---------- UTILITIES ----------
from scripts.utils.setup_timestamp import get_timestamp, get_random_suffix
TIMESTAMP = get_timestamp()
RANDOM_SUFFIX = get_random_suffix(6)

# ---------- CHECK PYTHON PACKAGES ----------
from scripts.utils.setup_packages import install_packages
check_python_pkg = install_packages(ROOT)

# ---------- CHECK OS ----------
from scripts.utils.setup_os import system_info_simplified
OS_VERSION = system_info_simplified()

# ---------- CHECK BINARIES ----------
from scripts.utils.setup_binaries import get_binary_path
SYFT_BIN = get_binary_path(OS_VERSION, ROOT, "SYFT")
GRYPE_BIN = get_binary_path(OS_VERSION, ROOT, "GRYPE")
MINIPQC_BIN = get_binary_path(OS_VERSION, ROOT, "mini_pqc_scanner")
SEMGREP_BIN = get_binary_path(OS_VERSION, ROOT, "SEMGREP")

# ---------- IMPORT SYFT SBOM ----------
from scripts.scan_1_syft_sbom import scan_syft_sbom

# ---------- IMPORT GRYPE VA ----------
from scripts.scan_2_grype_va import scan_grype_va

# ---------- IMPORT MINI_PQC_SCAN ----------
from scripts.scan_3_mini_pqc import scan_minipqc

# ---------- IMPORT SEMGREP ----------
from scripts.scan_4_semgrep_static import scan_semgrep_cbom

def main() -> int:
    try:
        parser = argparse.ArgumentParser(description="PQC-Scanner: Review and analyze software components for potential quantum computing vulnerabilities.",
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                          epilog="""Examples:\n  - Linux: python3 %(prog)s --path "/var/www/html"\n  - Windows: python3 %(prog)s --path "C:\\inetpub\\wwwroot"
                                          """)
        parser.add_argument("--path", type=str, help="Target directory to scan", default="./testing/DVWA")
        args = parser.parse_args()
        if check_python_pkg:
            logger.info(f"Python packages installed or updated successfully from: '{check_python_pkg}'")
            # 1. SBOM generation using Syft
            SBOM_JSON = scan_syft_sbom(SYFT_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)

            # 2. SBOM vulnerability scanning using Grype
            GRYPE_JSON = scan_grype_va(GRYPE_BIN, SBOM_JSON, TIMESTAMP, RANDOM_SUFFIX)

            # 3. PQC scan using mini-pqc-scanner (if applicable)
            MINIPQC_JSON = scan_minipqc(MINIPQC_BIN, TIMESTAMP, RANDOM_SUFFIX)

            # 4. CBOM mapping using semgrep (code patterns)
            SEMGREP_JSON = scan_semgrep_cbom(SEMGREP_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)

    except KeyboardInterrupt:
        logger.error("Script interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Error during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
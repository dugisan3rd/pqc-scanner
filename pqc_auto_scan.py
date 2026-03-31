#!/usr/bin/env python3
"""
PQC Auto Server Scanner
=======================
Automates a full Post-Quantum Cryptography (PQC) readiness assessment
for a server, covering:

  Stage 1  - SBOM       : Software Bill of Materials (Syft)
  Stage 2  - VA         : Vulnerability Assessment (Grype)
  Stage 3  - PQC        : System-level PQC Readiness (mini-pqc-scanner)
  Stage 4  - CBOM       : Cryptographic Bill of Materials (Semgrep)
  Stage 5  - TLS        : Server TLS/SSL Cryptographic Analysis
  Stage 6  - SSH        : Server SSH Algorithm Analysis
  Stage 7  - CERT FILES : X.509 Certificate & Key File Scanner
  Stage 8  - CONFIG     : Server/App Config File Weak-Crypto Scanner
  Stage 9  - REPORT     : Excel Workbook (all stages)

Usage
-----
  # Full scan - local code + server TLS check:
  Linux   : python3 pqc_auto_scan.py --path /var/www/html --server example.com
  Windows : python3 pqc_auto_scan.py --path "C:\\inetpub\\wwwroot" --server example.com

  # Directory scan only (no TLS):
  python3 pqc_auto_scan.py --path /var/www/html

  # Skip individual stages:
  python3 pqc_auto_scan.py --path /var/www/html --skip-va --skip-pqc

  # Custom report filename:
  python3 pqc_auto_scan.py --path /var/www/html --server example.com --report-name my_audit.xlsx
"""

# ---------- STANDARD LIBRARY ----------
import argparse
import datetime
import json
import socket
import ssl
import sys
from pathlib import Path
from typing import Optional

# ---------- ROOT ----------
ROOT = Path(__file__).resolve().parent

# ---------- LOGGING ----------
from loguru import logger
from scripts.utils.setup_logging import setup_logging
setup_logging(ROOT, LEVEL="DEBUG")

# ---------- ENV ----------
from scripts.utils.setup_env import load_env
load_env(ROOT, ".env", required=True)

# ---------- UTILITIES ----------
from scripts.utils.setup_timestamp import get_timestamp, get_random_suffix
TIMESTAMP = get_timestamp()
RANDOM_SUFFIX = get_random_suffix(6)

# ---------- PYTHON PACKAGES ----------
from scripts.utils.setup_packages import install_packages
_PKG_STATUS = install_packages(ROOT)

# ---------- OS DETECTION ----------
from scripts.utils.setup_os import system_info_simplified
OS_VERSION = system_info_simplified()

# ---------- BINARY RESOLUTION ----------
from scripts.utils.setup_binaries import get_binary_path
SYFT_BIN    = get_binary_path(OS_VERSION, ROOT, "SYFT")
GRYPE_BIN   = get_binary_path(OS_VERSION, ROOT, "GRYPE")
MINIPQC_BIN = get_binary_path(OS_VERSION, ROOT, "mini_pqc_scanner")
SEMGREP_BIN = get_binary_path(OS_VERSION, ROOT, "SEMGREP")

# ---------- SCAN MODULES ----------
from scripts.scan_1_syft_sbom      import scan_syft_sbom
from scripts.scan_2_grype_va       import scan_grype_va
from scripts.scan_3_mini_pqc       import scan_minipqc
from scripts.scan_4_semgrep_static import scan_semgrep_cbom
from scripts.scan_5_ssh            import scan_ssh
from scripts.scan_6_certfiles      import scan_certfiles
from scripts.scan_7_configfiles    import scan_configfiles

# ---------- REPORT MODULE ----------
from scripts.excel2.pqc_export_full import main as _generate_excel_report


# =============================================================================
# STAGE 5 — TLS / SSL SERVER CRYPTOGRAPHIC ANALYSIS
# =============================================================================

# Substrings that flag a cipher as weak / deprecated
_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "RC2", "IDEA", "SEED",
)

# TLS protocol versions considered too old
_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Fragments that indicate a PQC or hybrid cipher is in use
_PQC_CIPHER_INDICATORS = (
    "KYBER", "ML-KEM", "ML-DSA", "DILITHIUM",
    "FALCON", "SPHINCS", "NTRU", "FRODO", "X25519KYBER",
)

# Common RSA/EC key sizes that are considered "quantum-weak"
# (RSA/DH < 3072 bits, EC < 384 bits)
_QUANTUM_WEAK_KEY_BITS = {
    "RSA": 3072,
    "EC": 384,
    "DH": 3072,
}


def _parse_cert_expiry(not_after: str) -> Optional[datetime.datetime]:
    """Parse a certificate not-after string into a datetime (UTC)."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(not_after, fmt)
        except ValueError:
            continue
    return None


def _cert_key_type(cert_der_info: dict) -> str:
    """
    Best-effort extraction of the public-key type from a DER cert dict.
    ssl.getpeercert(binary_form=False) does not expose this directly;
    we infer from the subject public key info embedded in the cipher name.
    """
    return "unknown"


def check_tls_server(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Connect to *hostname*:*port* over TLS and collect cryptographic metadata.

    Returns a dict with keys:
      hostname, port, tls_version, cipher_suite, certificate,
      pqc_indicators, weak_findings, recommendations, error (if any)
    """
    result: dict = {
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "certificate": {},
        "pqc_indicators": [],
        "weak_findings": [],
        "recommendations": [],
    }

    # ---- connect ----
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                tls_ver = tls_sock.version() or "unknown"
                cipher  = tls_sock.cipher()         # (name, proto, key_bits)
                cert    = tls_sock.getpeercert()    # decoded dict

        result["tls_version"] = tls_ver

        if cipher:
            result["cipher_suite"] = {
                "name":     cipher[0],
                "protocol": cipher[1],
                "key_bits": cipher[2],
            }

        if cert:
            not_after  = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")
            expiry     = _parse_cert_expiry(not_after)
            days_left  = (expiry - datetime.datetime.utcnow()).days if expiry else None
            subject    = dict(x[0] for x in cert.get("subject", []))
            issuer     = dict(x[0] for x in cert.get("issuer", []))
            sans       = cert.get("subjectAltName", [])

            result["certificate"] = {
                "common_name":        subject.get("commonName", ""),
                "organization":       subject.get("organizationName", ""),
                "issuer_org":         issuer.get("organizationName", ""),
                "issuer_cn":          issuer.get("commonName", ""),
                "not_before":         not_before,
                "not_after":          not_after,
                "days_until_expiry":  days_left,
                "san":                [v for _, v in sans],
                "serial_number":      cert.get("serialNumber", ""),
            }

    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out ({timeout}s) to {hostname}:{port}"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
    except OSError as exc:
        result["error"] = f"Network error: {exc}"

    if "error" in result:
        return result

    # ---- analyse TLS version ----
    tls_ver    = result["tls_version"]
    cipher_d   = result.get("cipher_suite") or {}
    cipher_name = (cipher_d.get("name") or "").upper()
    key_bits   = cipher_d.get("key_bits") or 0
    cert_d     = result.get("certificate") or {}
    days_left  = cert_d.get("days_until_expiry")

    if tls_ver in _WEAK_TLS_VERSIONS:
        result["weak_findings"].append({
            "type":           "Deprecated TLS Version",
            "severity":       "High",
            "detail":         f"{tls_ver} is deprecated and vulnerable to known attacks (POODLE, BEAST, etc.)",
            "recommendation": "Disable TLS < 1.2; prefer TLS 1.3",
        })
    elif tls_ver == "TLSv1.2":
        result["recommendations"].append(
            "TLS 1.2 in use — upgrade to TLS 1.3 for improved security and forward secrecy"
        )

    # ---- analyse cipher suite ----
    for marker in _WEAK_CIPHER_MARKERS:
        if marker in cipher_name:
            result["weak_findings"].append({
                "type":           "Weak Cipher Suite",
                "severity":       "High",
                "detail":         f"Cipher '{cipher_d.get('name')}' contains weak component '{marker}'",
                "recommendation": "Use ECDHE+AES-256-GCM-SHA384 or TLS_CHACHA20_POLY1305_SHA256",
            })
            break

    if 0 < key_bits < 128:
        result["weak_findings"].append({
            "type":           "Insufficient Symmetric Key Bits",
            "severity":       "High",
            "detail":         f"Effective key bits: {key_bits} (< 128)",
            "recommendation": "Use ≥ 128-bit effective key length (AES-128 minimum, AES-256 preferred)",
        })

    # ---- certificate expiry ----
    if days_left is not None:
        if days_left < 0:
            result["weak_findings"].append({
                "type":           "Expired Certificate",
                "severity":       "Critical",
                "detail":         f"Certificate expired {abs(days_left)} days ago",
                "recommendation": "Renew certificate immediately",
            })
        elif days_left < 7:
            result["weak_findings"].append({
                "type":           "Certificate Expiring Very Soon",
                "severity":       "Critical",
                "detail":         f"Certificate expires in {days_left} day(s)",
                "recommendation": "Renew certificate immediately",
            })
        elif days_left < 30:
            result["weak_findings"].append({
                "type":           "Certificate Expiring Soon",
                "severity":       "High",
                "detail":         f"Certificate expires in {days_left} days",
                "recommendation": "Schedule certificate renewal",
            })

    # ---- PQC indicator detection ----
    for indicator in _PQC_CIPHER_INDICATORS:
        if indicator in cipher_name:
            result["pqc_indicators"].append(indicator)

    pqc_ready = bool(result["pqc_indicators"])

    if pqc_ready:
        result["recommendations"].append(
            f"PQC indicator(s) detected in cipher: {', '.join(result['pqc_indicators'])}. "
            "Verify full hybrid KEM deployment per NIST SP 800-227."
        )
    else:
        result["recommendations"].append(
            "TLS is NOT PQC-ready. No hybrid PQC KEM detected. "
            "Migrate to X25519Kyber768 / ML-KEM-768 hybrid key exchange."
        )
        if tls_ver == "TLSv1.3":
            result["recommendations"].append(
                "TLS 1.3 is a good baseline — add ML-KEM hybrid KEM (e.g. OpenSSL 3.5 + OQS provider) "
                "to achieve full post-quantum security."
            )

    # ---- general PQC migration guidance ----
    result["recommendations"].append(
        "Ensure server certificate uses a PQC-safe algorithm (ML-DSA / Falcon) "
        "or at minimum RSA-3072 / ECDSA P-384 as an interim measure."
    )

    return result


def check_server_tls(hostname: str, ports: list[int]) -> list[dict]:
    """Run TLS checks across multiple ports and return a list of results."""
    checks = []
    for port in ports:
        logger.info(f"[TLS] Connecting to {hostname}:{port} ...")
        res = check_tls_server(hostname, port)
        if "error" in res:
            logger.warning(f"[TLS] {hostname}:{port} — {res['error']}")
        else:
            pqc_tag = "PQC-INDICATORS DETECTED" if res["pqc_indicators"] else "NOT PQC-READY"
            logger.success(
                f"[TLS] {hostname}:{port} — {res['tls_version']} | "
                f"{(res.get('cipher_suite') or {}).get('name', 'N/A')} | {pqc_tag}"
            )
        checks.append(res)
    return checks


def _save_tls_json(tls_checks: list[dict], timestamp: int, suffix: str) -> Path:
    out_dir = ROOT / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"5_tls_check_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"tls_checks": tls_checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[TLS] Results saved to: '{out_file}'")
    return out_file


# =============================================================================
# SUMMARY PRINTER
# =============================================================================

def _load_json(path: Optional[Path]) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def print_summary(
    sbom_json:      Optional[Path],
    grype_json:     Optional[Path],
    mini_pqc_json:  Optional[Path],
    cbom_json:      Optional[Path],
    tls_json:       Optional[Path],
    ssh_json:       Optional[Path],
    cert_json:      Optional[Path],
    config_json:    Optional[Path],
    excel_path:     Optional[Path],
) -> None:
    """Print a human-readable summary table of all scan results."""

    bar = "=" * 72
    logger.info(bar)
    logger.info("  PQC AUTO SCAN — RESULTS SUMMARY")
    logger.info(bar)

    # ---- SBOM ----
    sbom = _load_json(sbom_json)
    if sbom:
        artifacts = sbom.get("artifacts", [])
        src = (sbom.get("source") or {}).get("target", "")
        logger.info(f"[1] SBOM        | {len(artifacts):>5} components  |  source: {src}")
    else:
        logger.info("[1] SBOM        |  SKIPPED / NOT AVAILABLE")

    # ---- Vulnerability Assessment ----
    grype = _load_json(grype_json)
    if grype:
        matches = grype.get("matches", [])
        sev: dict[str, int] = {}
        for m in matches:
            s = (m.get("vulnerability", {}).get("severity") or "unknown").lower()
            sev[s] = sev.get(s, 0) + 1
        sev_str = " | ".join(f"{k.upper()}: {v}" for k, v in
                             sorted(sev.items(), key=lambda x: ["critical","high","medium","low","negligible","unknown"].index(x[0])
                                    if x[0] in ["critical","high","medium","low","negligible","unknown"] else 99))
        logger.info(f"[2] VA          | {len(matches):>5} vulns total  |  {sev_str}")
    else:
        logger.info("[2] VA          |  SKIPPED / NOT AVAILABLE")

    # ---- Mini-PQC system check ----
    mini = _load_json(mini_pqc_json)
    if mini:
        recs = mini.get("recommendations", [])
        logger.info(f"[3] PQC Sys     | {len(recs):>5} findings")
        for r in recs:
            sev_id = r.get("Severity", "?")
            sev_label = {0: "INFO", 1: "OK", 2: "WARN", 3: "HIGH"}.get(sev_id, str(sev_id))
            logger.info(f"      [{sev_label:4}]  {r.get('Text', '')}")
    else:
        logger.info("[3] PQC Sys     |  SKIPPED / NOT AVAILABLE")

    # ---- CBOM ----
    cbom = _load_json(cbom_json)
    if cbom:
        results = cbom.get("results", [])
        algo_counts: dict[str, int] = {}
        for r in results:
            meta = (r.get("extra") or {}).get("metadata") or {}
            algo = (
                meta.get("algorithm_used")
                or meta.get("algorithm_name")
                or meta.get("cbom", {}).get("algorithm_used")
                or "unknown"
            )
            algo_counts[algo] = algo_counts.get(algo, 0) + 1
        top = sorted(algo_counts.items(), key=lambda x: -x[1])[:8]
        top_str = ", ".join(f"{a}×{c}" for a, c in top)
        logger.info(f"[4] CBOM        | {len(results):>5} findings    |  top algorithms: {top_str}")
    else:
        logger.info("[4] CBOM        |  SKIPPED / NOT AVAILABLE")

    # ---- TLS ----
    tls_data = _load_json(tls_json)
    if tls_data:
        tls_checks = tls_data.get("tls_checks", [])
        for chk in tls_checks:
            host     = chk.get("hostname")
            port     = chk.get("port")
            tls_ver  = chk.get("tls_version", "?")
            c_name   = (chk.get("cipher_suite") or {}).get("name", "?")
            pqc_flag = "YES" if chk.get("pqc_indicators") else "NO"
            weak_cnt = len(chk.get("weak_findings", []))
            err      = chk.get("error", "")
            if err:
                logger.warning(f"[5] TLS         |  {host}:{port}  ERROR: {err}")
            else:
                logger.info(
                    f"[5] TLS         |  {host}:{port}  {tls_ver}  "
                    f"{c_name}  PQC-ready:{pqc_flag}  weak:{weak_cnt}"
                )
                for w in chk.get("weak_findings", []):
                    logger.warning(f"      [{w.get('severity','?'):8}]  {w.get('type')}: {w.get('detail')}")
                for rec in chk.get("recommendations", []):
                    logger.info(f"      [REC]      {rec}")
    else:
        logger.info("[5] TLS         |  SKIPPED / NOT AVAILABLE")

    # ---- SSH ----
    ssh_data = _load_json(ssh_json)
    if ssh_data:
        for chk in ssh_data.get("ssh_checks", []):
            host    = chk.get("hostname")
            port    = chk.get("port")
            banner  = chk.get("banner", "?")
            pqc_tag = "PQC-HYBRID" if chk.get("pqc_ready") else "NOT PQC-READY"
            weak_n  = len(chk.get("weak_findings", []))
            err     = chk.get("error", "")
            if err:
                logger.warning(f"[6] SSH         |  {host}:{port}  ERROR: {err}")
            else:
                logger.info(f"[6] SSH         |  {host}:{port}  {banner}  {pqc_tag}  weak_algos={weak_n}")
                for w in chk.get("weak_findings", []):
                    logger.warning(f"      [{w.get('severity','?'):6}]  {w.get('category')}: {w.get('algorithm')} — {w.get('detail')}")
    else:
        logger.info("[6] SSH         |  SKIPPED / NOT AVAILABLE")

    # ---- Cert files ----
    cert_data = _load_json(cert_json)
    if cert_data:
        summary = cert_data.get("summary", {})
        logger.info(
            f"[7] CERT FILES  | {summary.get('files_parsed',0):>5} cert/key files  |  "
            f"{summary.get('total_findings',0)} finding(s)"
        )
        for entry in cert_data.get("cert_file_scan", []):
            for f in entry.get("findings", []):
                logger.warning(f"      [{f.get('severity','?'):8}]  {entry['file']}: {f.get('type')} — {f.get('detail','')[:80]}")
    else:
        logger.info("[7] CERT FILES  |  SKIPPED / NOT AVAILABLE")

    # ---- Config files ----
    config_data = _load_json(config_json)
    if config_data:
        summary = config_data.get("summary", {})
        logger.info(
            f"[8] CONFIG      | {summary.get('files_scanned',0):>5} files scanned   |  "
            f"{summary.get('total_findings',0)} finding(s) in "
            f"{summary.get('files_with_findings',0)} file(s)"
        )
        for entry in config_data.get("config_scan", []):
            for f in entry.get("findings", []):
                logger.warning(
                    f"      [{f.get('severity','?'):8}]  {entry['file']}:{f.get('line')}  "
                    f"{f.get('finding_type')} — {f.get('matched_text','')}"
                )
    else:
        logger.info("[8] CONFIG      |  SKIPPED / NOT AVAILABLE")

    # ---- Report ----
    if excel_path and excel_path.exists():
        logger.success(f"[9] REPORT      |  {excel_path}")
    else:
        logger.info("[9] REPORT      |  SKIPPED / NOT AVAILABLE")

    logger.info(bar)


# =============================================================================
# OUTPUT FILE LOCATOR — pick the latest raw JSON if a stage was skipped
# =============================================================================

def _latest_raw(prefix: str) -> Optional[Path]:
    """Return the most recently modified file matching output/raw/<prefix>_*.json."""
    raw_dir = ROOT / "output" / "raw"
    candidates = sorted(
        raw_dir.glob(f"{prefix}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PQC Auto Server Scanner — Full PQC Readiness Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ---- targets ----
    parser.add_argument(
        "--path", type=str, default="./testing/DVWA",
        help="Target directory to scan (web root, source code, etc.)",
    )
    parser.add_argument(
        "--server", type=str, default=None,
        help="Server hostname or IP for TLS/SSL and SSH analysis (e.g. example.com)",
    )
    parser.add_argument(
        "--ports", type=str, default="443",
        help="Comma-separated HTTPS port(s) for TLS check (default: 443)",
    )
    parser.add_argument(
        "--ssh-ports", type=str, default="22",
        help="Comma-separated SSH port(s) to check (default: 22)",
    )

    # ---- stage toggles ----
    parser.add_argument("--skip-sbom",    action="store_true", help="Skip Stage 1 — SBOM generation")
    parser.add_argument("--skip-va",      action="store_true", help="Skip Stage 2 — Vulnerability Assessment")
    parser.add_argument("--skip-pqc",     action="store_true", help="Skip Stage 3 — PQC system readiness check")
    parser.add_argument("--skip-cbom",    action="store_true", help="Skip Stage 4 — CBOM/Semgrep scan")
    parser.add_argument("--skip-tls",     action="store_true", help="Skip Stage 5 — TLS/SSL server check")
    parser.add_argument("--skip-ssh",     action="store_true", help="Skip Stage 6 — SSH algorithm analysis")
    parser.add_argument("--skip-certs",   action="store_true", help="Skip Stage 7 — Certificate/key file scan")
    parser.add_argument("--skip-configs", action="store_true", help="Skip Stage 8 — Config file weak-crypto scan")
    parser.add_argument("--skip-report",  action="store_true", help="Skip Stage 9 — Excel report generation")

    # ---- report ----
    parser.add_argument(
        "--report-name", type=str, default=None,
        help="Custom filename for the Excel report (default: pqc_report_<timestamp>.xlsx)",
    )

    args = parser.parse_args()

    if not _PKG_STATUS:
        logger.error("Python package installation check failed. Aborting.")
        return 1

    # Parse port lists
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()] or [443]
    ssh_ports = [int(p.strip()) for p in args.ssh_ports.split(",") if p.strip().isdigit()] or [22]

    sbom_json:     Optional[Path] = None
    grype_json:    Optional[Path] = None
    mini_pqc_json: Optional[Path] = None
    cbom_json:     Optional[Path] = None
    tls_json:      Optional[Path] = None
    ssh_json:      Optional[Path] = None
    cert_json:     Optional[Path] = None
    config_json:   Optional[Path] = None
    excel_path:    Optional[Path] = None

    logger.info("=" * 72)
    logger.info("  PQC AUTO SERVER SCAN  —  Starting")
    logger.info(f"  Target path   : {args.path}")
    logger.info(f"  Target server : {args.server or '(none — TLS/SSH stages will be skipped)'}")
    logger.info(f"  TLS ports     : {ports}    SSH ports: {ssh_ports}")
    logger.info(f"  Run timestamp : {TIMESTAMP}  suffix: {RANDOM_SUFFIX}")
    logger.info("=" * 72)

    try:
        # ------------------------------------------------------------------
        # STAGE 1 — SBOM
        # ------------------------------------------------------------------
        if not args.skip_sbom:
            logger.info(">>> STAGE 1 — SBOM Generation (Syft)")
            sbom_json = scan_syft_sbom(SYFT_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)
        else:
            logger.warning(">>> STAGE 1 — Skipped (--skip-sbom)")
            sbom_json = _latest_raw("1_syft_sbom")
            if sbom_json:
                logger.info(f"    Using latest SBOM: {sbom_json}")

        # ------------------------------------------------------------------
        # STAGE 2 — Vulnerability Assessment
        # ------------------------------------------------------------------
        if not args.skip_va:
            if sbom_json and sbom_json.exists():
                logger.info(">>> STAGE 2 — Vulnerability Assessment (Grype)")
                grype_json = scan_grype_va(GRYPE_BIN, sbom_json, TIMESTAMP, RANDOM_SUFFIX)
            else:
                logger.warning(">>> STAGE 2 — Skipped (no SBOM available from Stage 1)")
        else:
            logger.warning(">>> STAGE 2 — Skipped (--skip-va)")
            grype_json = _latest_raw("2_grype_va")
            if grype_json:
                logger.info(f"    Using latest VA: {grype_json}")

        # ------------------------------------------------------------------
        # STAGE 3 — PQC System Readiness
        # ------------------------------------------------------------------
        if not args.skip_pqc:
            logger.info(">>> STAGE 3 — PQC System Readiness (mini-pqc-scanner)")
            mini_pqc_json = scan_minipqc(MINIPQC_BIN, TIMESTAMP, RANDOM_SUFFIX)
        else:
            logger.warning(">>> STAGE 3 — Skipped (--skip-pqc)")
            mini_pqc_json = _latest_raw("3_mini_pqc")
            if mini_pqc_json:
                logger.info(f"    Using latest PQC scan: {mini_pqc_json}")

        # ------------------------------------------------------------------
        # STAGE 4 — CBOM (Semgrep)
        # ------------------------------------------------------------------
        if not args.skip_cbom:
            logger.info(">>> STAGE 4 — CBOM Scan (Semgrep)")
            cbom_json = scan_semgrep_cbom(SEMGREP_BIN, args.path, TIMESTAMP, RANDOM_SUFFIX)
        else:
            logger.warning(">>> STAGE 4 — Skipped (--skip-cbom)")
            cbom_json = _latest_raw("4_semgrep_cbom")
            if cbom_json:
                logger.info(f"    Using latest CBOM: {cbom_json}")

        # ------------------------------------------------------------------
        # STAGE 5 — TLS / SSL Server Check
        # ------------------------------------------------------------------
        if not args.skip_tls and args.server:
            logger.info(f">>> STAGE 5 — TLS/SSL Analysis  ({args.server}  ports: {ports})")
            tls_checks = check_server_tls(args.server, ports)
            tls_json = _save_tls_json(tls_checks, TIMESTAMP, RANDOM_SUFFIX)
        elif args.skip_tls:
            logger.warning(">>> STAGE 5 — Skipped (--skip-tls)")
        else:
            logger.warning(
                ">>> STAGE 5 — Skipped  "
                "(no --server specified; add --server <hostname> to enable TLS analysis)"
            )

        # ------------------------------------------------------------------
        # STAGE 6 — SSH Algorithm Analysis
        # ------------------------------------------------------------------
        if not args.skip_ssh and args.server:
            logger.info(f">>> STAGE 6 — SSH Analysis  ({args.server}  ports: {ssh_ports})")
            ssh_json = scan_ssh(args.server, ssh_ports, TIMESTAMP, RANDOM_SUFFIX, ROOT)
        elif args.skip_ssh:
            logger.warning(">>> STAGE 6 — Skipped (--skip-ssh)")
            ssh_json = _latest_raw("6_ssh_check")
        else:
            logger.warning(
                ">>> STAGE 6 — Skipped  "
                "(no --server specified; add --server <hostname> to enable SSH analysis)"
            )

        # ------------------------------------------------------------------
        # STAGE 7 — Certificate & Key File Scan
        # ------------------------------------------------------------------
        if not args.skip_certs:
            logger.info(f">>> STAGE 7 — Certificate/Key File Scan  ({args.path})")
            cert_json = scan_certfiles(args.path, TIMESTAMP, RANDOM_SUFFIX, ROOT)
        else:
            logger.warning(">>> STAGE 7 — Skipped (--skip-certs)")
            cert_json = _latest_raw("7_cert_files")
            if cert_json:
                logger.info(f"    Using latest cert scan: {cert_json}")

        # ------------------------------------------------------------------
        # STAGE 8 — Config File Weak-Crypto Scan
        # ------------------------------------------------------------------
        if not args.skip_configs:
            logger.info(f">>> STAGE 8 — Config File Scan  ({args.path})")
            config_json = scan_configfiles(args.path, TIMESTAMP, RANDOM_SUFFIX, ROOT)
        else:
            logger.warning(">>> STAGE 8 — Skipped (--skip-configs)")
            config_json = _latest_raw("8_config_scan")
            if config_json:
                logger.info(f"    Using latest config scan: {config_json}")

        # ------------------------------------------------------------------
        # STAGE 9 — Excel Report
        # ------------------------------------------------------------------
        if not args.skip_report:
            if sbom_json and grype_json and cbom_json and mini_pqc_json:
                logger.info(">>> STAGE 9 — Excel Report Generation")
                report_filename = args.report_name or f"pqc_report_{TIMESTAMP}_{RANDOM_SUFFIX}.xlsx"
                excel_path = (ROOT / "output" / report_filename).resolve()
                (ROOT / "output").mkdir(parents=True, exist_ok=True)
                _generate_excel_report(
                    str(sbom_json),
                    str(grype_json),
                    str(cbom_json),
                    str(mini_pqc_json),
                    str(excel_path),
                    tls_path=str(tls_json)    if tls_json    else None,
                    ssh_path=str(ssh_json)    if ssh_json    else None,
                    cert_path=str(cert_json)  if cert_json   else None,
                    config_path=str(config_json) if config_json else None,
                )
                logger.success(f">>> STAGE 9 — Report saved: {excel_path}")
            else:
                missing = [
                    name for name, val in [
                        ("SBOM",  sbom_json),
                        ("VA",    grype_json),
                        ("CBOM",  cbom_json),
                        ("PQC",   mini_pqc_json),
                    ] if not val
                ]
                logger.warning(
                    f">>> STAGE 9 — Skipped (missing required outputs: {', '.join(missing)}). "
                    "Run all stages or use --skip-* flags to reuse existing files."
                )
        else:
            logger.warning(">>> STAGE 9 — Skipped (--skip-report)")

    except KeyboardInterrupt:
        logger.error("Scan interrupted by user (Ctrl+C).")
        return 130
    except Exception as exc:
        logger.exception(f"Fatal error during scan: {exc}")
        return 1

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------
    print_summary(sbom_json, grype_json, mini_pqc_json, cbom_json,
                  tls_json, ssh_json, cert_json, config_json, excel_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

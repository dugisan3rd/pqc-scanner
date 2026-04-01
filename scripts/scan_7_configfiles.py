#!/usr/bin/env python3
"""Configuration file cryptographic scanner — Stage 8.

Walks a directory tree, finds common server/application config files
(nginx, Apache, sshd, OpenSSL, HAProxy, etc.), and scans each for
weak or quantum-vulnerable cryptographic algorithm strings.
"""

import json
import re
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# File patterns to scan
# ---------------------------------------------------------------------------

_CONFIG_FILENAME_PATTERNS = {
    # exact names
    "nginx.conf", "httpd.conf", "apache2.conf", "apache.conf",
    "sshd_config", "ssh_config", "openssl.cnf", "openssl.conf",
    "haproxy.cfg", "stunnel.conf", "stunnel.cfg",
    "server.xml",       # Tomcat
    "web.config",       # IIS
    ".htaccess",
    "postgresql.conf",
    "my.cnf", "my.ini", "mysqld.cnf",
}

_CONFIG_GLOB_PATTERNS = [
    "*.conf", "*.cfg", "*.ini", "*.cnf",
    "*.properties", "*.xml", "*.yaml", "*.yml",
    "*.env", ".env", ".env.*",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
]

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", "site-packages", ".tox",
}

# Maximum file size to scan (bytes) — skip large binary/log files
_MAX_FILE_SIZE = 512 * 1024  # 512 KB

# ---------------------------------------------------------------------------
# Detection rules: (regex_pattern, finding_type, severity, detail, recommendation)
# ---------------------------------------------------------------------------

_RULES = [
    # ----- Weak TLS/SSL protocol versions -----
    (r"\bSSLv2\b",                  "Weak Protocol",    "Critical",
     "SSLv2 is critically broken (DROWN attack, RFC 6176)",
     "Remove SSLv2 entirely; use TLS 1.3 only"),
    (r"\bSSLv3\b",                  "Weak Protocol",    "Critical",
     "SSLv3 is critically broken (POODLE attack, RFC 7568)",
     "Remove SSLv3 entirely; use TLS 1.3 only"),
    (r"\bTLSv1(?:\.0)?\b(?![\._\d])", "Weak Protocol",  "High",
     "TLS 1.0 deprecated (RFC 8996); vulnerable to BEAST/POODLE",
     "Disable TLS 1.0; use TLS 1.2+ (prefer TLS 1.3)"),
    (r"\bTLSv1\.1\b",               "Weak Protocol",    "High",
     "TLS 1.1 deprecated (RFC 8996)",
     "Disable TLS 1.1; use TLS 1.2+ (prefer TLS 1.3)"),

    # ----- Weak cipher suites -----
    (r"\bRC4\b",                    "Weak Cipher",      "Critical",
     "RC4 stream cipher is cryptographically broken",
     "Remove all RC4 cipher suites"),
    (r"\bEXPORT\b",                 "Weak Cipher",      "Critical",
     "EXPORT cipher suites intentionally weakened (FREAK attack)",
     "Remove EXPORT cipher suites"),
    (r"\bNULL\b(?=.*cipher|.*suite|.*ssl|.*tls)", "Weak Cipher", "Critical",
     "NULL cipher suite provides no encryption",
     "Remove NULL cipher suites"),
    (r"\b(?:3DES|DES|TRIPLE[_-]DES)\b", "Weak Cipher", "High",
     "3DES/DES deprecated (Sweet32 attack, CVE-2016-2183)",
     "Remove 3DES/DES cipher suites; use AES-GCM"),
    (r"\bRC2\b",                    "Weak Cipher",      "High",
     "RC2 cipher is deprecated and weak",
     "Remove RC2 cipher suites"),
    (r"\bIDEA\b(?=.*cipher|.*suite|.*ssl|.*tls)", "Weak Cipher", "Medium",
     "IDEA cipher is deprecated",
     "Remove IDEA cipher suites"),
    (r"\bSEED\b(?=.*cipher|.*suite|.*ssl|.*tls)", "Weak Cipher", "Medium",
     "SEED cipher is deprecated",
     "Remove SEED cipher suites"),
    (r"\baNULL\b|ANON(?:ymous)?",   "Weak Auth",        "Critical",
     "Anonymous (no authentication) cipher suites allow MitM",
     "Remove anonymous/aNULL cipher suites"),
    (r"\bADH\b|\bAECDH\b",          "Weak Auth",        "Critical",
     "Anonymous DH/ECDH — no server authentication",
     "Remove ADH/AECDH cipher suites"),

    # ----- Weak hash / MAC -----
    (r"\bMD5\b",                    "Weak Hash",        "High",
     "MD5 is cryptographically broken (RFC 6151)",
     "Replace MD5 with SHA-256 or stronger"),
    (r"\bSHA1\b|\bSHA-1\b",         "Weak Hash",        "High",
     "SHA-1 deprecated (NIST 2030 deadline; SHAttered collision)",
     "Replace SHA-1 with SHA-256 or stronger"),

    # ----- Weak asymmetric / key exchange -----
    (r"\bDH[_ ]?(?:param|key|bits?)[^\d]*(?:512|768|1024)\b", "Weak Key",  "High",
     "DH key size < 2048 bits — vulnerable to Logjam (NIST minimum: 3072)",
     "Set DH parameter size to at least 3072 bits"),
    (r"ssl_dhparam.*(?:512|768|1024)",  "Weak DH Param", "High",
     "DH parameter file with insufficient key size",
     "Regenerate DH params: openssl dhparam -out dhparam.pem 4096"),
    (r"\bRSA(?:_KEY)?[_ ]?(?:KEY)?[_ ]?SIZE[^\d]*(?:512|768|1024)\b", "Weak Key", "High",
     "RSA key size < 2048 bits — does not meet NIST minimum",
     "Use RSA-3072 minimum (RSA-2048 acceptable short-term, not PQC-safe)"),

    # ----- Insecure verification -----
    (r"ssl_verify_peer\s*=\s*(?:no|false|0)\b", "Cert Verification Disabled", "Critical",
     "TLS peer certificate verification disabled",
     "Enable certificate verification (ssl_verify_peer = yes)"),
    (r"verify\s*=\s*0\b",           "Cert Verification Disabled", "High",
     "Certificate verification disabled",
     "Enable certificate verification"),
    (r"InsecureSkipVerify\s*:\s*true", "Cert Verification Disabled", "Critical",
     "Go TLS: InsecureSkipVerify=true disables certificate validation",
     "Remove InsecureSkipVerify or set to false"),
    (r"ssl\s*=\s*off\b|ssl_protocols\s*\w*\s*;?\s*$", "TLS Disabled", "High",
     "TLS/SSL appears to be disabled",
     "Enable TLS and configure strong cipher suites"),

    # ----- Hard-coded private keys / secrets -----
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key in Config", "Critical",
     "Private key material embedded directly in config file",
     "Remove private key from config; store in HSM or secure key store"),

    # ----- Weak password hashing config -----
    (r"\bmd5_password\b|\bpassword_encryption\s*=\s*md5\b", "Weak Password Hash", "High",
     "MD5 password hashing configured (e.g. PostgreSQL md5_password)",
     "Use scram-sha-256 (PostgreSQL) or bcrypt/Argon2id"),

    # ----- SSL/TLS compression -----
    (r"\bssl_compression\s+on\b",       "TLS Compression Enabled", "High",
     "SSL/TLS compression enabled — vulnerable to CRIME attack (CVE-2012-4929)",
     "Set ssl_compression off (nginx) or compile OpenSSL without zlib"),
    (r"\bSSLCompression\s+on\b",        "TLS Compression Enabled", "High",
     "Apache SSLCompression on — CRIME attack risk",
     "Set SSLCompression off in Apache config"),

    # ----- Weak elliptic curves -----
    (r"\b(?:secp112r1|secp128r1|secp160r1|secp192r1|secp224r1|prime192v1)\b", "Weak EC Curve", "High",
     "Elliptic curve < 256 bits is classically weak and easily broken",
     "Use P-384 (secp384r1) or X25519 as minimum; prefer X448 or ML-KEM for PQC"),
    (r"\b(?:secp256k1|prime256v1|P-256|secp256r1)\b", "Weak EC Curve", "Medium",
     "P-256 (secp256r1) is quantum-vulnerable to Shor's algorithm on a CRQC",
     "Migrate to P-384 or X25519 short-term; ML-KEM for PQC readiness"),

    # ----- SSH-specific weak settings -----
    (r"StrictHostKeyChecking\s+no\b",   "SSH Host Verification Disabled", "Critical",
     "StrictHostKeyChecking=no disables SSH host key verification — trivial MitM",
     "Set StrictHostKeyChecking yes or accept and pin host keys"),
    (r"UserKnownHostsFile\s+/dev/null\b", "SSH Host Verification Disabled", "Critical",
     "SSH known_hosts discarded — no host key pinning, MitM trivially possible",
     "Remove UserKnownHostsFile /dev/null; maintain a real known_hosts file"),
    (r"PermitRootLogin\s+(?:yes|without-password|prohibit-password)\b", "SSH Root Login", "High",
     "SSH root login permitted — increases blast radius of credential compromise",
     "Set PermitRootLogin no; use sudo for privilege escalation"),
    (r"PasswordAuthentication\s+yes\b", "SSH Password Auth", "Medium",
     "SSH password authentication enabled — vulnerable to brute-force and credential stuffing",
     "Set PasswordAuthentication no; enforce public-key authentication only"),
    (r"(?:Ciphers|ciphers)\s+[^\n]*(?:3des-cbc|arcfour|blowfish-cbc|cast128-cbc|aes128-cbc|aes192-cbc|aes256-cbc)\b",
     "Weak SSH Cipher", "High",
     "SSH config includes weak or non-AEAD cipher (CBC mode or broken stream cipher)",
     "Use aes256-gcm@openssh.com or chacha20-poly1305@openssh.com"),
    (r"(?:MACs|macs)\s+[^\n]*(?:hmac-md5|hmac-sha1(?!-etm)|hmac-ripemd)\b", "Weak SSH MAC", "High",
     "SSH config includes deprecated MAC algorithm (MD5 or SHA-1 based)",
     "Use hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com"),
    (r"(?:KexAlgorithms|kexalgorithms)\s+[^\n]*(?:diffie-hellman-group1|diffie-hellman-group14-sha1|ecdh-sha2-nistp256)\b",
     "Weak SSH KEX", "High",
     "SSH KexAlgorithms includes weak or quantum-vulnerable key exchange",
     "Add sntrup761x25519-sha512@openssh.com as first KEX; remove SHA-1 variants"),

    # ----- TLS version enforcement -----
    (r"ssl_protocols\s+(?!.*TLSv1\.3)[^\n;]+;", "TLS 1.3 Not Enforced", "Medium",
     "TLS 1.3 not included in ssl_protocols — missing PQC hybrid KEX support",
     "Add TLSv1.3 to ssl_protocols; it is required for ML-KEM hybrid ciphers"),
    (r"SSLProtocol\s+(?!.*TLSv1\.3|-all|\+TLSv1\.3)[^\n]+", "TLS 1.3 Not Enforced", "Medium",
     "Apache SSLProtocol does not include TLS 1.3",
     "Add +TLSv1.3 to SSLProtocol directive"),

    # ----- Minimum protocol version -----
    (r"MinProtocol\s*=\s*(?:TLSv1\.0|TLSv1\.1|TLSv1\.2)\b", "Weak Min Protocol", "Medium",
     "OpenSSL MinProtocol set below TLS 1.3 — PQC hybrid KEX requires TLS 1.3",
     "Set MinProtocol = TLSv1.3 in openssl.cnf for full PQC readiness"),
]

# Compile all patterns once
_COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), ftype, sev, detail, rec)
    for pattern, ftype, sev, detail, rec in _RULES
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_scannable(file_path: Path) -> bool:
    """Return True if this file is worth scanning."""
    name = file_path.name.lower()
    ext  = file_path.suffix.lower()

    if name in {p.lower() for p in _CONFIG_FILENAME_PATTERNS}:
        return True
    for pat in _CONFIG_GLOB_PATTERNS:
        if file_path.match(pat):
            return True
    return False


def _scan_file(file_path: Path, root_path: Path) -> Optional[dict]:
    """Scan a single file and return findings (or None if no findings)."""
    try:
        size = file_path.stat().st_size
    except OSError:
        return None

    if size > _MAX_FILE_SIZE or size == 0:
        return None

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    lines = text.splitlines()
    findings = []
    seen = set()   # deduplicate (pattern, line_number)

    for regex, ftype, severity, detail, recommendation in _COMPILED_RULES:
        for match in regex.finditer(text):
            # find line number
            line_no = text[:match.start()].count("\n") + 1
            key = (ftype, line_no)
            if key in seen:
                continue
            seen.add(key)

            # get context line
            context = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            # skip commented-out lines
            if context.lstrip().startswith(("#", "//", ";", "--")):
                continue

            findings.append({
                "line":           line_no,
                "finding_type":   ftype,
                "severity":       severity,
                "matched_text":   match.group(0),
                "context_line":   context[:200],
                "detail":         detail,
                "recommendation": recommendation,
            })

    if not findings:
        return None

    try:
        relative = str(file_path.relative_to(root_path))
    except ValueError:
        relative = str(file_path)

    return {
        "file":     relative,
        "findings": sorted(findings, key=lambda x: x["line"]),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_configfiles(
    target_path: str,
    timestamp,
    suffix: str,
    root: Path,
) -> Optional[Path]:
    from loguru import logger

    target = Path(target_path).resolve()
    if not target.exists():
        logger.error(f"[CONFIG] Target path does not exist: {target}")
        return None

    logger.info(f"[CONFIG] Scanning config files under: {target}")

    all_results = []
    scanned     = 0
    files_found = 0

    for file_path in target.rglob("*"):
        if any(part in _SKIP_DIRS for part in file_path.parts):
            continue
        if not file_path.is_file():
            continue
        if not _is_scannable(file_path):
            continue

        files_found += 1
        result = _scan_file(file_path, target)
        scanned += 1

        if result:
            n = len(result["findings"])
            logger.warning(f"[CONFIG] {result['file']} — {n} finding(s)")
            all_results.append(result)
        else:
            logger.debug(f"[CONFIG] {file_path.name} — no findings")

    total_findings = sum(len(r["findings"]) for r in all_results)
    logger.success(
        f"[CONFIG] Scan complete — {scanned} config files scanned, "
        f"{len(all_results)} files with findings, {total_findings} total finding(s)"
    )

    out_dir  = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"8_config_scan_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"config_scan": all_results, "summary": {
            "files_scanned": scanned,
            "files_with_findings": len(all_results),
            "total_findings": total_findings,
        }}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[CONFIG] Results saved to: '{out_file}'")
    return out_file

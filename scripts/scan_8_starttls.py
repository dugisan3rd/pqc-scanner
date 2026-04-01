#!/usr/bin/env python3
"""STARTTLS and implicit-TLS cryptographic analysis — Stage 8.

For each mail / directory / file-transfer service that supports STARTTLS
(SMTP, IMAP, POP3, LDAP, FTP) the scanner upgrades the plain-text
connection to TLS and then analyses the negotiated cipher suite, TLS
version, server certificate, and PQC readiness indicators, using the
same classification logic as the TLS stage in pqc_auto_scan.py.

Implicit-TLS ports (SMTPS/465, LDAPS/636, IMAPS/993, POP3S/995) are
also checked directly.
"""

import json
import os
import socket
import ssl
import struct
import time
import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Classification constants (mirrors pqc_auto_scan.py)
# ---------------------------------------------------------------------------

_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "RC2", "IDEA", "SEED",
)

_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_PQC_CIPHER_INDICATORS = (
    "KYBER", "ML-KEM", "ML-DSA", "DILITHIUM",
    "FALCON", "X25519KYBER",
)

# ---------------------------------------------------------------------------
# Service definitions
# ---------------------------------------------------------------------------

# (port, service_label, starttls_method)
# starttls_method: "smtp" | "imap" | "pop3" | "ldap" | "ftp" | "implicit"
_SERVICES = [
    (25,  "SMTP",   "smtp"),
    (587, "SMTP",   "smtp"),
    (143, "IMAP",   "imap"),
    (110, "POP3",   "pop3"),
    (389, "LDAP",   "ldap"),
    (21,  "FTP",    "ftp"),
    (465, "SMTPS",  "implicit"),
    (636, "LDAPS",  "implicit"),
    (993, "IMAPS",  "implicit"),
    (995, "POP3S",  "implicit"),
]

_CONNECT_TIMEOUT = 8  # seconds


# ---------------------------------------------------------------------------
# Low-level socket helpers
# ---------------------------------------------------------------------------

def _recv_line(sock: socket.socket, max_bytes: int = 4096) -> str:
    """Read bytes until \\n (or max_bytes) and return as a decoded string."""
    buf = b""
    while len(buf) < max_bytes:
        try:
            byte = sock.recv(1)
        except OSError:
            break
        if not byte:
            break
        buf += byte
        if buf.endswith(b"\n"):
            break
    return buf.decode("utf-8", errors="replace")


def _recv_until(sock: socket.socket, marker: bytes, max_bytes: int = 8192) -> bytes:
    """Read until *marker* appears in the buffer or *max_bytes* is reached."""
    buf = b""
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(256)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if marker in buf:
            break
    return buf


def _send(sock: socket.socket, data: str) -> None:
    sock.sendall(data.encode("utf-8"))


# ---------------------------------------------------------------------------
# STARTTLS negotiation per protocol
# ---------------------------------------------------------------------------

def _negotiate_smtp(sock: socket.socket) -> tuple[bool, bool]:
    """
    Exchange EHLO and STARTTLS for SMTP (ports 25 / 587).

    Returns (starttls_supported, starttls_upgraded).
    The caller then wraps the socket with TLS.
    """
    # Flush greeting
    greeting = _recv_until(sock, b"\n")
    plain_available = b"220" in greeting

    _send(sock, "EHLO pqc-scanner\r\n")
    ehlo_resp = _recv_until(sock, b"\n", max_bytes=4096)
    # Collect multi-line response (lines starting with "250-" continue)
    timeout_save = sock.gettimeout()
    sock.settimeout(2)
    try:
        while True:
            extra = _recv_until(sock, b"\n", max_bytes=512)
            if not extra:
                break
            ehlo_resp += extra
            if b"250 " in extra:   # final line has "250 " (space, not dash)
                break
    except (socket.timeout, OSError):
        pass
    sock.settimeout(timeout_save)

    starttls_supported = b"STARTTLS" in ehlo_resp.upper()
    if not starttls_supported:
        return False, False

    _send(sock, "STARTTLS\r\n")
    resp = _recv_until(sock, b"\n")
    return True, b"220" in resp


def _negotiate_imap(sock: socket.socket) -> tuple[bool, bool]:
    """
    Exchange CAPABILITY and STARTTLS for IMAP (port 143).

    Returns (starttls_supported, starttls_upgraded).
    """
    # Read banner
    _recv_until(sock, b"\n")

    _send(sock, "A001 CAPABILITY\r\n")
    cap_resp = _recv_until(sock, b"A001 OK", max_bytes=4096)
    # Absorb any trailing OK line
    sock.settimeout(2)
    try:
        _recv_until(sock, b"\n", max_bytes=256)
    except (socket.timeout, OSError):
        pass
    sock.settimeout(_CONNECT_TIMEOUT)

    starttls_supported = b"STARTTLS" in cap_resp.upper()
    if not starttls_supported:
        return False, False

    _send(sock, "A002 STARTTLS\r\n")
    resp = _recv_until(sock, b"\n")
    return True, b"OK" in resp.upper()


def _negotiate_pop3(sock: socket.socket) -> tuple[bool, bool]:
    """
    Exchange CAPA and STLS for POP3 (port 110).

    Returns (starttls_supported, starttls_upgraded).
    """
    # Read banner (+OK …)
    _recv_until(sock, b"\n")

    _send(sock, "CAPA\r\n")
    capa_resp = _recv_until(sock, b".", max_bytes=4096)

    starttls_supported = b"STLS" in capa_resp.upper()
    if not starttls_supported:
        return False, False

    _send(sock, "STLS\r\n")
    resp = _recv_until(sock, b"\n")
    return True, b"+OK" in resp


def _negotiate_ldap(sock: socket.socket) -> tuple[bool, bool]:
    """
    Send an LDAP ExtendedRequest (StartTLS OID 1.3.6.1.4.1.1466.20037).

    Returns (starttls_supported, starttls_upgraded).
    The OID is BER-encoded as an OCTET STRING inside an ExtendedRequest
    (application tag 23).
    """
    # OID bytes for 1.3.6.1.4.1.1466.20037
    oid = b"1.3.6.1.4.1.1466.20037"
    oid_len = len(oid)

    # Build BER:
    # ExtendedRequest [APPLICATION 23] SEQUENCE {
    #   requestName [0] LDAPOID
    # }
    # LDAPOID is OCTET STRING containing the dotted-decimal OID string
    req_name = bytes([0x80, oid_len]) + oid          # context [0]
    # LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp }
    ext_req_inner = req_name
    ext_req = bytes([0x77, len(ext_req_inner)]) + ext_req_inner   # [APPLICATION 23]
    msg_id  = bytes([0x02, 0x01, 0x01])               # messageID = 1
    ldap_msg_inner = msg_id + ext_req
    ldap_msg = bytes([0x30, len(ldap_msg_inner)]) + ldap_msg_inner  # SEQUENCE

    try:
        sock.sendall(ldap_msg)
        resp = _recv_until(sock, b"\x00", max_bytes=1024)
        # resultCode 0 = success (extended result)
        # We check for resultCode 0 (0x0a 0x01 0x00) inside the response
        starttls_ok = (b"\x0a\x01\x00" in resp)
        return True, starttls_ok
    except OSError:
        return False, False


def _negotiate_ftp(sock: socket.socket) -> tuple[bool, bool]:
    """
    Read FTP banner and send AUTH TLS.

    Returns (starttls_supported, starttls_upgraded).
    """
    _recv_until(sock, b"\n")   # 220 banner

    _send(sock, "AUTH TLS\r\n")
    resp = _recv_until(sock, b"\n")
    supported = b"234" in resp or b"AUTH TLS" in resp.upper()
    return supported, supported


# ---------------------------------------------------------------------------
# TLS wrapper + analysis (mirrors check_tls_server from pqc_auto_scan.py)
# ---------------------------------------------------------------------------

def _parse_cert_expiry(not_after: str) -> Optional[datetime.datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(not_after, fmt)
        except ValueError:
            continue
    return None


def _analyse_tls(raw_sock: socket.socket, hostname: str) -> dict:
    """
    Wrap *raw_sock* with TLS (check_hostname=False, CERT_NONE) and
    return a dict with tls_version, cipher_suite, certificate,
    pqc_indicators, weak_findings, and recommendations.
    """
    tls_info: dict = {
        "tls_version":   None,
        "cipher_suite":  None,
        "certificate":   {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
            tls_ver = tls_sock.version() or "unknown"
            cipher  = tls_sock.cipher()          # (name, protocol, key_bits)
            cert    = tls_sock.getpeercert()     # decoded dict (may be empty when CERT_NONE)

        tls_info["tls_version"] = tls_ver

        if cipher:
            tls_info["cipher_suite"] = {
                "name":     cipher[0],
                "key_bits": cipher[2],
            }

        if cert:
            not_after = cert.get("notAfter", "")
            expiry    = _parse_cert_expiry(not_after)
            days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
            subject   = dict(x[0] for x in cert.get("subject", []))
            issuer    = dict(x[0] for x in cert.get("issuer",  []))

            tls_info["certificate"] = {
                "common_name":       subject.get("commonName", ""),
                "issuer_cn":         issuer.get("commonName",  ""),
                "not_after":         not_after,
                "days_until_expiry": days_left,
            }

    except (ssl.SSLError, OSError) as exc:
        tls_info["tls_error"] = str(exc)
        return tls_info

    # ---- analyse TLS version ----
    tls_ver = tls_info["tls_version"] or ""
    if tls_ver in _WEAK_TLS_VERSIONS:
        tls_info["weak_findings"].append({
            "type":           "Weak TLS Version",
            "severity":       "High",
            "detail":         f"{tls_ver} is deprecated and vulnerable (POODLE, BEAST, etc.)",
            "recommendation": "Disable TLS < 1.2; prefer TLS 1.3",
        })
    elif tls_ver == "TLSv1.2":
        tls_info["recommendations"].append(
            "TLS 1.2 in use — upgrade to TLS 1.3 for improved security and forward secrecy"
        )

    # ---- analyse cipher ----
    cipher_d    = tls_info.get("cipher_suite") or {}
    cipher_name = (cipher_d.get("name") or "").upper()
    key_bits    = cipher_d.get("key_bits") or 0

    for marker in _WEAK_CIPHER_MARKERS:
        if marker in cipher_name:
            tls_info["weak_findings"].append({
                "type":           "Weak Cipher Suite",
                "severity":       "High",
                "detail":         f"Cipher '{cipher_d.get('name')}' contains weak component '{marker}'",
                "recommendation": "Use ECDHE+AES-256-GCM-SHA384 or TLS_CHACHA20_POLY1305_SHA256",
            })
            break

    if 0 < key_bits < 128:
        tls_info["weak_findings"].append({
            "type":           "Insufficient Symmetric Key Bits",
            "severity":       "High",
            "detail":         f"Effective key bits: {key_bits} (< 128)",
            "recommendation": "Use AES-128 minimum, AES-256 preferred",
        })

    # ---- cert expiry ----
    cert_d    = tls_info.get("certificate") or {}
    days_left = cert_d.get("days_until_expiry")
    if days_left is not None:
        if days_left < 0:
            tls_info["weak_findings"].append({
                "type":           "Expired Certificate",
                "severity":       "Critical",
                "detail":         f"Certificate expired {abs(days_left)} days ago",
                "recommendation": "Renew certificate immediately",
            })
        elif days_left < 7:
            tls_info["weak_findings"].append({
                "type":           "Certificate Expiring Very Soon",
                "severity":       "Critical",
                "detail":         f"Certificate expires in {days_left} day(s)",
                "recommendation": "Renew certificate immediately",
            })
        elif days_left < 30:
            tls_info["weak_findings"].append({
                "type":           "Certificate Expiring Soon",
                "severity":       "High",
                "detail":         f"Certificate expires in {days_left} days",
                "recommendation": "Schedule certificate renewal",
            })

    # ---- PQC indicators ----
    for indicator in _PQC_CIPHER_INDICATORS:
        if indicator in cipher_name:
            tls_info["pqc_indicators"].append(indicator)

    if tls_info["pqc_indicators"]:
        tls_info["recommendations"].append(
            f"PQC indicator(s) detected: {', '.join(tls_info['pqc_indicators'])}. "
            "Verify full hybrid KEM deployment per NIST SP 800-227."
        )
    else:
        tls_info["recommendations"].append(
            "TLS is NOT PQC-ready. Migrate to X25519Kyber768 / ML-KEM-768 hybrid key exchange."
        )

    return tls_info


# ---------------------------------------------------------------------------
# Per-service scanner
# ---------------------------------------------------------------------------

def _check_service(
    hostname: str,
    port: int,
    service: str,
    method: str,
) -> dict:
    """
    Attempt to connect, negotiate STARTTLS (or detect implicit TLS),
    then analyse the TLS session.
    """
    result: dict = {
        "hostname":          hostname,
        "port":              port,
        "service":           service,
        "plain_available":   False,
        "starttls_supported": False,
        "starttls_required":  False,
        "tls_version":       None,
        "cipher_suite":      None,
        "certificate":       {},
        "pqc_indicators":    [],
        "weak_findings":     [],
        "recommendations":   [],
        "error":             None,
    }

    try:
        raw_sock = socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT)
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out to {hostname}:{port}"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    raw_sock.settimeout(_CONNECT_TIMEOUT)

    try:
        if method == "implicit":
            # Direct TLS — no plain-text phase
            result["plain_available"]    = False
            result["starttls_supported"] = True   # implicit TLS is always "STARTTLS"
            tls_info = _analyse_tls(raw_sock, hostname)

        elif method == "smtp":
            result["plain_available"] = True
            supported, upgraded = _negotiate_smtp(raw_sock)
            result["starttls_supported"] = supported
            if not supported:
                result["weak_findings"].append({
                    "type":           "No STARTTLS",
                    "severity":       "High",
                    "detail":         f"SMTP on port {port} does not advertise STARTTLS — mail transmitted in plaintext",
                    "recommendation": "Enable STARTTLS on the SMTP server",
                })
                result["recommendations"].append(
                    "Enable STARTTLS to encrypt mail in transit and protect credentials."
                )
                raw_sock.close()
                return result
            if not upgraded:
                result["error"] = "STARTTLS handshake rejected by server"
                raw_sock.close()
                return result
            tls_info = _analyse_tls(raw_sock, hostname)

        elif method == "imap":
            result["plain_available"] = True
            supported, upgraded = _negotiate_imap(raw_sock)
            result["starttls_supported"] = supported
            if not supported:
                result["weak_findings"].append({
                    "type":           "No STARTTLS",
                    "severity":       "High",
                    "detail":         f"IMAP on port {port} does not advertise STARTTLS",
                    "recommendation": "Enable STARTTLS on the IMAP server",
                })
                raw_sock.close()
                return result
            if not upgraded:
                result["error"] = "IMAP STARTTLS handshake rejected"
                raw_sock.close()
                return result
            tls_info = _analyse_tls(raw_sock, hostname)

        elif method == "pop3":
            result["plain_available"] = True
            supported, upgraded = _negotiate_pop3(raw_sock)
            result["starttls_supported"] = supported
            if not supported:
                result["weak_findings"].append({
                    "type":           "No STARTTLS",
                    "severity":       "High",
                    "detail":         f"POP3 on port {port} does not support STLS",
                    "recommendation": "Enable STLS on the POP3 server",
                })
                raw_sock.close()
                return result
            if not upgraded:
                result["error"] = "POP3 STLS handshake rejected"
                raw_sock.close()
                return result
            tls_info = _analyse_tls(raw_sock, hostname)

        elif method == "ldap":
            result["plain_available"] = True
            supported, upgraded = _negotiate_ldap(raw_sock)
            result["starttls_supported"] = supported
            if not supported or not upgraded:
                result["starttls_supported"] = False
                result["weak_findings"].append({
                    "type":           "No LDAP StartTLS",
                    "severity":       "Critical",
                    "detail":         (
                        "LDAP on port 389 does not support StartTLS. "
                        "LDAP traffic (including bind credentials and directory data) "
                        "is transmitted in plaintext."
                    ),
                    "recommendation": (
                        "Enable StartTLS on the LDAP server, or migrate to LDAPS (port 636). "
                        "Enforce LDAP channel binding (CVE-2017-8563)."
                    ),
                })
                raw_sock.close()
                return result
            tls_info = _analyse_tls(raw_sock, hostname)

        elif method == "ftp":
            result["plain_available"] = True
            supported, upgraded = _negotiate_ftp(raw_sock)
            result["starttls_supported"] = supported
            if not supported or not upgraded:
                result["starttls_supported"] = False
                result["weak_findings"].append({
                    "type":           "No AUTH TLS",
                    "severity":       "High",
                    "detail":         f"FTP on port {port} does not support AUTH TLS — credentials transmitted in plaintext",
                    "recommendation": "Enable AUTH TLS (FTPS) or migrate to SFTP (SSH file transfer)",
                })
                raw_sock.close()
                return result
            tls_info = _analyse_tls(raw_sock, hostname)

        else:
            result["error"] = f"Unknown STARTTLS method: {method}"
            raw_sock.close()
            return result

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        try:
            raw_sock.close()
        except Exception:
            pass
        return result

    # Merge TLS analysis into result
    result["tls_version"]    = tls_info.get("tls_version")
    result["cipher_suite"]   = tls_info.get("cipher_suite")
    result["certificate"]    = tls_info.get("certificate", {})
    result["pqc_indicators"] = tls_info.get("pqc_indicators", [])
    result["weak_findings"]  += tls_info.get("weak_findings", [])
    result["recommendations"] += tls_info.get("recommendations", [])

    if tls_info.get("tls_error"):
        result["error"] = tls_info["tls_error"]

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_starttls(
    hostname: str,
    timestamp,
    suffix,
    root: Optional[Path] = None,
) -> Path:
    """
    Check STARTTLS / implicit-TLS on all standard mail, directory, and
    file-transfer ports, then save results to output/raw/8_starttls_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    logger.info(f"[STARTTLS] Starting STARTTLS/implicit-TLS scan on '{hostname}' ...")

    checks = []
    for port, service, method in _SERVICES:
        logger.info(f"[STARTTLS] Checking {service} on {hostname}:{port} (method={method}) ...")
        try:
            res = _check_service(hostname, port, service, method)
        except Exception as exc:
            res = {
                "hostname": hostname, "port": port, "service": service,
                "error": f"{type(exc).__name__}: {exc}",
            }

        if res.get("error"):
            logger.warning(f"[STARTTLS] {hostname}:{port} — {res['error']}")
        else:
            tls_ok   = bool(res.get("tls_version"))
            pqc_flag = "PQC-INDICATORS" if res.get("pqc_indicators") else "NOT PQC-READY"
            weak_n   = len(res.get("weak_findings", []))
            logger.success(
                f"[STARTTLS] {hostname}:{port}/{service} — "
                f"TLS={tls_ok} | {pqc_flag} | weak_findings={weak_n}"
            )

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"8_starttls_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"starttls_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[STARTTLS] Results saved to: '{out_file}'")
    return out_file

#!/usr/bin/env python3
"""RDP (Remote Desktop Protocol) cryptographic analysis — Stage 10.

Sends an RDP Connection Request (TPKT + COTP + RDP Negotiation Request),
parses the server's selected security protocol, then performs TLS analysis
(version, cipher, certificate) if TLS or NLA was selected.

Security findings follow the same severity model as the other scan stages.
All packet construction uses only the Python standard library.
"""

import json
import os
import socket
import ssl
import struct
import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# RDP protocol constants
# ---------------------------------------------------------------------------

# TPKT
_TPKT_VERSION = 3

# COTP PDU types
_COTP_CONNECTION_REQUEST = 0xE0
_COTP_CONNECTION_CONFIRM = 0xD0

# RDP Negotiation message types
_TYPE_RDP_NEG_REQ = 0x01
_TYPE_RDP_NEG_RSP = 0x02
_TYPE_RDP_NEG_FAILURE = 0x03

# Selected protocol flags (little-endian uint32 in the negotiation response)
_PROTOCOL_RDP        = 0x00000000   # Classic RC4 RDP
_PROTOCOL_SSL        = 0x00000001   # TLS only
_PROTOCOL_HYBRID     = 0x00000002   # CredSSP / NLA
_PROTOCOL_HYBRID_EX  = 0x00000003   # Extended CredSSP

_PROTOCOL_NAMES = {
    _PROTOCOL_RDP:       "PROTOCOL_RDP",
    _PROTOCOL_SSL:       "PROTOCOL_SSL",
    _PROTOCOL_HYBRID:    "PROTOCOL_HYBRID",
    _PROTOCOL_HYBRID_EX: "PROTOCOL_HYBRID_EX",
}

# TLS analysis constants (mirrors pqc_auto_scan.py)
_WEAK_CIPHER_MARKERS = (
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "RC2", "IDEA", "SEED",
)
_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_PQC_CIPHER_INDICATORS = (
    "KYBER", "ML-KEM", "ML-DSA", "DILITHIUM",
    "FALCON", "X25519KYBER",
)

_CONNECT_TIMEOUT = 8   # seconds


# ---------------------------------------------------------------------------
# TPKT / COTP / RDP packet builder
# ---------------------------------------------------------------------------

def _build_rdp_negotiation_request() -> bytes:
    """
    Build the 19-byte TPKT + COTP CR + RDP Negotiation Request packet.

    Structure:
      TPKT header  (4 bytes): version=3, reserved=0, length=19 (big-endian)
      COTP CR      (7 bytes): length=6, pdu_type=0xE0, dst-ref=0, src-ref=1, class=0
      RDP Neg Req  (8 bytes): type=1, flags=0, length=8 (LE), protocols=3 (LE)
    """
    rdp_neg_req = struct.pack(
        "<BBHII",          # little-endian for the RDP fields
        _TYPE_RDP_NEG_REQ, # type (uint8)
        0x00,              # flags (uint8)
        0x0008,            # length (uint16 LE) = 8
        0x00000003,        # requestedProtocols (uint32 LE) = SSL | HYBRID
    )
    # COTP Connection Request (7 bytes)
    # length field = byte count of COTP *excluding* the length byte itself = 6
    cotp_cr = struct.pack(
        "!BHHB",
        6,       # length (excludes itself)
        0xE000,  # pdu_type(0xE0) + reserved
        0x0001,  # src-ref
        0x00,    # class option
    )
    # Rebuild COTP correctly — fields are:
    # LI(1) | PDU-Type(1) | DST-REF(2) | SRC-REF(2) | Class(1)
    cotp_cr = struct.pack("!BBHHB", 6, _COTP_CONNECTION_REQUEST, 0x0000, 0x0001, 0x00)

    total_length = 4 + len(cotp_cr) + len(rdp_neg_req)   # 4 + 7 + 8 = 19
    tpkt_header = struct.pack("!BBH", _TPKT_VERSION, 0, total_length)

    return tpkt_header + cotp_cr + rdp_neg_req


# ---------------------------------------------------------------------------
# TPKT / COTP response parser
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading response")
        buf += chunk
    return buf


def _parse_rdp_response(sock: socket.socket) -> dict:
    """
    Read and parse the server's Connection Confirm (TPKT + COTP CC).

    Returns a dict with:
      cotp_pdu_type, selected_protocol (int or None), protocol_name (str),
      neg_response_found (bool), error (str or None)
    """
    info: dict = {
        "cotp_pdu_type":       None,
        "selected_protocol":   None,
        "protocol_name":       None,
        "neg_response_found":  False,
        "error":               None,
    }

    try:
        # Read TPKT header (4 bytes)
        tpkt = _recv_exactly(sock, 4)
        version  = tpkt[0]
        reserved = tpkt[1]
        total_length = struct.unpack("!H", tpkt[2:4])[0]

        if version != _TPKT_VERSION:
            info["error"] = f"Unexpected TPKT version: {version}"
            return info

        payload_length = total_length - 4
        if payload_length <= 0:
            info["error"] = "TPKT payload length is zero or negative"
            return info

        payload = _recv_exactly(sock, payload_length)

    except ConnectionError as exc:
        info["error"] = str(exc)
        return info
    except OSError as exc:
        info["error"] = f"Socket error reading TPKT response: {exc}"
        return info

    if len(payload) < 2:
        info["error"] = "TPKT payload too short for COTP"
        return info

    # COTP header: LI(1) | PDU-Type(1) | ...
    cotp_li       = payload[0]   # length indicator (length of COTP header - 1)
    cotp_pdu_type = payload[1]
    info["cotp_pdu_type"] = cotp_pdu_type

    if cotp_pdu_type != _COTP_CONNECTION_CONFIRM:
        info["error"] = f"COTP PDU type is 0x{cotp_pdu_type:02x}, expected 0xD0 (Connection Confirm)"
        return info

    # COTP user data starts after the COTP header (li + 1 bytes total COTP)
    cotp_header_len = cotp_li + 1   # LI counts bytes after itself, +1 for LI byte
    if len(payload) <= cotp_header_len:
        # No user data — valid but no RDP Negotiation Response present
        return info

    user_data = payload[cotp_header_len:]

    if len(user_data) < 8:
        # RDP Neg Response is 8 bytes; shorter means no negotiation response
        return info

    # RDP Negotiation Response
    neg_type   = user_data[0]
    neg_flags  = user_data[1]
    neg_length = struct.unpack("<H", user_data[2:4])[0]  # little-endian

    if neg_type == _TYPE_RDP_NEG_RSP and neg_length == 8 and len(user_data) >= 8:
        selected_protocol = struct.unpack("<I", user_data[4:8])[0]   # little-endian
        info["neg_response_found"] = True
        info["selected_protocol"]  = selected_protocol
        info["protocol_name"]      = _PROTOCOL_NAMES.get(selected_protocol, f"UNKNOWN(0x{selected_protocol:08x})")

    elif neg_type == _TYPE_RDP_NEG_FAILURE and len(user_data) >= 8:
        failure_code = struct.unpack("<I", user_data[4:8])[0]
        info["error"] = f"RDP Negotiation Failure: code 0x{failure_code:08x}"

    return info


# ---------------------------------------------------------------------------
# TLS analysis (mirrors check_tls_server from pqc_auto_scan.py)
# ---------------------------------------------------------------------------

def _parse_cert_expiry(not_after: str) -> Optional[datetime.datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(not_after, fmt)
        except ValueError:
            continue
    return None


def _analyse_tls(hostname: str, port: int) -> dict:
    """
    Open a *new* TLS connection to hostname:port (bypassing certificate
    verification) and return a dict with tls_version, cipher_suite,
    certificate, pqc_indicators, weak_findings, recommendations, and
    optionally tls_error.
    """
    tls_info: dict = {
        "tls_version":     None,
        "cipher_suite":    None,
        "certificate":     {},
        "pqc_indicators":  [],
        "weak_findings":   [],
        "recommendations": [],
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                tls_ver = tls_sock.version() or "unknown"
                cipher  = tls_sock.cipher()      # (name, proto, key_bits)
                cert    = tls_sock.getpeercert()  # decoded dict

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

    # ---- TLS version ----
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

    # ---- Cipher ----
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

    # ---- Cert expiry ----
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

    tls_info["recommendations"].append(
        "Ensure server certificate uses ML-DSA / Falcon, or at minimum RSA-3072 / ECDSA P-384."
    )

    return tls_info


# ---------------------------------------------------------------------------
# Per-port checker
# ---------------------------------------------------------------------------

def _check_rdp_port(hostname: str, port: int) -> dict:
    """
    Send RDP negotiation request to *hostname*:*port* and analyse security.
    """
    result: dict = {
        "hostname":             hostname,
        "port":                 port,
        "responding":           False,
        "security_protocol":    None,
        "nla_enabled":          False,
        "classic_rdp_security": False,
        "tls_version":          None,
        "cipher_suite":         None,
        "certificate":          {},
        "pqc_ready":            False,
        "weak_findings":        [],
        "recommendations":      [],
        "error":                None,
    }

    # ------------------------------------------------------------------
    # Step 1 — Send RDP Connection Request
    # ------------------------------------------------------------------
    try:
        sock = socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT)
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out to {hostname}:{port}"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    try:
        sock.settimeout(_CONNECT_TIMEOUT)
        request_packet = _build_rdp_negotiation_request()
        sock.sendall(request_packet)

        # Step 2 — Parse response
        rdp_resp = _parse_rdp_response(sock)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        sock.close()
        return result
    finally:
        sock.close()

    if rdp_resp.get("error"):
        result["error"] = rdp_resp["error"]
        # Still mark as responding if COTP was received (even partial)
        if rdp_resp.get("cotp_pdu_type") is not None:
            result["responding"] = True
        return result

    result["responding"] = True

    if not rdp_resp.get("neg_response_found"):
        result["error"] = "RDP Negotiation Response not found in server reply"
        return result

    selected_protocol = rdp_resp["selected_protocol"]
    result["security_protocol"] = rdp_resp["protocol_name"]

    # ------------------------------------------------------------------
    # Step 3 — Classify security protocol
    # ------------------------------------------------------------------

    if selected_protocol == _PROTOCOL_RDP:
        # Classic RC4-based RDP — no TLS
        result["classic_rdp_security"] = True
        result["nla_enabled"]          = False
        result["weak_findings"].append({
            "type":           "Classic RDP Security",
            "severity":       "Critical",
            "detail":         (
                "Server selected PROTOCOL_RDP (classic RC4 encryption). "
                "No TLS, no certificate authentication, no forward secrecy. "
                "Vulnerable to man-in-the-middle and credential interception attacks."
            ),
            "recommendation": (
                "Enable Network Level Authentication (NLA / CredSSP) and TLS. "
                "Set 'Security Layer' to TLS or Negotiate in Group Policy "
                "(Computer Configuration → Administrative Templates → Windows Components → "
                "Remote Desktop Services → RDP Security Layer)."
            ),
        })
        result["recommendations"].append(
            "Disable classic RDP security immediately. Enforce TLS 1.2+ and NLA."
        )
        return result

    # TLS or NLA/CredSSP selected
    nla_selected = selected_protocol in (_PROTOCOL_HYBRID, _PROTOCOL_HYBRID_EX)
    result["nla_enabled"] = nla_selected

    if nla_selected:
        result["weak_findings"].append({
            "type":           "Quantum-Vulnerable Authentication",
            "severity":       "Medium",
            "detail":         (
                "NLA / CredSSP uses NTLM or Kerberos for pre-authentication. "
                "Both are broken by Shor's algorithm on a CRQC "
                "(Kerberos uses RSA/ECDH; NTLM uses MD4/HMAC-MD5)."
            ),
            "recommendation": (
                "Plan migration to PQC-safe authentication (e.g. certificate-based auth "
                "with ML-DSA, or FIDO2/WebAuthn with PQC keys). "
                "Interim: enforce Kerberos with AES-256 and disable NTLM where possible."
            ),
        })

    # ------------------------------------------------------------------
    # Step 4 — TLS analysis (new connection, since first was plain-text)
    # ------------------------------------------------------------------
    tls_info = _analyse_tls(hostname, port)

    result["tls_version"]    = tls_info.get("tls_version")
    result["cipher_suite"]   = tls_info.get("cipher_suite")
    result["certificate"]    = tls_info.get("certificate", {})
    result["pqc_ready"]      = bool(tls_info.get("pqc_indicators"))
    result["weak_findings"]  += tls_info.get("weak_findings", [])
    result["recommendations"] += tls_info.get("recommendations", [])

    if tls_info.get("tls_error"):
        # TLS analysis failed (e.g. the second connect was refused after the negotiation
        # probe; note this but do not overwrite the protocol-level findings)
        result["recommendations"].insert(
            0,
            f"TLS handshake analysis failed: {tls_info['tls_error']} — "
            "inspect manually with 'openssl s_client -connect {hostname}:{port}'"
        )

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_rdp(
    hostname: str,
    timestamp,
    suffix,
    ports: Optional[list] = None,
    root: Optional[Path] = None,
) -> Path:
    """
    Probe RDP security on the given ports and save results to
    output/raw/10_rdp_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    if ports is None:
        ports = [3389]

    logger.info(f"[RDP] Starting RDP scan on '{hostname}' ports {ports} ...")

    checks = []
    for port in ports:
        logger.info(f"[RDP] Checking {hostname}:{port} ...")
        try:
            res = _check_rdp_port(hostname, port)
        except Exception as exc:
            res = {
                "hostname":    hostname,
                "port":        port,
                "responding":  False,
                "error":       f"{type(exc).__name__}: {exc}",
            }

        if res.get("error") and not res.get("responding"):
            logger.warning(f"[RDP] {hostname}:{port} — {res['error']}")
        elif res.get("classic_rdp_security"):
            logger.warning(
                f"[RDP] {hostname}:{port} — Classic RC4 RDP (CRITICAL) | "
                f"weak_findings={len(res.get('weak_findings', []))}"
            )
        elif res.get("responding"):
            proto    = res.get("security_protocol", "?")
            pqc_flag = "PQC-READY" if res.get("pqc_ready") else "NOT PQC-READY"
            weak_n   = len(res.get("weak_findings", []))
            nla      = "NLA=yes" if res.get("nla_enabled") else "NLA=no"
            logger.success(
                f"[RDP] {hostname}:{port} — {proto} | {nla} | "
                f"{pqc_flag} | weak_findings={weak_n}"
            )
        else:
            logger.info(f"[RDP] {hostname}:{port} — not responding")

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"10_rdp_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"rdp_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[RDP] Results saved to: '{out_file}'")
    return out_file

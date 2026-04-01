#!/usr/bin/env python3
"""Kerberos cryptographic analysis — Stage 14.

Sends a minimal Kerberos AS-REQ to a KDC and parses the KRB-ERROR response
to determine which encryption types (etypes) the KDC supports.  Both TCP
(with 4-byte length prefix) and UDP (without prefix) are attempted.

All ASN.1 / DER encoding is implemented manually using only the Python
standard library (socket, struct, random).

Etype security ratings:
  1  des-cbc-crc              → Critical
  3  des-cbc-md5              → Critical
  17 aes128-cts-hmac-sha1-96  → High      (SHA-1 HMAC)
  18 aes256-cts-hmac-sha1-96  → Medium    (SHA-1 HMAC, AES-256)
  23 rc4-hmac (NTLM)          → Critical
  24 rc4-hmac-exp             → Critical
"""

import json
import random
import socket
import struct
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CONNECT_TIMEOUT = 8    # seconds (TCP)
_UDP_TIMEOUT     = 3    # seconds (UDP)
_UDP_RETRIES     = 1    # retry once on UDP timeout

# Kerberos error codes we expect
_KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
_KDC_ERR_PREAUTH_REQUIRED    = 25

_KRB_ERROR_NAMES = {
    6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    25: "KDC_ERR_PREAUTH_REQUIRED",
}

# Etype table: id → (name, severity, quantum_vulnerable)
_ETYPES: dict[int, tuple[str, str, bool]] = {
    1:    ("des-cbc-crc",             "Critical", True),
    3:    ("des-cbc-md5",             "Critical", True),
    17:   ("aes128-cts-hmac-sha1-96", "High",     True),
    18:   ("aes256-cts-hmac-sha1-96", "Medium",   True),
    23:   ("rc4-hmac (NTLM)",         "Critical", True),
    -133: ("rc4-hmac-exp",            "Critical", True),
    24:   ("rc4-hmac-exp",            "Critical", True),
}

# Etypes we request in our AS-REQ (also used to scan response)
_REQUESTED_ETYPES = [18, 17, 23, 3, 1]


# ---------------------------------------------------------------------------
# Minimal DER / ASN.1 encoding helpers
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    """Encode an ASN.1 DER length."""
    if n < 0x80:
        return bytes([n])
    lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(lb)]) + lb


def _der_tlv(tag: int, data: bytes) -> bytes:
    """Encode a DER TLV (tag, length, value)."""
    return bytes([tag]) + _der_len(len(data)) + data


def _der_int(n: int) -> bytes:
    """Encode a DER INTEGER (tag 0x02)."""
    # Minimum number of bytes; always positive here
    byte_len = max(1, (n.bit_length() + 8) // 8)
    raw = n.to_bytes(byte_len, "big", signed=False)
    # Remove leading 0x00 bytes that are not needed for sign representation,
    # but keep at least one byte.
    raw = raw.lstrip(b"\x00") or b"\x00"
    # Re-add leading 0x00 if the high bit is set (to prevent misinterpretation
    # as a negative number in two's complement).
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_seq(*items: bytes) -> bytes:
    """Encode a DER SEQUENCE (tag 0x30)."""
    return _der_tlv(0x30, b"".join(items))


def _der_ctx(n: int, data: bytes) -> bytes:
    """Encode a DER context-specific constructed tag [n] EXPLICIT."""
    return _der_tlv(0xA0 | n, data)


def _der_genstr(s: str) -> bytes:
    """Encode a DER GeneralString (tag 0x1B)."""
    return _der_tlv(0x1B, s.encode("ascii"))


def _der_gtime(s: str) -> bytes:
    """Encode a DER GeneralizedTime (tag 0x18)."""
    return _der_tlv(0x18, s.encode("ascii"))


def _der_bitstr(data: bytes) -> bytes:
    """
    Encode a DER BIT STRING (tag 0x03).

    Prepends an 'unused bits' octet of 0x00 (all bits used).
    """
    return _der_tlv(0x03, bytes([0]) + data)


# ---------------------------------------------------------------------------
# KDC-REQ-BODY builder
# ---------------------------------------------------------------------------

def _build_kdc_req_body(realm: str) -> bytes:
    """
    Build the KDC-REQ-BODY ASN.1 structure.

    Uses principal "pqcscan" (non-existent, intentional) to provoke either
    KDC_ERR_C_PRINCIPAL_UNKNOWN or KDC_ERR_PREAUTH_REQUIRED, both of which
    carry etype information we can parse.
    """
    # kdc-options [0] KerberosFlags: forwardable | renewable | canonicalize
    flags = _der_ctx(0, _der_bitstr(b"\x40\x81\x00\x10"))

    # cname [1] PrincipalName: type=1 (NT-PRINCIPAL), value="pqcscan"
    cname = _der_ctx(1, _der_seq(
        _der_ctx(0, _der_int(1)),
        _der_ctx(1, _der_seq(_der_genstr("pqcscan"))),
    ))

    # realm [2] Realm
    realm_asn = _der_ctx(2, _der_genstr(realm))

    # sname [3] PrincipalName: type=2 (NT-SRV-INST), value=["krbtgt", realm]
    sname = _der_ctx(3, _der_seq(
        _der_ctx(0, _der_int(2)),
        _der_ctx(1, _der_seq(_der_genstr("krbtgt"), _der_genstr(realm))),
    ))

    # till [5] KerberosTime — far future
    till  = _der_ctx(5, _der_gtime("20370913024805Z"))

    # nonce [7] UInt32
    nonce = _der_ctx(7, _der_int(random.randint(1, 0x7FFFFFFF)))

    # etype [8] SEQUENCE OF Int32 — all etypes we want to probe
    etype_seq = _der_seq(*[_der_int(e) for e in _REQUESTED_ETYPES])
    etypes    = _der_ctx(8, etype_seq)

    return _der_seq(flags, cname, realm_asn, sname, till, nonce, etypes)


# ---------------------------------------------------------------------------
# AS-REQ builder
# ---------------------------------------------------------------------------

def _build_as_req(realm: str = "EXAMPLE.COM", tcp: bool = True) -> bytes:
    """
    Build a Kerberos AS-REQ.

    If *tcp* is True, prefix with a 4-byte big-endian message length (as
    required by RFC 4120 §7.2.2 for TCP transport).
    """
    # pvno [1] INTEGER 5
    pvno     = _der_ctx(1, _der_int(5))
    # msg-type [2] INTEGER 10 (KRB_AS_REQ)
    msg_type = _der_ctx(2, _der_int(10))
    # padata [3] SEQUENCE OF PA-DATA (empty — triggers PREAUTH_REQUIRED)
    padata   = _der_ctx(3, _der_seq())
    # req-body [4] KDC-REQ-BODY
    req_body = _der_ctx(4, _build_kdc_req_body(realm))

    # Wrap in an AS-REQ: APPLICATION [10] = 0x6A
    as_req_inner = _der_seq(pvno, msg_type, padata, req_body)
    as_req       = _der_tlv(0x6A, as_req_inner)

    if tcp:
        return struct.pack("!I", len(as_req)) + as_req
    return as_req


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _scan_for_etype_ints(data: bytes) -> list[int]:
    """
    Scan *data* for DER-encoded INTEGER values matching known etype IDs.

    This is a heuristic: we look for the byte patterns 02 01 XX (1-byte int)
    and 02 02 FF XX (2-byte int with high byte 0xFF for negative values like
    -133 = rc4-hmac-exp) that correspond to our target etype values.
    """
    found: set[int] = set()
    target_positive = {e for e in _REQUESTED_ETYPES if e > 0}
    # rc4-hmac-exp encoded as 2-byte negative: -133 = 0xFF7B
    target_negative = {e for e in _ETYPES if e < 0}

    for i in range(len(data) - 2):
        if data[i] == 0x02 and data[i + 1] == 0x01:
            val = data[i + 2]
            if val in target_positive:
                found.add(val)
        elif data[i] == 0x02 and data[i + 1] == 0x02 and i + 3 < len(data):
            # 2-byte signed integer: big-endian, might be negative
            raw = struct.unpack_from(">h", data, i + 2)[0]
            if raw in target_negative or raw in _ETYPES:
                found.add(raw)

    return sorted(found, reverse=True)


def _parse_krb_error_code(data: bytes) -> Optional[int]:
    """
    Extract the error-code INTEGER from a KRB-ERROR message.

    KRB-ERROR is APPLICATION [30] = 0x7E, containing a SEQUENCE.
    We search for the error-code field [6] EXPLICIT INTEGER.
    """
    # Locate APPLICATION [30] tag (0x7E) or fall back to scanning for [6] context tag
    # Context tag [6] EXPLICIT INTEGER: 0xA6 + length + 0x02 + 0x01 + error_code
    for i in range(len(data) - 4):
        if data[i] == 0xA6:
            # [6] EXPLICIT: should wrap a single INTEGER
            inner_start = i + 2   # skip tag + length byte (assume short form)
            if data[inner_start] == 0x02 and inner_start + 2 < len(data):
                int_len = data[inner_start + 1]
                if int_len == 1 and inner_start + 3 <= len(data):
                    return data[inner_start + 2]
    return None


def _parse_krb_response(raw_msg: bytes) -> dict:
    """
    Parse a raw Kerberos message (TCP payload, without length prefix).

    Returns a dict with: error_code, error_name, supported_etypes.
    """
    result: dict = {
        "error_code":      None,
        "error_name":      None,
        "supported_etypes": [],
    }

    if not raw_msg:
        return result

    error_code = _parse_krb_error_code(raw_msg)
    result["error_code"] = error_code
    result["error_name"] = _KRB_ERROR_NAMES.get(error_code, f"KRB_ERROR_{error_code}")

    # Both error codes 6 and 25 can contain etype data.
    # Scan the entire response for known etype integer values.
    if error_code in (_KDC_ERR_C_PRINCIPAL_UNKNOWN, _KDC_ERR_PREAUTH_REQUIRED, None):
        result["supported_etypes"] = _scan_for_etype_ints(raw_msg)

    return result


# ---------------------------------------------------------------------------
# TCP and UDP probes
# ---------------------------------------------------------------------------

def _probe_tcp(hostname: str, port: int, realm: str) -> dict:
    """Send AS-REQ over TCP and return parse result + protocol metadata."""
    result: dict = {
        "protocol":  "TCP",
        "responding": False,
        "raw_error":  None,
        "parse":      {},
    }
    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.sendall(_build_as_req(realm, tcp=True))

            # Read 4-byte length prefix
            raw_len = b""
            while len(raw_len) < 4:
                chunk = sock.recv(4 - len(raw_len))
                if not chunk:
                    raise ConnectionError("Connection closed before reading length prefix")
                raw_len += chunk

            msg_len = struct.unpack("!I", raw_len)[0]
            if msg_len == 0 or msg_len > 65535:
                result["raw_error"] = f"Implausible Kerberos message length: {msg_len}"
                return result

            msg_buf = b""
            while len(msg_buf) < msg_len:
                chunk = sock.recv(msg_len - len(msg_buf))
                if not chunk:
                    raise ConnectionError("Connection closed while reading Kerberos message")
                msg_buf += chunk

        result["responding"] = True
        result["parse"]      = _parse_krb_response(msg_buf)

    except ConnectionRefusedError:
        result["raw_error"] = f"Connection refused at {hostname}:{port}"
    except (socket.timeout, TimeoutError):
        result["raw_error"] = f"Connection timed out to {hostname}:{port}"
    except ConnectionError as exc:
        result["raw_error"] = str(exc)
    except OSError as exc:
        result["raw_error"] = f"Network error: {exc}"
    except Exception as exc:
        result["raw_error"] = f"{type(exc).__name__}: {exc}"

    return result


def _probe_udp(hostname: str, port: int, realm: str) -> dict:
    """Send AS-REQ over UDP (no length prefix) and return parse result."""
    result: dict = {
        "protocol":   "UDP",
        "responding": False,
        "raw_error":  None,
        "parse":      {},
    }
    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        result["raw_error"] = f"DNS resolution failed: {exc}"
        return result

    packet = _build_as_req(realm, tcp=False)

    for _ in range(_UDP_RETRIES + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(_UDP_TIMEOUT)
        try:
            sock.sendto(packet, (server_ip, port))
            data, _ = sock.recvfrom(65535)
            result["responding"] = True
            result["parse"]      = _parse_krb_response(data)
            return result
        except (socket.timeout, TimeoutError):
            pass   # retry
        except ConnectionRefusedError:
            result["raw_error"] = f"UDP port {port} closed (ICMP unreachable)"
            return result
        except OSError as exc:
            result["raw_error"] = f"Network error: {exc}"
            return result
        finally:
            sock.close()

    result["raw_error"] = f"No UDP response from {hostname}:{port} (timeout)"
    return result


# ---------------------------------------------------------------------------
# PQC analysis
# ---------------------------------------------------------------------------

def _analyse_kerberos(
    hostname:         str,
    port:             int,
    protocol:         str,
    responding:       bool,
    error_code:       Optional[int],
    error_name:       Optional[str],
    supported_etypes: list[int],
) -> dict:
    weak_findings: list = []
    recommendations: list = []

    etype_names = [_ETYPES[e][0] if e in _ETYPES else f"etype={e}" for e in supported_etypes]

    rc4_enabled = any(e in (23, 24, -133) for e in supported_etypes)
    des_enabled = any(e in (1, 3) for e in supported_etypes)

    if rc4_enabled:
        weak_findings.append({
            "type":           "RC4-HMAC (NTLM) Kerberos",
            "severity":       "Critical",
            "detail":         (
                "The KDC supports RC4-HMAC (etype 23 / rc4-hmac).  RC4 is cryptographically "
                "broken: the cipher is vulnerable to stream-cipher attacks and the "
                "HMAC-MD5 construction has no forward secrecy.  This etype underpins NTLM "
                "pass-the-hash and AS-REP roasting attacks."
            ),
            "recommendation": (
                "Disable RC4-HMAC in Group Policy: Computer Configuration → Windows Settings → "
                "Security Settings → Local Policies → Security Options → "
                "'Network security: Configure encryption types allowed for Kerberos' — "
                "uncheck DES and RC4, enable only AES-128-CTS-HMAC-SHA1-96 and "
                "AES-256-CTS-HMAC-SHA1-96.  Set msDS-SupportedEncryptionTypes on all "
                "accounts and computer objects."
            ),
        })

    if des_enabled:
        weak_findings.append({
            "type":           "DES Kerberos Encryption",
            "severity":       "Critical",
            "detail":         (
                "The KDC supports DES-based Kerberos encryption types (etype 1=des-cbc-crc "
                "and/or etype 3=des-cbc-md5).  DES has an effective 56-bit key size and "
                "is completely broken both classically (exhaustive search) and by quantum "
                "computers."
            ),
            "recommendation": (
                "Disable DES entirely in Group Policy Kerberos encryption settings. "
                "Remove legacy systems that require DES (Windows XP / Server 2003)."
            ),
        })

    if 17 in supported_etypes:
        weak_findings.append({
            "type":           "AES-128 Kerberos (SHA-1 HMAC)",
            "severity":       "High",
            "detail":         (
                "etype 17 (aes128-cts-hmac-sha1-96) is advertised.  The 128-bit AES key "
                "provides only 64-bit quantum security under Grover's algorithm.  "
                "The SHA-1 HMAC is deprecated (NIST SP 800-131A, 2030)."
            ),
            "recommendation": (
                "Prefer etype 18 (AES-256) over etype 17.  Plan migration to Kerberos "
                "PKINIT with ML-DSA / Falcon certificates once RFC support is available."
            ),
        })

    if 18 in supported_etypes:
        weak_findings.append({
            "type":           "AES-256 Kerberos (SHA-1 HMAC)",
            "severity":       "Medium",
            "detail":         (
                "etype 18 (aes256-cts-hmac-sha1-96) is advertised.  AES-256 provides "
                "128-bit quantum security under Grover's algorithm (acceptable for now), "
                "but the SHA-1 HMAC is deprecated and Kerberos key exchange remains "
                "vulnerable to Shor's algorithm (no PQC key encapsulation)."
            ),
            "recommendation": (
                "Use AES-256 as minimum etype.  Disable RC4 and DES.  Plan migration to "
                "Kerberos PKINIT with PQC certificates (ML-DSA / Falcon) per IETF "
                "draft-ietf-lamps-pq-composite-kem."
            ),
        })

    # General PKINIT vulnerability
    weak_findings.append({
        "type":           "Kerberos PKINIT — Quantum-Vulnerable Key Exchange",
        "severity":       "High",
        "detail":         (
            "Kerberos PKINIT (if used) relies on RSA or ECDH public-key operations for "
            "pre-authentication.  Both are broken by Shor's algorithm on a CRQC.  "
            "Even password-based Kerberos depends on symmetric keys derived from "
            "string2key functions that lack PQC forward secrecy."
        ),
        "recommendation": (
            "Monitor IETF progress on PQC Kerberos (draft-ietf-kitten-pkinit-alg-agility). "
            "Enforce MS-ATA/Windows Defender Credential Guard to limit lateral movement "
            "from credential theft until PQC Kerberos is standardised."
        ),
    })

    pqc_ready = False   # no current Kerberos deployment is PQC-ready

    recommendations.append(
        "Kerberos is NOT PQC-ready.  Disable RC4/DES etypes immediately.  Use AES-256 "
        "(etype 18) as the minimum.  Monitor IETF/NIST for standardised PQC Kerberos "
        "extensions and plan migration to hybrid ML-KEM key encapsulation for KDC "
        "communication when available."
    )

    return {
        "hostname":         hostname,
        "port":             port,
        "protocol":         protocol,
        "responding":       responding,
        "error_code":       error_code,
        "error_name":       error_name,
        "supported_etypes": supported_etypes,
        "etype_names":      etype_names,
        "rc4_enabled":      rc4_enabled,
        "des_enabled":      des_enabled,
        "pqc_ready":        pqc_ready,
        "weak_findings":    weak_findings,
        "recommendations":  recommendations,
        "error":            None,
    }


# ---------------------------------------------------------------------------
# Per-port checker
# ---------------------------------------------------------------------------

def _check_kerberos_port(hostname: str, port: int, realm: str) -> dict:
    """
    Try TCP first, then UDP, and return the first successful probe result.
    Falls back to UDP-only findings if TCP is refused/timed-out.
    """
    result: dict = {
        "hostname":         hostname,
        "port":             port,
        "protocol":         None,
        "responding":       False,
        "error_code":       None,
        "error_name":       None,
        "supported_etypes": [],
        "etype_names":      [],
        "rc4_enabled":      False,
        "des_enabled":      False,
        "pqc_ready":        False,
        "weak_findings":    [],
        "recommendations":  [],
        "error":            None,
    }

    tcp_probe = _probe_tcp(hostname, port, realm)
    if tcp_probe["responding"]:
        parse     = tcp_probe["parse"]
        analysis  = _analyse_kerberos(
            hostname, port, "TCP", True,
            parse.get("error_code"),
            parse.get("error_name"),
            parse.get("supported_etypes", []),
        )
        result.update(analysis)
        return result

    # TCP failed — try UDP
    udp_probe = _probe_udp(hostname, port, realm)
    if udp_probe["responding"]:
        parse    = udp_probe["parse"]
        analysis = _analyse_kerberos(
            hostname, port, "UDP", True,
            parse.get("error_code"),
            parse.get("error_name"),
            parse.get("supported_etypes", []),
        )
        result.update(analysis)
        return result

    # Both failed
    tcp_err = tcp_probe.get("raw_error") or "TCP timed out"
    udp_err = udp_probe.get("raw_error") or "UDP timed out"
    result["error"] = f"TCP: {tcp_err}; UDP: {udp_err}"
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_kerberos(
    hostname: str,
    timestamp,
    suffix,
    ports: Optional[list] = None,
    root: Optional[Path]  = None,
) -> Path:
    """
    Probe Kerberos KDC(s) on the given ports (TCP and UDP) and save results
    to output/raw/14_kerberos_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    if ports is None:
        ports = [88]

    # Derive a plausible realm from the hostname (best-effort)
    parts = hostname.upper().split(".")
    realm = ".".join(parts) if len(parts) >= 2 else "EXAMPLE.COM"

    logger.info(
        f"[KRB] Starting Kerberos scan on '{hostname}' ports {ports} "
        f"(realm guess: {realm}) ..."
    )

    checks = []
    for port in ports:
        logger.info(f"[KRB] Probing {hostname}:{port} ...")
        try:
            res = _check_kerberos_port(hostname, port, realm)
        except Exception as exc:
            res = {
                "hostname":   hostname,
                "port":       port,
                "responding": False,
                "error":      f"{type(exc).__name__}: {exc}",
            }

        if res.get("error") and not res.get("responding"):
            logger.warning(f"[KRB] {hostname}:{port} — {res['error']}")
        elif res.get("responding"):
            proto    = res.get("protocol", "?")
            etypes   = res.get("etype_names", [])
            pqc_flag = "PQC-READY" if res.get("pqc_ready") else "NOT PQC-READY"
            weak_n   = len(res.get("weak_findings", []))
            rc4_tag  = " | RC4=CRITICAL" if res.get("rc4_enabled") else ""
            des_tag  = " | DES=CRITICAL" if res.get("des_enabled") else ""
            logger.success(
                f"[KRB] {hostname}:{port}/{proto} — etypes={etypes}"
                f"{rc4_tag}{des_tag} | {pqc_flag} | weak_findings={weak_n}"
            )
        else:
            logger.info(f"[KRB] {hostname}:{port} — not responding")

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"14_kerberos_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"kerberos_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[KRB] Results saved to: '{out_file}'")
    return out_file

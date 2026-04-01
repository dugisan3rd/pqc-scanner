#!/usr/bin/env python3
"""SNMP cryptographic analysis — Stage 13.

Probes UDP port 161 for SNMPv1, SNMPv2c, and SNMPv3 using hand-crafted
BER-encoded packets.  All encoding helpers are implemented manually using
only the Python standard library.

Security findings are rated against PQC-readiness criteria:
- SNMPv1/v2c rely on community-string authentication with no encryption.
- SNMPv3 introduces optional authentication (MD5, SHA-1, SHA-256) and
  privacy (DES, AES-128), but lacks any quantum-safe key exchange.
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

_UDP_TIMEOUT = 3    # seconds per send attempt
_UDP_RETRIES = 1    # retry once on timeout

_SNMP_PORT   = 161
_SYSDESRC_OID = "1.3.6.1.2.1.1.1.0"   # sysDescr


# ---------------------------------------------------------------------------
# Minimal BER encoding helpers (stdlib only)
# ---------------------------------------------------------------------------

def _ber_length(n: int) -> bytes:
    """Encode an ASN.1/BER length field."""
    if n < 0x80:
        return bytes([n])
    enc = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc


def _ber_tlv(tag: int, value: bytes) -> bytes:
    """Encode a BER TLV (tag, length, value)."""
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_sequence(*items: bytes) -> bytes:
    """Encode a BER SEQUENCE (tag 0x30) from concatenated items."""
    content = b"".join(items)
    return _ber_tlv(0x30, content)


def _ber_int(n: int) -> bytes:
    """Encode a BER INTEGER (tag 0x02)."""
    if n == 0:
        return _ber_tlv(0x02, b"\x00")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big").lstrip(b"\x00") or b"\x00"
    return _ber_tlv(0x02, raw)


def _ber_octet_string(s) -> bytes:
    """Encode a BER OCTET STRING (tag 0x04)."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _ber_tlv(0x04, s)


def _ber_null() -> bytes:
    """Encode a BER NULL (tag 0x05, length 0)."""
    return b"\x05\x00"


def _ber_oid(oid_str: str) -> bytes:
    """
    Encode a BER OBJECT IDENTIFIER (tag 0x06).

    Example: '1.3.6.1.2.1.1.1.0'
    """
    parts = [int(x) for x in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid_str!r}")

    # First two components are combined: first * 40 + second
    first = parts[0] * 40 + parts[1]
    encoded: list[int] = []

    for component in [first] + parts[2:]:
        if component == 0:
            encoded.append(0)
        else:
            buf: list[int] = []
            p = component
            while p:
                buf.append(p & 0x7F)
                p >>= 7
            buf.reverse()
            for i, b in enumerate(buf):
                encoded.append(b | (0x80 if i < len(buf) - 1 else 0))

    return _ber_tlv(0x06, bytes(encoded))


# ---------------------------------------------------------------------------
# SNMPv1 / SNMPv2c packet builder
# ---------------------------------------------------------------------------

def _build_snmp_get(version: int, community: str, oid_str: str, request_id: int) -> bytes:
    """
    Build an SNMP GetRequest PDU.

    *version*: 0 = SNMPv1, 1 = SNMPv2c
    *community*: community string (e.g. "public")
    *oid_str*: dotted OID string
    *request_id*: unique integer request identifier
    """
    # VarBind: SEQUENCE { OID, NULL }
    varbind      = _ber_sequence(_ber_oid(oid_str), _ber_null())
    varbind_list = _ber_sequence(varbind)

    # GetRequest-PDU (tag 0xA0 = context class, constructed, [0])
    pdu = _ber_tlv(
        0xA0,
        _ber_int(request_id)   # request-id
        + _ber_int(0)          # error-status: noError
        + _ber_int(0)          # error-index: 0
        + varbind_list,
    )

    # SNMPv1/v2c message: SEQUENCE { version, community, pdu }
    return _ber_sequence(
        _ber_int(version),
        _ber_octet_string(community),
        pdu,
    )


# ---------------------------------------------------------------------------
# SNMPv3 discovery message builder
# ---------------------------------------------------------------------------

def _build_snmpv3_discovery() -> bytes:
    """
    Build a minimal SNMPv3 discovery (engine-ID-discovery) message.

    Sends an empty USM Security Parameters block with the reportable flag
    set.  A compliant SNMPv3 agent will respond with a Report-PDU that
    includes the snmpEngineID (enabling version detection).
    """
    msg_id   = random.randint(1, 0xFFFFFF)
    request_id = random.randint(1, 0xFFFFFF)

    # HeaderData SEQUENCE:
    #   msgID(int) | msgMaxSize(int) | msgFlags(octet) | msgSecurityModel(int)
    header_data = _ber_sequence(
        _ber_int(msg_id),
        _ber_int(65507),              # msgMaxSize
        _ber_octet_string(b"\x04"),   # msgFlags: reportable (bit 2 set)
        _ber_int(3),                  # msgSecurityModel: USM=3
    )

    # msgSecurityParameters: empty USM block (for discovery)
    # Minimal USM: SEQUENCE { contextEngineID, contextName, userName, ... } all empty
    usm_params = _ber_sequence(
        _ber_octet_string(b""),   # msgAuthoritativeEngineID
        _ber_int(0),              # msgAuthoritativeEngineBoots
        _ber_int(0),              # msgAuthoritativeEngineTime
        _ber_octet_string(b""),   # msgUserName
        _ber_octet_string(b""),   # msgAuthenticationParameters
        _ber_octet_string(b""),   # msgPrivacyParameters
    )
    security_params = _ber_octet_string(usm_params)

    # ScopedPDU: contextEngineID, contextName, GetRequest PDU (empty varbind)
    varbind_list = _ber_sequence()   # empty VarBindList
    pdu = _ber_tlv(
        0xA0,
        _ber_int(request_id)
        + _ber_int(0)
        + _ber_int(0)
        + varbind_list,
    )
    scoped_pdu = _ber_sequence(
        _ber_octet_string(b""),   # contextEngineID: empty for discovery
        _ber_octet_string(b""),   # contextName: empty
        pdu,
    )

    # SNMPv3 message: SEQUENCE { version=3, headerData, securityParams, scopedPDU }
    return _ber_sequence(
        _ber_int(3),
        header_data,
        security_params,
        scoped_pdu,
    )


# ---------------------------------------------------------------------------
# UDP send / receive helper
# ---------------------------------------------------------------------------

def _udp_send_recv(
    hostname: str,
    port: int,
    packet: bytes,
    timeout: float = _UDP_TIMEOUT,
    retries: int   = _UDP_RETRIES,
) -> Optional[bytes]:
    """Send *packet* via UDP and return the response, or None on failure."""
    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise OSError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server_ip, port))
            data, _ = sock.recvfrom(65535)
            return data
        except (socket.timeout, TimeoutError):
            pass   # retry
        except ConnectionRefusedError:
            return None   # ICMP port-unreachable
        except OSError:
            return None
        finally:
            sock.close()

    return None


# ---------------------------------------------------------------------------
# Response validators
# ---------------------------------------------------------------------------

def _is_valid_snmp_response(data: bytes) -> bool:
    """
    Very lightweight check: data must start with a BER SEQUENCE (0x30)
    and contain a valid-looking SNMP version integer.
    """
    if not data or data[0] != 0x30:
        return False
    # Skip outer SEQUENCE header and check for INTEGER (version)
    pos = 1
    # Skip length bytes
    if pos >= len(data):
        return False
    if data[pos] & 0x80:
        num_len_bytes = data[pos] & 0x7F
        pos += 1 + num_len_bytes
    else:
        pos += 1
    # Next should be INTEGER tag 0x02
    return pos < len(data) and data[pos] == 0x02


def _is_valid_snmpv3_response(data: bytes) -> bool:
    """
    Check that data looks like an SNMPv3 message:
    SEQUENCE → INTEGER version=3 (encoded as 0x02 0x01 0x03).
    """
    if not data or data[0] != 0x30:
        return False
    # Find the version integer after the outer SEQUENCE header
    pos = 1
    if pos >= len(data):
        return False
    if data[pos] & 0x80:
        num_len_bytes = data[pos] & 0x7F
        pos += 1 + num_len_bytes
    else:
        pos += 1
    # Expect: 02 01 03  (INTEGER, length=1, value=3)
    return (
        pos + 3 <= len(data)
        and data[pos]     == 0x02
        and data[pos + 1] == 0x01
        and data[pos + 2] == 0x03
    )


# ---------------------------------------------------------------------------
# PQC analysis
# ---------------------------------------------------------------------------

def _analyse_snmp(
    hostname:                str,
    port:                    int,
    v1_enabled:              bool,
    v2c_enabled:             bool,
    v3_enabled:              bool,
    public_community_responds: bool,
) -> dict:
    weak_findings: list = []
    recommendations: list = []

    if v1_enabled or v2c_enabled:
        versions = []
        if v1_enabled:
            versions.append("SNMPv1")
        if v2c_enabled:
            versions.append("SNMPv2c")

        weak_findings.append({
            "type":           "SNMPv1/v2c Enabled",
            "severity":       "Critical",
            "detail":         (
                f"{'/'.join(versions)} use cleartext community-string authentication "
                "with no encryption.  All SNMP traffic (including MIB data and community "
                "strings) is transmitted in plaintext, vulnerable to passive interception "
                "and MITM attacks.  Neither version provides any quantum resistance."
            ),
            "recommendation": (
                "Disable SNMPv1 and SNMPv2c.  Deploy SNMPv3 with authPriv security level, "
                "SHA-256 authentication (USM auth protocol = usmHMAC256SHA384AuthProtocol), "
                "and AES-128 or AES-256 privacy."
            ),
        })

    if public_community_responds:
        weak_findings.append({
            "type":           "Default Community String 'public' Accepted",
            "severity":       "Critical",
            "detail":         (
                "The SNMP community string 'public' is accepted, granting read access to the "
                "full MIB tree.  This is the factory default and is exploited routinely by "
                "network scanners and attackers for reconnaissance."
            ),
            "recommendation": (
                "Change all community strings to long random values.  Restrict SNMP access "
                "by source IP using ACLs.  Migrate to SNMPv3 user-based security."
            ),
        })

    if v3_enabled:
        # We cannot determine auth/priv protocol from a passive discovery probe
        # but we flag the generic quantum vulnerability of all current SNMPv3 options.
        weak_findings.append({
            "type":           "SNMPv3 Authentication — Quantum-Vulnerable",
            "severity":       "Medium",
            "detail":         (
                "SNMPv3 is enabled.  Current USM authentication protocols (MD5, SHA-1, "
                "SHA-256) and privacy protocols (DES, AES-128) provide no post-quantum "
                "security.  MD5 and DES are cryptographically broken classically."
            ),
            "recommendation": (
                "Configure SNMPv3 with the strongest available options: "
                "authProtocol=usmHMAC256SHA384AuthProtocol, privProtocol=usmAesCfb256Protocol. "
                "Monitor IETF drafts for PQC-capable SNMP security models."
            ),
        })
    elif not v1_enabled and not v2c_enabled:
        recommendations.append(
            "No SNMP version responded on this port.  If SNMP is required, deploy SNMPv3 "
            "with authPriv security level and strong USM parameters."
        )

    pqc_ready = False   # no current SNMP version supports PQC key exchange

    if not recommendations:
        recommendations.append(
            "SNMP is NOT PQC-ready.  No SNMP version currently supports quantum-safe key "
            "exchange or authentication.  Minimise SNMP exposure, prefer network telemetry "
            "alternatives (gRPC/YANG) where possible, and plan migration to SNMPv3 at minimum."
        )

    return {
        "hostname":                  hostname,
        "port":                      port,
        "responding":                v1_enabled or v2c_enabled or v3_enabled,
        "v1_enabled":                v1_enabled,
        "v2c_enabled":               v2c_enabled,
        "v3_enabled":                v3_enabled,
        "public_community_responds": public_community_responds,
        "pqc_ready":                 pqc_ready,
        "weak_findings":             weak_findings,
        "recommendations":           recommendations,
        "error":                     None,
    }


# ---------------------------------------------------------------------------
# Per-host checker
# ---------------------------------------------------------------------------

def _check_snmp_host(hostname: str, port: int) -> dict:
    """Probe *hostname*:*port* (UDP) for SNMPv1, v2c, and v3."""
    result: dict = {
        "hostname":                  hostname,
        "port":                      port,
        "responding":                False,
        "v1_enabled":                False,
        "v2c_enabled":               False,
        "v3_enabled":                False,
        "public_community_responds": False,
        "pqc_ready":                 False,
        "weak_findings":             [],
        "recommendations":           [],
        "error":                     None,
    }

    try:
        req_id_v1 = random.randint(1, 0x7FFFFFFF)
        req_id_v2 = random.randint(1, 0x7FFFFFFF)

        # --- SNMPv1 probe ---
        v1_packet  = _build_snmp_get(0, "public", _SYSDESRC_OID, req_id_v1)
        v1_response = _udp_send_recv(hostname, port, v1_packet)

        if v1_response and _is_valid_snmp_response(v1_response):
            # Check version byte in response (should be INTEGER 0 = v1)
            result["v1_enabled"]                = True
            result["public_community_responds"] = True

        # --- SNMPv2c probe ---
        v2_packet  = _build_snmp_get(1, "public", _SYSDESRC_OID, req_id_v2)
        v2_response = _udp_send_recv(hostname, port, v2_packet)

        if v2_response and _is_valid_snmp_response(v2_response):
            result["v2c_enabled"]               = True
            result["public_community_responds"] = True

        # --- SNMPv3 probe ---
        v3_packet  = _build_snmpv3_discovery()
        v3_response = _udp_send_recv(hostname, port, v3_packet)

        if v3_response and _is_valid_snmpv3_response(v3_response):
            result["v3_enabled"] = True

    except OSError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    if not (result["v1_enabled"] or result["v2c_enabled"] or result["v3_enabled"]):
        result["error"] = f"No SNMP response from {hostname}:{port} (all versions timed out)"
        return result

    analysis = _analyse_snmp(
        hostname,
        port,
        result["v1_enabled"],
        result["v2c_enabled"],
        result["v3_enabled"],
        result["public_community_responds"],
    )
    result.update(analysis)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_snmp(
    hostname: str,
    timestamp,
    suffix,
    root: Optional[Path] = None,
) -> Path:
    """
    Probe SNMPv1, SNMPv2c, and SNMPv3 on UDP port 161 and save results to
    output/raw/13_snmp_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    port = _SNMP_PORT
    logger.info(f"[SNMP] Starting SNMP scan on '{hostname}' UDP/{port} ...")

    try:
        res = _check_snmp_host(hostname, port)
    except Exception as exc:
        res = {
            "hostname":   hostname,
            "port":       port,
            "responding": False,
            "error":      f"{type(exc).__name__}: {exc}",
        }

    if res.get("error") and not res.get("responding"):
        logger.warning(f"[SNMP] {hostname}:{port} — {res['error']}")
    elif res.get("responding"):
        versions = []
        if res.get("v1_enabled"):
            versions.append("v1")
        if res.get("v2c_enabled"):
            versions.append("v2c")
        if res.get("v3_enabled"):
            versions.append("v3")
        pqc_flag = "PQC-READY" if res.get("pqc_ready") else "NOT PQC-READY"
        weak_n   = len(res.get("weak_findings", []))
        pub_tag  = " | public=CRITICAL" if res.get("public_community_responds") else ""
        logger.success(
            f"[SNMP] {hostname}:{port} — SNMP {'+'.join(versions)}{pub_tag} | "
            f"{pqc_flag} | weak_findings={weak_n}"
        )
    else:
        logger.info(f"[SNMP] {hostname}:{port} — not responding")

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"13_snmp_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"snmp_checks": [res]}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[SNMP] Results saved to: '{out_file}'")
    return out_file

#!/usr/bin/env python3
"""IKE (Internet Key Exchange) cryptographic analysis — Stage 9.

Probes UDP ports 500 and 4500 with hand-crafted IKEv2 SA_INIT packets
that propose seven DH groups.  Parses the responder's chosen DH group
and flags quantum-vulnerable choices.  Also probes for legacy IKEv1
(deprecated, RFC 9395) on UDP 500.

All packet structures are built with only the Python standard library
(socket, struct, os, random).
"""

import json
import os
import random
import socket
import struct
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# DH Group classification table
# ---------------------------------------------------------------------------

# group_id → (human_name, severity, shor_vulnerable)
# Severity reflects both classical strength and Shor vulnerability on a CRQC:
#   Critical  = broken classically or extremely small key (< 2048-bit MODP, < P-256)
#   High      = broken by Shor on a CRQC, but classically acceptable (2048-bit MODP, NIST curves)
#   Medium    = transitional — large enough MODP to require more qubits, but still Shor-vulnerable
#               (NIST SP 800-56A Rev3 transitional: 3072–4096-bit MODP)
#   Low       = Shor-resistant classical DH (6144/8192-bit, requires impractically large QC)
#   PQC Ready = post-quantum hybrid or pure PQC KEX
_IKE_DH_GROUPS: dict[int, tuple[str, str, bool]] = {
    1:  ("768-bit MODP",          "Critical", True),
    2:  ("1024-bit MODP",         "Critical", True),
    5:  ("1536-bit MODP",         "Critical", True),
    14: ("2048-bit MODP",         "High",     True),   # NIST transitional (formerly acceptable)
    15: ("3072-bit MODP",         "Medium",   True),   # NIST acceptable transitional
    16: ("4096-bit MODP",         "Medium",   True),   # NIST acceptable transitional
    17: ("6144-bit MODP",         "Low",      True),   # Shor requires impractically large QC
    18: ("8192-bit MODP",         "Low",      True),   # Shor requires impractically large QC
    19: ("P-256 (NIST)",          "High",     True),   # Shor breaks ECC efficiently
    20: ("P-384 (NIST)",          "High",     True),   # Shor breaks ECC efficiently
    21: ("P-521 (NIST)",          "High",     True),   # Shor breaks ECC efficiently
    31: ("X25519",                "High",     True),   # Shor breaks ECDH efficiently
    32: ("X448",                  "High",     True),   # Shor breaks ECDH efficiently
    34: ("ML-KEM-768 hybrid",     "Low",      False),  # PQC hybrid — quantum-safe
    35: ("ML-KEM-1024 hybrid",    "Low",      False),  # PQC hybrid — quantum-safe
}

# Groups included in our IKEv2 SA proposal (ordered most→least preferred)
_PROPOSED_DH_GROUPS = [14, 15, 16, 19, 20, 21, 31]

# IKEv2 exchange/payload type constants
_IKEv2_EXCHANGE_SA_INIT = 34
_IKEv2_VERSION           = 0x20
_IKEv2_FLAG_INITIATOR    = 0x08

_PAYLOAD_SA    = 33
_PAYLOAD_KE    = 40
_PAYLOAD_NONCE = 41
_PAYLOAD_NOTIFY = 41   # Note: NOTIFY is also type 41 in some contexts;
                        # but in IKEv2 Notify is actually type 41.
                        # RFC 7296: Notify = 41, Nonce = 40.
                        # Corrected:
_PAYLOAD_NONCE_CORRECT  = 40
_PAYLOAD_NOTIFY_CORRECT = 41

# IKEv2 Notify message types
_NOTIFY_NO_PROPOSAL_CHOSEN  = 14
_NOTIFY_INVALID_KE_PAYLOAD  = 17

# IKEv1 exchange type for Main Mode
_IKEv1_VERSION    = 0x10
_IKEv1_EXCHANGE_MAIN_MODE = 2

_UDP_TIMEOUT  = 3   # seconds per send attempt
_UDP_RETRIES  = 1   # retry once on timeout


# ---------------------------------------------------------------------------
# IKEv2 packet builder
# ---------------------------------------------------------------------------

def _build_transform(t_type: int, t_id: int, attrs: bytes = b"", last: bool = False) -> bytes:
    """Build a single IKEv2 Transform substructure."""
    # struct: last_or_more(1) | reserved(1) | transform_length(2) | type(1) | reserved(1) | id(2)
    body = struct.pack("!BBBBH", t_type, 0, t_id >> 8, t_id & 0xFF, 0) + attrs
    # Re-pack properly: type(1) reserved(1) id(2)
    body = struct.pack("!BBH", t_type, 0, t_id) + attrs
    more = 0 if last else 3
    length = 8 + len(attrs)
    return struct.pack("!BBH", more, 0, length) + struct.pack("!BBH", t_type, 0, t_id) + attrs


def _build_keylen_attr(bits: int) -> bytes:
    """Build a fixed-length Key Length attribute (AF=1 → top bit set)."""
    # Attribute format: type(2, AF bit set) | value(2)
    return struct.pack("!HH", 0x800E, bits)


def _build_proposal(prop_num: int, dh_group: int, last: bool = False) -> bytes:
    """
    Build one IKEv2 SA Proposal with 4 transforms:
      Enc=AES-CBC-256, PRF=HMAC-SHA2-256, Integ=HMAC-SHA2-256-128, DH=dh_group
    """
    # Transform 1: Encryption AES-CBC (id=12) with key_len=256
    t1 = _build_transform(1, 12, _build_keylen_attr(256), last=False)
    # Transform 2: PRF HMAC-SHA2-256 (id=5)
    t2 = _build_transform(2, 5,  b"", last=False)
    # Transform 3: Integrity HMAC-SHA2-256-128 (id=12)
    t3 = _build_transform(3, 12, b"", last=False)
    # Transform 4: DH Group (id=dh_group) — last transform
    t4 = _build_transform(4, dh_group, b"", last=True)

    transforms = t1 + t2 + t3 + t4

    # Proposal header: last_or_more(1) | reserved(1) | length(2) | num(1) |
    #                  protocol(1=IKE) | spi_size(1=0) | num_transforms(1)
    more   = 0 if last else 2
    length = 8 + len(transforms)  # 8-byte proposal header
    header = struct.pack("!BBHBBBB", more, 0, length, prop_num, 1, 0, 4)
    return header + transforms


def _build_sa_payload(next_payload: int) -> bytes:
    """Build the SA payload containing one proposal per DH group."""
    proposals = b""
    for i, group in enumerate(_PROPOSED_DH_GROUPS):
        last = (i == len(_PROPOSED_DH_GROUPS) - 1)
        proposals += _build_proposal(i + 1, group, last=last)

    # Generic payload header: next_payload(1) | critical(1) | length(2)
    length = 4 + len(proposals)
    return struct.pack("!BBH", next_payload, 0, length) + proposals


def _build_ke_payload(next_payload: int, dh_group: int = 14) -> bytes:
    """
    Build a KE payload for DH Group 14 (2048-bit MODP).
    KE data is 256 bytes of random material (the correct size for group 14).
    """
    ke_data = os.urandom(256)
    # KE payload body: dh_group(2) | reserved(2) | ke_data
    body    = struct.pack("!HH", dh_group, 0) + ke_data
    length  = 4 + len(body)
    return struct.pack("!BBH", next_payload, 0, length) + body


def _build_nonce_payload(next_payload: int) -> bytes:
    """Build a Nonce payload with 32 random bytes."""
    nonce  = os.urandom(32)
    length = 4 + len(nonce)
    return struct.pack("!BBH", next_payload, 0, length) + nonce


def _build_ikev2_sa_init() -> tuple[bytes, bytes]:
    """
    Construct a complete IKEv2 IKE_SA_INIT packet.

    Returns (packet_bytes, initiator_spi).
    """
    initiator_spi = os.urandom(8)
    responder_spi = b"\x00" * 8

    # Payload chain: SA → KE → Nonce
    sa_payload    = _build_sa_payload(next_payload=_PAYLOAD_KE)
    ke_payload    = _build_ke_payload(next_payload=_PAYLOAD_NONCE_CORRECT)
    nonce_payload = _build_nonce_payload(next_payload=0)

    body = sa_payload + ke_payload + nonce_payload
    total_length = 28 + len(body)   # 28-byte IKE header

    # IKE Header (28 bytes):
    # initiator_spi(8) | responder_spi(8) | next_payload(1) | version(1) |
    # exchange_type(1) | flags(1) | message_id(4) | length(4)
    header = (
        initiator_spi
        + responder_spi
        + struct.pack(
            "!BBBBII",
            _PAYLOAD_SA,             # next payload = SA
            _IKEv2_VERSION,          # 0x20
            _IKEv2_EXCHANGE_SA_INIT, # 34
            _IKEv2_FLAG_INITIATOR,   # 0x08
            0,                       # message ID
            total_length,
        )
    )
    return header + body, initiator_spi


# ---------------------------------------------------------------------------
# IKEv2 response parser
# ---------------------------------------------------------------------------

def _parse_ikev2_response(data: bytes) -> dict:
    """
    Parse an IKEv2 response.  Returns a dict with:
      responding, chosen_dh_group, notify_type, ikev2_version
    """
    info: dict = {
        "responding":       True,
        "chosen_dh_group":  None,
        "notify_type":      None,
        "raw_length":       len(data),
    }

    if len(data) < 28:
        info["parse_error"] = "Response too short for IKE header"
        return info

    # IKE header
    next_payload  = data[16]
    version       = data[17]
    exchange_type = data[18]
    flags         = data[19]

    info["ikev2_version"]   = f"0x{version:02x}"
    info["exchange_type"]   = exchange_type

    # Walk payloads
    pos          = 28   # after IKE header
    current_type = next_payload

    while pos + 4 <= len(data) and current_type != 0:
        try:
            payload_next   = data[pos]
            payload_flags  = data[pos + 1]
            payload_length = struct.unpack("!H", data[pos + 2: pos + 4])[0]
        except (struct.error, IndexError):
            break

        payload_data = data[pos + 4: pos + payload_length]

        if current_type == _PAYLOAD_SA:
            # Try to extract chosen DH group from SA payload
            # Walk proposals/transforms in the SA
            inner_pos = 0
            while inner_pos + 8 <= len(payload_data):
                prop_more   = payload_data[inner_pos]
                prop_len    = struct.unpack("!H", payload_data[inner_pos + 2: inner_pos + 4])[0]
                prop_num    = payload_data[inner_pos + 4]
                num_trans   = payload_data[inner_pos + 7]
                t_pos       = inner_pos + 8
                for _ in range(num_trans):
                    if t_pos + 8 > len(payload_data):
                        break
                    t_more   = payload_data[t_pos]
                    t_len    = struct.unpack("!H", payload_data[t_pos + 2: t_pos + 4])[0]
                    t_type   = payload_data[t_pos + 4]
                    t_id     = struct.unpack("!H", payload_data[t_pos + 6: t_pos + 8])[0]
                    if t_type == 4:   # DH group transform
                        info["chosen_dh_group"] = t_id
                    t_pos += t_len
                if prop_more == 0:
                    break
                inner_pos += prop_len

        elif current_type == _PAYLOAD_NOTIFY_CORRECT:
            # Notify payload: protocol_id(1) | spi_size(1) | notify_type(2) | [spi] | notify_data
            if len(payload_data) >= 4:
                notify_type = struct.unpack("!H", payload_data[2:4])[0]
                info["notify_type"] = notify_type
                # INVALID_KE_PAYLOAD includes preferred group in notify data
                if notify_type == _NOTIFY_INVALID_KE_PAYLOAD and len(payload_data) >= 6:
                    preferred_group = struct.unpack("!H", payload_data[4:6])[0]
                    info["chosen_dh_group"] = preferred_group

        current_type = payload_next
        if payload_length < 4:
            break
        pos += payload_length

    return info


# ---------------------------------------------------------------------------
# IKEv1 probe builder
# ---------------------------------------------------------------------------

def _build_ikev1_main_mode() -> bytes:
    """
    Build a minimal IKEv1 Main Mode SA packet with a single proposal
    (3DES / SHA-1 / DH Group 2).

    IKEv1 header (28 bytes):
      initiator_cookie(8) | responder_cookie(8) | next_payload(1) |
      version(1=0x10) | exchange_type(1=2 Main) | flags(1) |
      message_id(4) | length(4)
    """
    initiator_cookie = os.urandom(8)
    responder_cookie = b"\x00" * 8

    # Minimal SA payload (RFC 2408 ISAKMP):
    # SA payload header: next(1) | reserved(1) | length(2) | doi(4) | situation(4)
    # Proposal: next(1) | reserved(1) | length(2) | num(1) | proto(1=ISAKMP) |
    #           spi_size(1) | num_transforms(1)
    # Transform: next(1) | reserved(1) | length(2) | num(1) | id(1=KEY_IKE) |
    #            reserved(2) | attributes...
    # Attribute: 3DES (type 1, val 5), SHA-1 (type 2, val 2), DH-2 (type 4, val 2),
    #            Auth=PSK (type 3, val 1), LifeType=seconds (type 11, val 1),
    #            LifeDuration=28800 (type 12, val 28800)

    def attr(t: int, v: int) -> bytes:
        return struct.pack("!HH", 0x8000 | t, v)

    transform_attrs = (
        attr(1, 5)    # Encryption 3DES
        + attr(2, 2)  # Hash SHA-1
        + attr(4, 2)  # Group 2 (1024-bit MODP)
        + attr(3, 1)  # Auth PSK
        + attr(11, 1) # Life type = seconds
        + attr(12, 28800)  # Life duration
    )

    # Transform substructure
    trans_body   = struct.pack("!BBHBB", 1, 0, 0, 1, 0) + b"\x00\x00" + transform_attrs
    # Fix: transform header is next(1)|reserved(1)|length(2)|num(1)|id(1)|reserved(2)
    trans_header = struct.pack("!BBHBBH", 0, 0, 8 + len(transform_attrs), 1, 1, 0)
    transform    = trans_header + transform_attrs

    # Proposal
    prop_body    = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1)
    proposal     = prop_body + transform

    # SA payload: doi=1 (IPSEC), situation=1 (SIT_IDENTITY_ONLY)
    sa_inner     = struct.pack("!II", 1, 1) + proposal
    sa_payload   = struct.pack("!BBH", 0, 0, 4 + len(sa_inner)) + sa_inner

    total_length = 28 + len(sa_payload)
    header = (
        initiator_cookie
        + responder_cookie
        + struct.pack(
            "!BBBBII",
            1,                   # next payload = SA
            _IKEv1_VERSION,      # 0x10
            _IKEv1_EXCHANGE_MAIN_MODE,  # 2
            0,                   # flags
            0,                   # message ID
            total_length,
        )
    )
    return header + sa_payload


# ---------------------------------------------------------------------------
# UDP probe helper
# ---------------------------------------------------------------------------

def _udp_send_recv(
    hostname: str,
    port: int,
    packet: bytes,
    timeout: float = _UDP_TIMEOUT,
    retries: int = _UDP_RETRIES,
) -> Optional[bytes]:
    """Send *packet* to (hostname, port) via UDP and return the response bytes, or None."""
    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise OSError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server_ip, port))
            data, _ = sock.recvfrom(65535)
            return data
        except (socket.timeout, TimeoutError):
            pass   # will retry
        except ConnectionRefusedError:
            return None   # ICMP port-unreachable → definitely closed
        except OSError:
            return None
        finally:
            sock.close()

    return None   # all attempts timed out


# ---------------------------------------------------------------------------
# Per-port checker
# ---------------------------------------------------------------------------

def _check_ike_port(hostname: str, port: int) -> dict:
    """
    Probe a single UDP port for IKEv2 (and IKEv1 on port 500).
    Returns a structured result dict.
    """
    result: dict = {
        "hostname":          hostname,
        "port":              port,
        "protocol":          "UDP",
        "ike_version":       None,
        "responding":        False,
        "ikev1_enabled":     False,
        "preferred_dh_group": None,
        "proposed_dh_groups": _PROPOSED_DH_GROUPS[:],
        "encryption_algos":  ["AES-CBC-256"],
        "pqc_ready":         False,
        "weak_findings":     [],
        "recommendations":   [],
        "error":             None,
    }

    # ------------------------------------------------------------------
    # IKEv2 probe
    # ------------------------------------------------------------------
    try:
        packet, init_spi = _build_ikev2_sa_init()
        response = _udp_send_recv(hostname, port, packet)
    except OSError as exc:
        result["error"] = str(exc)
        return result

    if response is None:
        result["error"] = f"No IKEv2 response from {hostname}:{port} (timeout or ICMP closed)"
        return result

    result["responding"]   = True
    result["ike_version"]  = "IKEv2"

    parsed = _parse_ikev2_response(response)
    notify = parsed.get("notify_type")

    # Determine chosen/preferred DH group
    chosen_group_id = parsed.get("chosen_dh_group")

    if notify == _NOTIFY_NO_PROPOSAL_CHOSEN:
        result["weak_findings"].append({
            "type":           "No IKEv2 Proposal Chosen",
            "severity":       "Medium",
            "detail":         "Responder rejected all proposed DH groups",
            "recommendation": "Review IKEv2 policy and propose mutually supported DH groups",
        })

    if chosen_group_id is not None:
        group_info = _IKE_DH_GROUPS.get(chosen_group_id, (f"Unknown (id={chosen_group_id})", "Unknown", False))
        result["preferred_dh_group"] = {
            "id":              chosen_group_id,
            "name":            group_info[0],
            "shor_vulnerable": group_info[2],
        }

        severity      = group_info[1]
        shor_vuln     = group_info[2]

        if shor_vuln:
            result["weak_findings"].append({
                "type":           "Quantum-Vulnerable DH Group",
                "severity":       severity,
                "detail":         (
                    f"IKEv2 DH Group {chosen_group_id} ({group_info[0]}) is broken by "
                    "Shor's algorithm on a cryptographically relevant quantum computer (CRQC)"
                ),
                "recommendation": (
                    "Migrate to IKEv2 with DH Group 35 (ML-KEM-1024 hybrid) or Group 34 "
                    "(ML-KEM-768 hybrid) per IETF draft-ietf-ipsecme-ikev2-mlkem"
                ),
            })
        else:
            result["pqc_ready"] = True

        result["recommendations"].append(
            "Migrate to IKEv2 with DH Group 35 (ML-KEM-1024 hybrid) per "
            "IETF draft-ietf-ipsecme-ikev2-mlkem"
            if shor_vuln else
            f"PQC-ready DH Group {chosen_group_id} ({group_info[0]}) detected."
        )
    else:
        # No explicit DH group in response; flag default proposal as vulnerable
        result["recommendations"].append(
            "Could not determine preferred DH group from response. "
            "Inspect IKEv2 policy manually and migrate to ML-KEM hybrid groups."
        )

    # ------------------------------------------------------------------
    # IKEv1 probe (port 500 only)
    # ------------------------------------------------------------------
    if port == 500:
        try:
            v1_packet  = _build_ikev1_main_mode()
            v1_response = _udp_send_recv(hostname, port, v1_packet)
        except OSError:
            v1_response = None

        if v1_response and len(v1_response) >= 28:
            # Sanity: check version byte = 0x10 and exchange type = 2
            v1_version  = v1_response[17]
            v1_exchange = v1_response[18]
            if v1_version == _IKEv1_VERSION and v1_exchange == _IKEv1_EXCHANGE_MAIN_MODE:
                result["ikev1_enabled"] = True
                result["weak_findings"].append({
                    "type":           "IKEv1 Enabled",
                    "severity":       "High",
                    "detail":         (
                        "IKEv1 is deprecated (RFC 9395) and has known cryptographic weaknesses "
                        "(e.g. Aggressive Mode identity leakage, weak PSK susceptibility)"
                    ),
                    "recommendation": (
                        "Disable IKEv1 completely and use IKEv2 exclusively. "
                        "See RFC 9395 for migration guidance."
                    ),
                })

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_ike(
    hostname: str,
    timestamp,
    suffix,
    ports: Optional[list] = None,
    root: Optional[Path] = None,
) -> Path:
    """
    Probe IKEv2 (and IKEv1) on UDP ports 500 and 4500.
    Save results to output/raw/9_ike_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    if ports is None:
        ports = [500, 4500]

    logger.info(f"[IKE] Starting IKE scan on '{hostname}' ports {ports} ...")

    checks = []
    for port in ports:
        logger.info(f"[IKE] Probing {hostname}:{port}/UDP ...")
        try:
            res = _check_ike_port(hostname, port)
        except Exception as exc:
            res = {
                "hostname": hostname, "port": port, "protocol": "UDP",
                "responding": False, "error": f"{type(exc).__name__}: {exc}",
            }

        if res.get("error"):
            logger.warning(f"[IKE] {hostname}:{port} — {res['error']}")
        elif res.get("responding"):
            pqc_flag = "PQC-READY" if res.get("pqc_ready") else "NOT PQC-READY"
            dh       = res.get("preferred_dh_group") or {}
            dh_name  = dh.get("name", "unknown")
            weak_n   = len(res.get("weak_findings", []))
            logger.success(
                f"[IKE] {hostname}:{port} — IKEv2 | DH={dh_name} | "
                f"{pqc_flag} | weak_findings={weak_n}"
            )
            if res.get("ikev1_enabled"):
                logger.warning(f"[IKE] {hostname}:{port} — IKEv1 also ENABLED (High severity)")
        else:
            logger.info(f"[IKE] {hostname}:{port} — not responding")

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"9_ike_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"ike_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[IKE] Results saved to: '{out_file}'")
    return out_file

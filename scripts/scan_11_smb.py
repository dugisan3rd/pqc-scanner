#!/usr/bin/env python3
"""SMB cryptographic analysis — Stage 11.

Probes TCP port 445 for SMBv1 (NEGOTIATE request) and SMB2/3
(NEGOTIATE request with all dialect revisions).  Parses the selected
dialect, signing flags, encryption capabilities, and — for SMB 3.1.1 —
the Negotiate Contexts to extract cipher IDs.  All findings are rated
against PQC-readiness criteria.

All packet structures are built with only the Python standard library
(socket, struct, os).
"""

import json
import os
import socket
import struct
import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# SMB constants
# ---------------------------------------------------------------------------

_CONNECT_TIMEOUT = 8   # seconds

# SMBv1 magic in response
_SMBv1_MAGIC = b"\xFF\x53\x4D\x42"

# SMB2 dialect revisions
_SMB2_DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# SMB2 Negotiate Context types
_CTXTYPE_ENCRYPTION = 0x0002

# Cipher IDs (SMB 3.1.1 Negotiate Context type 0x0002)
_CIPHER_NAMES: dict[int, str] = {
    1: "AES-128-CCM",
    2: "AES-128-GCM",
    3: "AES-256-CCM",
    4: "AES-256-GCM",
}

# Cipher severity (id → severity, Grover-weakened label)
_CIPHER_SEVERITY: dict[int, tuple[str, str]] = {
    1: ("Medium", "AES-128-CCM — 64-bit quantum security under Grover's algorithm"),
    2: ("Medium", "AES-128-GCM — 64-bit quantum security under Grover's algorithm"),
    3: ("Low",    "AES-256-CCM — 128-bit quantum security; classically strong"),
    4: ("Low",    "AES-256-GCM — 128-bit quantum security; classically strong"),
}


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf


def _build_smb1_negotiate() -> bytes:
    """Build an SMBv1 NEGOTIATE request with the 'NT LM 0.12' dialect."""
    dialect = b"\x02NT LM 0.12\x00"
    byte_count = len(dialect)

    # SMBv1 header (32 bytes) + body
    smb1_header = (
        b"\xFF\x53\x4D\x42"          # Protocol: 0xFF + "SMB"
        + b"\x72"                     # Command: Negotiate (0x72)
        + struct.pack("<I", 0)        # Status: 0
        + b"\x18"                     # Flags: 0x18
        + struct.pack("<H", 0xC853)   # Flags2: 0xC853
        + b"\x00" * 12               # Extra (PID high, security features, reserved)
        + struct.pack("<H", 0)        # TID
        + struct.pack("<H", 0xFEFF)   # PID
        + struct.pack("<H", 0)        # UID
        + struct.pack("<H", 0)        # MID
    )
    smb1_body = (
        b"\x00"                       # Word Count: 0
        + struct.pack("<H", byte_count)  # Byte Count
        + dialect
    )
    smb1_message = smb1_header + smb1_body

    # NetBIOS Session header (4 bytes): 0x00 + 3-byte big-endian length
    nb_header = b"\x00" + struct.pack(">I", len(smb1_message))[1:]
    return nb_header + smb1_message


def _build_smb2_negotiate() -> bytes:
    """Build an SMB2 NEGOTIATE request advertising dialects 2.0–3.1.1."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    dialect_count = len(dialects)
    client_guid = os.urandom(16)

    # SMB2 Negotiate body (36 bytes fixed + 5*2 dialect bytes)
    negotiate_body = (
        struct.pack("<H", 36)              # StructureSize
        + struct.pack("<H", dialect_count) # DialectCount
        + struct.pack("<H", 1)             # SecurityMode: signing enabled
        + struct.pack("<H", 0)             # Reserved
        + struct.pack("<I", 0x7F)          # Capabilities
        + client_guid                      # ClientGUID (16 bytes)
        + struct.pack("<I", 0)             # NegotiateContextOffset
        + struct.pack("<H", 0)             # NegotiateContextCount
        + struct.pack("<H", 0)             # Reserved2
        + struct.pack("<" + "H" * dialect_count, *dialects)
    )

    # SMB2 header (64 bytes)
    smb2_header = (
        b"\xFE\x53\x4D\x42"           # Protocol ID: FE + "SMB"
        + struct.pack("<H", 64)        # StructureSize
        + struct.pack("<H", 0)         # CreditCharge
        + struct.pack("<I", 0)         # Status
        + struct.pack("<H", 0)         # Command: NEGOTIATE
        + struct.pack("<H", 0)         # CreditRequest
        + struct.pack("<I", 0)         # Flags
        + struct.pack("<I", 0)         # NextCommand
        + struct.pack("<Q", 0)         # MessageId
        + struct.pack("<I", 0)         # Reserved
        + struct.pack("<I", 0)         # TreeId
        + struct.pack("<Q", 0)         # SessionId
        + b"\x00" * 16                # Signature
    )

    smb2_message = smb2_header + negotiate_body

    # NetBIOS Session header
    nb_header = b"\x00" + struct.pack(">I", len(smb2_message))[1:]
    return nb_header + smb2_message


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def _check_smb1(hostname: str, port: int) -> dict:
    """
    Send an SMBv1 NEGOTIATE and check whether the server responds with an
    SMBv1 header (0xFF 0x53 0x4D 0x42 at response offset 4).

    Returns a dict with keys: smb1_enabled, error.
    """
    result: dict = {"smb1_enabled": False, "error": None}
    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.sendall(_build_smb1_negotiate())
            # Read NetBIOS header (4 bytes) to get the message length
            nb = _recv_exactly(sock, 4)
            msg_len = struct.unpack(">I", b"\x00" + nb[1:])[0]
            if msg_len < 4:
                return result
            response = _recv_exactly(sock, msg_len)
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = "Connection timed out"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    # Check for SMBv1 magic at offset 0 of the SMB message
    if len(response) >= 4 and response[:4] == _SMBv1_MAGIC:
        result["smb1_enabled"] = True
    return result


def _parse_smb2_negotiate_response(data: bytes) -> dict:
    """
    Parse an SMB2 NEGOTIATE response.

    Expects *data* to be the raw SMB2 message (after stripping the
    4-byte NetBIOS header).  Returns a dict with:
      dialect_revision, dialect_name, signing_enabled, signing_required,
      encryption_supported, cipher_ids, negotiate_context_offset,
      negotiate_context_count, parse_error.
    """
    info: dict = {
        "dialect_revision":        None,
        "dialect_name":            None,
        "signing_enabled":         False,
        "signing_required":        False,
        "encryption_supported":    False,
        "cipher_ids":              [],
        "negotiate_context_offset": 0,
        "negotiate_context_count":  0,
        "parse_error":             None,
    }

    if len(data) < 64:
        info["parse_error"] = "Response too short for SMB2 header"
        return info

    # Verify SMB2 magic
    if data[:4] != b"\xFE\x53\x4D\x42":
        info["parse_error"] = f"Not an SMB2 response (magic: {data[:4].hex()})"
        return info

    # SMB2 header is 64 bytes; Negotiate Response body starts at offset 64
    body = data[64:]
    if len(body) < 32:
        info["parse_error"] = "SMB2 Negotiate Response body too short"
        return info

    # SMB2 NEGOTIATE Response body structure (RFC MS-SMB2 §2.2.4):
    #   StructureSize  (2)  offset 0
    #   SecurityMode   (2)  offset 2
    #   DialectRevision(2)  offset 4
    #   NegCtxCount    (2)  offset 6
    #   ServerGUID     (16) offset 8
    #   Capabilities   (4)  offset 24
    #   MaxTransactSize(4)  offset 28
    #   MaxReadSize    (4)  offset 32
    #   MaxWriteSize   (4)  offset 36
    #   SystemTime     (8)  offset 40
    #   ServerStartTime(8)  offset 48
    #   SecurityBufOfs (2)  offset 56
    #   SecurityBufLen (2)  offset 58
    #   NegCtxOffset   (4)  offset 60

    security_mode    = struct.unpack_from("<H", body, 2)[0]
    dialect_revision = struct.unpack_from("<H", body, 4)[0]
    neg_ctx_count    = struct.unpack_from("<H", body, 6)[0]
    capabilities     = struct.unpack_from("<I", body, 24)[0] if len(body) >= 28 else 0
    neg_ctx_offset   = struct.unpack_from("<I", body, 60)[0] if len(body) >= 64 else 0

    info["dialect_revision"]       = dialect_revision
    info["dialect_name"]           = _SMB2_DIALECTS.get(dialect_revision, f"Unknown (0x{dialect_revision:04x})")
    info["signing_enabled"]        = bool(security_mode & 0x01)
    info["signing_required"]       = bool(security_mode & 0x02)
    info["encryption_supported"]   = bool(capabilities & 0x40)
    info["negotiate_context_count"] = neg_ctx_count
    info["negotiate_context_offset"] = neg_ctx_offset

    # Parse Negotiate Contexts for SMB 3.1.1
    if dialect_revision == 0x0311 and neg_ctx_count > 0 and neg_ctx_offset > 0:
        # neg_ctx_offset is relative to the start of the SMB2 message (i.e., data)
        ctx_pos = neg_ctx_offset  # already an absolute offset from data[0]
        for _ in range(neg_ctx_count):
            if ctx_pos + 4 > len(data):
                break
            ctx_type   = struct.unpack_from("<H", data, ctx_pos)[0]
            ctx_datalen = struct.unpack_from("<H", data, ctx_pos + 2)[0]
            ctx_body_start = ctx_pos + 8  # 2 type + 2 datalen + 4 reserved

            if ctx_type == _CTXTYPE_ENCRYPTION:
                # EncryptionCapabilities: CipherCount (uint16) + Cipher IDs (uint16 each)
                if ctx_body_start + 2 <= len(data):
                    cipher_count = struct.unpack_from("<H", data, ctx_body_start)[0]
                    for ci in range(cipher_count):
                        cipher_offset = ctx_body_start + 2 + ci * 2
                        if cipher_offset + 2 <= len(data):
                            cid = struct.unpack_from("<H", data, cipher_offset)[0]
                            info["cipher_ids"].append(cid)

            # Advance to next context (8-byte aligned)
            ctx_entry_size = 8 + ctx_datalen
            padding = (8 - (ctx_entry_size % 8)) % 8
            ctx_pos += ctx_entry_size + padding

    return info


def _check_smb2(hostname: str, port: int) -> dict:
    """
    Send an SMB2 NEGOTIATE and parse the dialect / capabilities.

    Returns a dict with: responding, smb2_info (from _parse_smb2_negotiate_response),
    error.
    """
    result: dict = {"responding": False, "smb2_info": {}, "error": None}
    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.sendall(_build_smb2_negotiate())
            nb = _recv_exactly(sock, 4)
            msg_len = struct.unpack(">I", b"\x00" + nb[1:])[0]
            if msg_len < 4:
                result["error"] = "Empty SMB2 response"
                return result
            response = _recv_exactly(sock, msg_len)
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = "Connection timed out"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    result["responding"] = True
    result["smb2_info"]  = _parse_smb2_negotiate_response(response)
    return result


# ---------------------------------------------------------------------------
# PQC analysis
# ---------------------------------------------------------------------------

def _analyse_smb(
    hostname: str,
    port: int,
    smb1_enabled: bool,
    smb2: dict,
) -> dict:
    """
    Build the full result dict for one SMB host:port probe.
    *smb2* is the parsed SMB2 negotiate response (from _parse_smb2_negotiate_response).
    """
    weak_findings: list = []
    recommendations: list = []

    dialect_revision = smb2.get("dialect_revision")
    dialect_name     = smb2.get("dialect_name") or "unknown"
    signing_enabled  = smb2.get("signing_enabled", False)
    signing_required = smb2.get("signing_required", False)
    enc_supported    = smb2.get("encryption_supported", False)
    raw_cipher_ids   = smb2.get("cipher_ids", [])
    cipher_names     = [_CIPHER_NAMES.get(c, f"Unknown (id={c})") for c in raw_cipher_ids]

    # --- SMBv1 ---
    if smb1_enabled:
        weak_findings.append({
            "type":           "SMBv1 Enabled",
            "severity":       "Critical",
            "detail":         (
                "SMBv1 is enabled. It lacks encryption, has no message signing by "
                "default, and is exploited by EternalBlue (MS17-010) / WannaCry. "
                "SMBv1 uses DES/RC4-based security with MD5 integrity — all broken."
            ),
            "recommendation": (
                "Disable SMBv1 immediately: PowerShell 'Set-SmbServerConfiguration "
                "-EnableSMB1Protocol $false' (Windows) or 'options smb1 = no' (Samba)."
            ),
        })

    # --- Dialect ---
    if dialect_revision in (0x0202, 0x0210):
        weak_findings.append({
            "type":           "SMB 2.0/2.1 — No Encryption",
            "severity":       "High",
            "detail":         (
                f"Negotiated dialect {dialect_name} does not support SMB encryption. "
                "All data is transmitted in plaintext on the wire."
            ),
            "recommendation": (
                "Upgrade to SMB 3.x and enable encryption: "
                "'Set-SmbServerConfiguration -EncryptData $true'."
            ),
        })
    elif dialect_revision in (0x0300, 0x0302):
        if raw_cipher_ids:
            for cid in raw_cipher_ids:
                sev, detail = _CIPHER_SEVERITY.get(cid, ("Medium", f"Cipher id={cid}"))
                if sev in ("Medium",):
                    weak_findings.append({
                        "type":           "Grover-Weakened SMB Cipher",
                        "severity":       sev,
                        "detail":         f"{dialect_name} uses {_CIPHER_NAMES.get(cid, str(cid))}: {detail}",
                        "recommendation": "Prefer SMB 3.1.1 with AES-256-GCM.",
                    })
        else:
            # SMB 3.0/3.0.2 reports encryption capability via Capabilities bit
            if enc_supported:
                weak_findings.append({
                    "type":           "Grover-Weakened SMB Cipher",
                    "severity":       "Medium",
                    "detail":         (
                        f"{dialect_name} encryption uses AES-128-CCM by default — "
                        "provides only 64-bit quantum security under Grover's algorithm."
                    ),
                    "recommendation": "Upgrade to SMB 3.1.1 with AES-256-GCM.",
                })
    elif dialect_revision == 0x0311:
        for cid in raw_cipher_ids:
            sev, detail = _CIPHER_SEVERITY.get(cid, ("Medium", f"Cipher id={cid}"))
            if sev == "Medium":
                weak_findings.append({
                    "type":           "Grover-Weakened SMB Cipher",
                    "severity":       "Medium",
                    "detail":         f"SMB 3.1.1 cipher {_CIPHER_NAMES.get(cid, str(cid))}: {detail}",
                    "recommendation": (
                        "Prefer AES-256-GCM (cipher id=4) in SMB 3.1.1 cipher priority list. "
                        "On Windows: 'Set-SmbServerConfiguration -SMBServerNameHardeningLevel 1'."
                    ),
                })

    # --- Signing ---
    if not signing_required:
        weak_findings.append({
            "type":           "SMB Signing Not Required",
            "severity":       "High",
            "detail":         (
                "SMB message signing is not enforced. Attackers can perform NTLM relay "
                "attacks to intercept and forward authentication to other services."
            ),
            "recommendation": (
                "Require SMB signing: 'Set-SmbServerConfiguration -RequireSecuritySignature $true' "
                "(Windows) or 'server signing = mandatory' (Samba)."
            ),
        })

    # --- NTLM / Authentication ---
    weak_findings.append({
        "type":           "Quantum-Vulnerable Authentication",
        "severity":       "Medium",
        "detail":         (
            "SMB authentication uses NTLM or Kerberos, both of which are vulnerable to "
            "Shor's algorithm on a cryptographically relevant quantum computer (CRQC). "
            "NTLM relies on MD4/HMAC-MD5; Kerberos relies on RSA/ECDH key exchange."
        ),
        "recommendation": (
            "Plan migration to certificate-based authentication with PQC algorithms "
            "(ML-DSA / Falcon). Interim: enforce Kerberos with AES-256, disable NTLMv1, "
            "and restrict NTLMv2 where possible."
        ),
    })

    # --- Recommendations summary ---
    pqc_ready = False
    if dialect_revision == 0x0311 and signing_required:
        best_cipher = max(raw_cipher_ids) if raw_cipher_ids else 0
        if best_cipher in (3, 4):   # AES-256-CCM or AES-256-GCM
            pqc_ready = False  # still not PQC-ready (auth is quantum-vulnerable)
            recommendations.append(
                "SMB 3.1.1 with AES-256 encryption and required signing is the best "
                "currently achievable SMB posture, but it is NOT PQC-ready because "
                "authentication (NTLM/Kerberos) remains quantum-vulnerable."
            )

    if not pqc_ready and not recommendations:
        recommendations.append(
            "SMB is NOT PQC-ready. Upgrade to SMB 3.1.1, enforce AES-256-GCM encryption, "
            "require signing, and plan migration to PQC-safe authentication mechanisms."
        )

    return {
        "hostname":            hostname,
        "port":                port,
        "smb1_enabled":        smb1_enabled,
        "dialect":             dialect_name,
        "dialect_revision":    f"0x{dialect_revision:04x}" if dialect_revision else None,
        "signing_enabled":     signing_enabled,
        "signing_required":    signing_required,
        "encryption_supported": enc_supported,
        "cipher_ids":          cipher_names,
        "pqc_ready":           pqc_ready,
        "weak_findings":       weak_findings,
        "recommendations":     recommendations,
    }


# ---------------------------------------------------------------------------
# Per-port checker
# ---------------------------------------------------------------------------

def _check_smb_port(hostname: str, port: int) -> dict:
    """Probe *hostname*:*port* for SMBv1 and SMB2/3 and return a findings dict."""
    result: dict = {
        "hostname":            hostname,
        "port":                port,
        "responding":          False,
        "smb1_enabled":        False,
        "dialect":             None,
        "dialect_revision":    None,
        "signing_enabled":     False,
        "signing_required":    False,
        "encryption_supported": False,
        "cipher_ids":          [],
        "pqc_ready":           False,
        "weak_findings":       [],
        "recommendations":     [],
        "error":               None,
    }

    # Step 1 — SMBv1 detection
    smb1_result = _check_smb1(hostname, port)
    if smb1_result.get("error") and not smb1_result.get("smb1_enabled"):
        result["error"] = smb1_result["error"]
        return result

    smb1_enabled = smb1_result.get("smb1_enabled", False)

    # Step 2 — SMB2/3 NEGOTIATE
    smb2_result = _check_smb2(hostname, port)
    if smb2_result.get("error") and not smb2_result.get("responding"):
        result["error"] = smb2_result["error"]
        # Still report SMBv1 if we got that far
        if smb1_enabled:
            result["smb1_enabled"] = True
            result["responding"]   = True
            result["weak_findings"].append({
                "type":           "SMBv1 Enabled",
                "severity":       "Critical",
                "detail":         (
                    "SMBv1 is enabled. SMB2/3 probe failed; SMBv1-only server suspected."
                ),
                "recommendation": "Disable SMBv1 immediately.",
            })
        return result

    result["responding"] = True

    smb2_info   = smb2_result.get("smb2_info", {})
    parse_error = smb2_info.get("parse_error")
    if parse_error:
        result["error"] = f"SMB2 parse error: {parse_error}"

    analysis = _analyse_smb(hostname, port, smb1_enabled, smb2_info)
    result.update(analysis)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_smb(
    hostname: str,
    timestamp,
    suffix,
    ports: Optional[list] = None,
    root: Optional[Path] = None,
) -> Path:
    """
    Probe SMBv1 and SMB2/3 on the given ports and save results to
    output/raw/11_smb_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    if ports is None:
        ports = [445]

    logger.info(f"[SMB] Starting SMB scan on '{hostname}' ports {ports} ...")

    checks = []
    for port in ports:
        logger.info(f"[SMB] Checking {hostname}:{port} ...")
        try:
            res = _check_smb_port(hostname, port)
        except Exception as exc:
            res = {
                "hostname":   hostname,
                "port":       port,
                "responding": False,
                "error":      f"{type(exc).__name__}: {exc}",
            }

        if res.get("error") and not res.get("responding"):
            logger.warning(f"[SMB] {hostname}:{port} — {res['error']}")
        elif res.get("responding"):
            dialect  = res.get("dialect") or "unknown"
            pqc_flag = "PQC-READY" if res.get("pqc_ready") else "NOT PQC-READY"
            weak_n   = len(res.get("weak_findings", []))
            smb1_tag = " | SMBv1=CRITICAL" if res.get("smb1_enabled") else ""
            logger.success(
                f"[SMB] {hostname}:{port} — {dialect}{smb1_tag} | "
                f"{pqc_flag} | weak_findings={weak_n}"
            )
        else:
            logger.info(f"[SMB] {hostname}:{port} — not responding")

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"11_smb_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"smb_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[SMB] Results saved to: '{out_file}'")
    return out_file

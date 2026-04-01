#!/usr/bin/env python3
"""Database TLS cryptographic analysis — Stage 12.

Probes MySQL/MariaDB (3306), PostgreSQL (5432), MSSQL (1433), MongoDB
(27017), and Redis (6379 / 6380) for TLS support.  Where TLS is present
a full cipher/version/certificate analysis is performed.  Plain-text
database endpoints are flagged as Critical or High PQC findings.

All packet structures are built with only the Python standard library
(socket, struct, ssl, datetime).
"""

import datetime
import json
import socket
import ssl
import struct
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Shared TLS analysis constants (mirrors scan_10_rdp.py style)
# ---------------------------------------------------------------------------

_CONNECT_TIMEOUT = 8   # seconds

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
# Database service definitions
# ---------------------------------------------------------------------------

_DB_SERVICES = [
    {"service": "MySQL",      "port": 3306},
    {"service": "PostgreSQL", "port": 5432},
    {"service": "MSSQL",      "port": 1433},
    {"service": "MongoDB",    "port": 27017},
    {"service": "Redis",      "port": 6379},
    {"service": "Redis-TLS",  "port": 6380},
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf


def _parse_cert_expiry(not_after: str) -> Optional[datetime.datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(not_after, fmt)
        except ValueError:
            continue
    return None


def _analyse_tls_connection(hostname: str, port: int, raw_sock: socket.socket) -> dict:
    """
    Wrap *raw_sock* (already open, positioned after any STARTTLS handshake)
    in TLS and return a dict with tls_version, cipher_suite, certificate,
    pqc_indicators, weak_findings, recommendations, tls_error.
    """
    tls_info: dict = {
        "tls_version":     None,
        "cipher_suite":    None,
        "certificate":     {},
        "pqc_indicators":  [],
        "weak_findings":   [],
        "recommendations": [],
        "tls_error":       None,
    }
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
            tls_ver = tls_sock.version() or "unknown"
            cipher  = tls_sock.cipher()      # (name, proto, key_bits)
            cert    = tls_sock.getpeercert()  # decoded dict (no validation)

        tls_info["tls_version"] = tls_ver
        if cipher:
            tls_info["cipher_suite"] = {"name": cipher[0], "key_bits": cipher[2]}
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

    # --- TLS version ---
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

    # --- Cipher ---
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

    # --- Certificate expiry ---
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

    # --- PQC indicators ---
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
# MySQL / MariaDB (port 3306)
# ---------------------------------------------------------------------------

def _check_mysql(hostname: str, port: int) -> dict:
    """
    Connect to MySQL/MariaDB, read the server greeting, check SSL capability,
    send SSLRequest and perform TLS handshake if supported.
    """
    result: dict = {
        "hostname":       hostname,
        "port":           port,
        "service":        "MySQL",
        "responding":     False,
        "tls_supported":  False,
        "tls_required":   False,
        "server_version": None,
        "tls_version":    None,
        "cipher_suite":   None,
        "certificate":    {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
        "error":          None,
    }

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
        result["responding"] = True

        # Read MySQL packet header: 3-byte length (LE) + 1-byte sequence_id
        raw_header = _recv_exactly(sock, 4)
        payload_len = struct.unpack_from("<I", raw_header[:3] + b"\x00")[0]
        if payload_len == 0 or payload_len > 65535:
            result["error"] = f"Invalid MySQL packet length: {payload_len}"
            sock.close()
            return result

        greeting = _recv_exactly(sock, payload_len)
        protocol_version = greeting[0]

        # Extract server version (null-terminated string starting at offset 1)
        nul = greeting.index(b"\x00", 1)
        server_version = greeting[1:nul].decode("utf-8", errors="replace")
        result["server_version"] = server_version

        if protocol_version not in (9, 10):
            result["error"] = f"Unknown MySQL protocol version: {protocol_version}"
            sock.close()
            return result

        # Capability flags are at: after version-string + 4 (conn_id) + 8 (auth data) + 1 (filler)
        cap_offset = nul + 1 + 4 + 8 + 1
        if len(greeting) < cap_offset + 2:
            result["error"] = "Greeting too short to read capability flags"
            sock.close()
            return result

        cap_low = struct.unpack_from("<H", greeting, cap_offset)[0]
        client_ssl_flag = 0x0800
        ssl_capable = bool(cap_low & client_ssl_flag)
        result["tls_supported"] = ssl_capable

        if not ssl_capable:
            result["weak_findings"].append({
                "type":           "No TLS Support",
                "severity":       "Critical",
                "detail":         (
                    f"MySQL/MariaDB {server_version} does not advertise SSL/TLS capability. "
                    "All database traffic is transmitted in plaintext."
                ),
                "recommendation": (
                    "Enable SSL in MySQL: set ssl_cert, ssl_key, ssl_ca in my.cnf and "
                    "restart. Enforce with 'REQUIRE SSL' on user accounts."
                ),
            })
            sock.close()
            return result

        # Send SSLRequest packet (sequence_id=1)
        ssl_req_payload = (
            struct.pack("<I", 0x00000801)   # capability flags: CLIENT_SSL | CLIENT_PROTOCOL_41
            + struct.pack("<I", 0x40000000) # max packet size
            + b"\x21"                       # character set: utf8
            + b"\x00" * 23                 # reserved
        )
        ssl_req_header = struct.pack("<I", len(ssl_req_payload))[:3] + b"\x01"
        sock.sendall(ssl_req_header + ssl_req_payload)

        # Now wrap in TLS (sock is consumed by _analyse_tls_connection)
        tls_info = _analyse_tls_connection(hostname, port, sock)
        result["tls_version"]    = tls_info.get("tls_version")
        result["cipher_suite"]   = tls_info.get("cipher_suite")
        result["certificate"]    = tls_info.get("certificate", {})
        result["pqc_indicators"] = tls_info.get("pqc_indicators", [])
        result["weak_findings"] += tls_info.get("weak_findings", [])
        result["recommendations"] += tls_info.get("recommendations", [])
        if tls_info.get("tls_error"):
            result["error"] = tls_info["tls_error"]

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# PostgreSQL (port 5432)
# ---------------------------------------------------------------------------

def _check_postgresql(hostname: str, port: int) -> dict:
    """
    Send the PostgreSQL SSLRequest magic and check the single-byte response.
    If 'S', wrap in TLS and analyse.
    """
    result: dict = {
        "hostname":       hostname,
        "port":           port,
        "service":        "PostgreSQL",
        "responding":     False,
        "tls_supported":  False,
        "tls_required":   False,
        "server_version": None,
        "tls_version":    None,
        "cipher_suite":   None,
        "certificate":    {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
        "error":          None,
    }

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
        result["responding"] = True

        # SSLRequest: length=8 (uint32 BE) + SSLRequest code=80877103 (uint32 BE)
        ssl_request = struct.pack("!II", 8, 80877103)
        sock.sendall(ssl_request)
        response_byte = _recv_exactly(sock, 1)

        if response_byte == b"S":
            result["tls_supported"] = True
            tls_info = _analyse_tls_connection(hostname, port, sock)
            result["tls_version"]    = tls_info.get("tls_version")
            result["cipher_suite"]   = tls_info.get("cipher_suite")
            result["certificate"]    = tls_info.get("certificate", {})
            result["pqc_indicators"] = tls_info.get("pqc_indicators", [])
            result["weak_findings"] += tls_info.get("weak_findings", [])
            result["recommendations"] += tls_info.get("recommendations", [])
            if tls_info.get("tls_error"):
                result["error"] = tls_info["tls_error"]

        elif response_byte == b"N":
            result["tls_supported"] = False
            result["weak_findings"].append({
                "type":           "No TLS Support",
                "severity":       "Critical",
                "detail":         (
                    "PostgreSQL server replied 'N' to SSLRequest — SSL/TLS is not enabled. "
                    "All database traffic is transmitted in plaintext."
                ),
                "recommendation": (
                    "Enable SSL in postgresql.conf: set ssl=on, provide ssl_cert_file and "
                    "ssl_key_file. Enforce with 'hostssl' rows in pg_hba.conf."
                ),
            })
        else:
            result["error"] = f"Unexpected SSLRequest response byte: {response_byte!r}"

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# MSSQL (port 1433)
# ---------------------------------------------------------------------------

def _build_mssql_prelogin() -> bytes:
    """
    Build a minimal TDS PRELOGIN packet advertising ENCRYPTION=ENCRYPT_ON.

    Token layout (offsets relative to start of PRELOGIN body):
      TOKEN 0x00 (VERSION)    offset=13, length=6
      TOKEN 0x01 (ENCRYPTION) offset=19, length=1
      TOKEN 0xFF (TERMINATOR)
      VERSION data  (6 bytes): 0x0E 0x00 0x00 0x00 0x00 0x00
      ENCRYPTION data (1 byte): 0x02 (ENCRYPT_ON)
    """
    # Option tokens header (7 bytes) + VERSION data (6) + ENCRYPTION data (1) = 14 bytes body
    # Each option token: 1 byte type + 2 byte BE offset + 2 byte BE length = 5 bytes
    # Two tokens (VERSION + ENCRYPTION) = 10 bytes, plus 1 byte terminator = 11 bytes
    # Data starts at offset 11 from the start of PRELOGIN body
    version_offset    = 11          # after token table (11 bytes)
    encryption_offset = version_offset + 6  # after VERSION (6 bytes)

    body = (
        b"\x00"                                     # token: VERSION
        + struct.pack(">HH", version_offset, 6)     # offset=11, length=6
        + b"\x01"                                   # token: ENCRYPTION
        + struct.pack(">HH", encryption_offset, 1)  # offset=17, length=1
        + b"\xFF"                                   # token: TERMINATOR
        + b"\x0E\x00\x00\x00\x00\x00"              # VERSION: SQL Server 14
        + b"\x02"                                   # ENCRYPTION: ENCRYPT_ON
    )

    # TDS header: type(1) + status(1) + total_length(2 BE) + SPID(2) + PacketID(1) + Window(1)
    total_length = 8 + len(body)
    header = struct.pack(">BBHBBBB", 0x12, 0x01, total_length, 0, 0, 0x00, 0x00)
    return header + body


def _parse_mssql_prelogin_response(data: bytes) -> Optional[int]:
    """
    Parse PRELOGIN response and return the ENCRYPTION token value, or None.
    """
    if len(data) < 8:
        return None
    # Skip 8-byte TDS header
    body = data[8:]
    pos  = 0
    # Walk token table
    while pos < len(body):
        token = body[pos]
        if token == 0xFF:
            break
        if pos + 5 > len(body):
            break
        offset = struct.unpack_from(">H", body, pos + 1)[0]
        length = struct.unpack_from(">H", body, pos + 3)[0]
        pos   += 5
        if token == 0x01:   # ENCRYPTION
            if offset < len(body):
                return body[offset]
    return None


def _check_mssql(hostname: str, port: int) -> dict:
    """
    Send TDS PRELOGIN, parse ENCRYPTION value, do TLS handshake if encryption
    is requested or required.
    """
    result: dict = {
        "hostname":       hostname,
        "port":           port,
        "service":        "MSSQL",
        "responding":     False,
        "tls_supported":  False,
        "tls_required":   False,
        "server_version": None,
        "tls_version":    None,
        "cipher_suite":   None,
        "certificate":    {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
        "error":          None,
    }

    _ENCRYPT_OFF = 0x00
    _ENCRYPT_OFF_ALSO = 0x01
    _ENCRYPT_ON  = 0x02
    _ENCRYPT_REQ = 0x03

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
        result["responding"] = True

        sock.sendall(_build_mssql_prelogin())
        raw = sock.recv(4096)
        if not raw:
            result["error"] = "Empty PRELOGIN response"
            sock.close()
            return result

        enc_value = _parse_mssql_prelogin_response(raw)

        if enc_value in (_ENCRYPT_OFF, _ENCRYPT_OFF_ALSO):
            result["tls_supported"] = False
            result["weak_findings"].append({
                "type":           "No TLS / Encryption Off",
                "severity":       "Critical",
                "detail":         (
                    f"MSSQL PRELOGIN returned ENCRYPTION=0x{enc_value:02x} (ENCRYPT_OFF). "
                    "Data is transmitted in plaintext."
                ),
                "recommendation": (
                    "Set 'Force Encryption = Yes' in SQL Server Configuration Manager "
                    "→ SQL Server Network Configuration → Protocols for MSSQLSERVER."
                ),
            })
        elif enc_value in (_ENCRYPT_ON, _ENCRYPT_REQ):
            result["tls_supported"] = True
            result["tls_required"]  = (enc_value == _ENCRYPT_REQ)

            tls_info = _analyse_tls_connection(hostname, port, sock)
            result["tls_version"]    = tls_info.get("tls_version")
            result["cipher_suite"]   = tls_info.get("cipher_suite")
            result["certificate"]    = tls_info.get("certificate", {})
            result["pqc_indicators"] = tls_info.get("pqc_indicators", [])
            result["weak_findings"] += tls_info.get("weak_findings", [])
            result["recommendations"] += tls_info.get("recommendations", [])
            if tls_info.get("tls_error"):
                result["error"] = tls_info["tls_error"]
        else:
            result["error"] = f"Unknown MSSQL ENCRYPTION token value: {enc_value!r}"

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# MongoDB (port 27017)
# ---------------------------------------------------------------------------

def _build_ismongodb_op_msg() -> bytes:
    """
    Build a MongoDB OP_MSG with {isMaster: 1} as BSON.

    BSON {isMaster: 1}:
      int32 doc_length + type(0x10=int32) + "isMaster\x00" + int32(1) + 0x00 terminator
    """
    key      = b"isMaster\x00"
    bson_doc = (
        b"\x10"           # type: int32
        + key
        + struct.pack("<i", 1)   # value: 1
        + b"\x00"         # document terminator
    )
    doc_len   = 4 + len(bson_doc) + 1   # int32 length + content + final null
    # actually BSON doc = total_length (includes itself) + elements + terminator
    bson_data = struct.pack("<i", 4 + len(bson_doc)) + bson_doc

    # OP_MSG body: flagBits (uint32) + section_type (uint8=0) + bson_doc
    op_msg_body = struct.pack("<I", 0) + b"\x00" + bson_data

    # MsgHeader: messageLength(int32) + requestID(int32) + responseTo(int32) + opCode(int32=2013)
    total_len = 16 + len(op_msg_body)
    header = struct.pack("<iiii", total_len, 1, 0, 2013)
    return header + op_msg_body


def _check_mongodb(hostname: str, port: int) -> dict:
    """
    Send isMaster OP_MSG to MongoDB.  If it responds without TLS → flag Critical.
    We attempt a direct TLS connect on the same port to see if TLS is at least
    an option.
    """
    result: dict = {
        "hostname":       hostname,
        "port":           port,
        "service":        "MongoDB",
        "responding":     False,
        "tls_supported":  False,
        "tls_required":   False,
        "server_version": None,
        "tls_version":    None,
        "cipher_suite":   None,
        "certificate":    {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
        "error":          None,
    }

    # Step 1 — Check if plain TCP port is open / answers OP_MSG
    plain_open = False
    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.sendall(_build_ismongodb_op_msg())
            raw = sock.recv(4096)
            if raw and len(raw) >= 16:
                plain_open = True
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out to {hostname}:{port}"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    result["responding"] = True

    if plain_open:
        result["tls_supported"] = False
        result["weak_findings"].append({
            "type":           "No TLS Support",
            "severity":       "Critical",
            "detail":         (
                "MongoDB is accepting plain-text connections on port "
                f"{port}. All wire protocol data (queries, results, "
                "credentials) is transmitted unencrypted."
            ),
            "recommendation": (
                "Enable TLS in mongod.conf: set net.tls.mode=requireTLS, provide "
                "net.tls.certificateKeyFile and net.tls.CAFile. "
                "Enforce client certificate validation."
            ),
        })

    # Step 2 — Try direct TLS connect to the same port (mongod with --tlsMode requireTLS)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                tls_ver = tls_sock.version() or "unknown"
                cipher  = tls_sock.cipher()
                cert    = tls_sock.getpeercert()

        result["tls_supported"] = True
        result["tls_required"]  = True  # it answered TLS directly → likely requireTLS mode
        result["tls_version"]   = tls_ver
        if cipher:
            result["cipher_suite"] = {"name": cipher[0], "key_bits": cipher[2]}
        if cert:
            not_after = cert.get("notAfter", "")
            expiry    = _parse_cert_expiry(not_after)
            days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
            subject   = dict(x[0] for x in cert.get("subject", []))
            issuer    = dict(x[0] for x in cert.get("issuer",  []))
            result["certificate"] = {
                "common_name":       subject.get("commonName", ""),
                "issuer_cn":         issuer.get("commonName",  ""),
                "not_after":         not_after,
                "days_until_expiry": days_left,
            }
        # Remove the "No TLS" finding we added above if direct TLS works
        result["weak_findings"] = [
            f for f in result["weak_findings"] if f.get("type") != "No TLS Support"
        ]
        result["recommendations"].append(
            "TLS is NOT PQC-ready. Migrate to X25519Kyber768 / ML-KEM-768 hybrid key exchange."
        )
        result["recommendations"].append(
            "Ensure server certificate uses ML-DSA / Falcon, or at minimum RSA-3072 / ECDSA P-384."
        )
    except (ssl.SSLError, OSError):
        # TLS not available on this port — plain_open result stands
        if not plain_open:
            result["error"] = "Port is open but neither plain-text OP_MSG nor direct TLS succeeded"

    return result


# ---------------------------------------------------------------------------
# Redis (ports 6379 / 6380)
# ---------------------------------------------------------------------------

def _check_redis(hostname: str, port: int) -> dict:
    """
    Check Redis.

    Port 6379: send PING, classify response.
    Port 6380: attempt direct TLS connect (Redis TLS port convention).
    """
    is_tls_port = (port == 6380)
    service_name = "Redis-TLS" if is_tls_port else "Redis"

    result: dict = {
        "hostname":       hostname,
        "port":           port,
        "service":        service_name,
        "responding":     False,
        "tls_supported":  False,
        "tls_required":   False,
        "server_version": None,
        "tls_version":    None,
        "cipher_suite":   None,
        "certificate":    {},
        "pqc_indicators": [],
        "weak_findings":  [],
        "recommendations": [],
        "error":          None,
    }

    if is_tls_port:
        # Attempt direct TLS connection
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                    # Send PING over TLS
                    tls_sock.sendall(b"PING\r\n")
                    response = tls_sock.recv(256)
                    tls_ver  = tls_sock.version() or "unknown"
                    cipher   = tls_sock.cipher()
                    cert     = tls_sock.getpeercert()

            result["responding"]    = True
            result["tls_supported"] = True
            result["tls_required"]  = True
            result["tls_version"]   = tls_ver
            if cipher:
                result["cipher_suite"] = {"name": cipher[0], "key_bits": cipher[2]}
            if cert:
                not_after = cert.get("notAfter", "")
                expiry    = _parse_cert_expiry(not_after)
                days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
                subject   = dict(x[0] for x in cert.get("subject", []))
                issuer    = dict(x[0] for x in cert.get("issuer",  []))
                result["certificate"] = {
                    "common_name":       subject.get("commonName", ""),
                    "issuer_cn":         issuer.get("commonName",  ""),
                    "not_after":         not_after,
                    "days_until_expiry": days_left,
                }

            if response and not response.startswith(b"+PONG"):
                result["error"] = f"Unexpected PING response over TLS: {response[:64]!r}"

            result["recommendations"].append(
                "TLS is NOT PQC-ready. Migrate to X25519Kyber768 / ML-KEM-768 hybrid key exchange."
            )
            result["recommendations"].append(
                "Ensure server certificate uses ML-DSA / Falcon, or at minimum RSA-3072 / ECDSA P-384."
            )

        except ConnectionRefusedError:
            result["error"] = f"Connection refused at {hostname}:{port}"
        except (socket.timeout, TimeoutError):
            result["error"] = f"Connection timed out to {hostname}:{port}"
        except (ssl.SSLError, OSError) as exc:
            result["error"] = f"TLS error: {exc}"

        return result

    # Plain Redis port (6379)
    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.sendall(b"PING\r\n")
            response = sock.recv(256)
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
        return result
    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out to {hostname}:{port}"
        return result
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
        return result

    result["responding"] = True
    resp_str = response.decode("utf-8", errors="replace").strip()

    if response.startswith(b"+PONG"):
        result["weak_findings"].append({
            "type":           "Redis Unauthenticated — No TLS",
            "severity":       "Critical",
            "detail":         (
                "Redis responded to PING with +PONG without authentication and without TLS. "
                "The instance is fully open: all data readable/writable, no encryption."
            ),
            "recommendation": (
                "Enable requirepass in redis.conf and configure TLS with tls-port, "
                "tls-cert-file, tls-key-file, tls-ca-cert-file. "
                "Bind to localhost or restrict with firewall rules."
            ),
        })
    elif resp_str.startswith("-NOAUTH") or "NOAUTH" in resp_str:
        result["weak_findings"].append({
            "type":           "Redis Authentication Required — No TLS",
            "severity":       "High",
            "detail":         (
                "Redis requires authentication (NOAUTH error), but the connection is "
                "unencrypted. Credentials are transmitted in plaintext."
            ),
            "recommendation": (
                "Enable Redis TLS (tls-port 6380) and require clients to use TLS. "
                "Consider also mutual TLS (tls-auth-clients yes)."
            ),
        })
    else:
        result["error"] = f"Unexpected Redis response: {resp_str[:128]!r}"

    result["recommendations"].append(
        "Redis does not support PQC-safe key exchange. Plan migration to a TLS 1.3 "
        "deployment with ML-KEM hybrid cipher suites when supported by the Redis TLS library."
    )

    return result


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _check_db_service(hostname: str, service: str, port: int) -> dict:
    """Route to the correct per-service checker."""
    if service == "MySQL":
        return _check_mysql(hostname, port)
    if service == "PostgreSQL":
        return _check_postgresql(hostname, port)
    if service == "MSSQL":
        return _check_mssql(hostname, port)
    if service == "MongoDB":
        return _check_mongodb(hostname, port)
    if service in ("Redis", "Redis-TLS"):
        return _check_redis(hostname, port)
    return {
        "hostname": hostname, "port": port, "service": service,
        "responding": False, "error": f"Unknown service type: {service}",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_databases(
    hostname: str,
    timestamp,
    suffix,
    root: Optional[Path] = None,
) -> Path:
    """
    Probe MySQL, PostgreSQL, MSSQL, MongoDB, and Redis for TLS support and
    PQC-readiness.  Save results to output/raw/12_db_*.json.
    """
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    logger.info(f"[DB] Starting database TLS scan on '{hostname}' ...")

    checks = []
    for svc in _DB_SERVICES:
        service = svc["service"]
        port    = svc["port"]
        logger.info(f"[DB] Checking {hostname}:{port} ({service}) ...")
        try:
            res = _check_db_service(hostname, service, port)
        except Exception as exc:
            res = {
                "hostname":   hostname,
                "port":       port,
                "service":    service,
                "responding": False,
                "error":      f"{type(exc).__name__}: {exc}",
            }

        if res.get("error") and not res.get("responding"):
            logger.warning(f"[DB] {hostname}:{port} ({service}) — {res['error']}")
        elif res.get("responding"):
            tls_ver  = res.get("tls_version") or "none"
            tls_flag = "TLS" if res.get("tls_supported") else "PLAIN-TEXT"
            weak_n   = len(res.get("weak_findings", []))
            logger.success(
                f"[DB] {hostname}:{port} ({service}) — {tls_flag} {tls_ver} | "
                f"weak_findings={weak_n}"
            )
        else:
            logger.info(f"[DB] {hostname}:{port} ({service}) — not responding")

        checks.append(res)

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"12_db_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"db_checks": checks}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[DB] Results saved to: '{out_file}'")
    return out_file

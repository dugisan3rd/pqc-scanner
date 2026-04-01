#!/usr/bin/env python3
"""SSH cryptographic analysis — Stage 6.

Connects to an SSH server, reads SSH_MSG_KEXINIT, and classifies all
advertised key-exchange, host-key, cipher, and MAC algorithms against
PQC-readiness standards using raw socket protocol negotiation.
"""

import json
import os
import socket
import struct
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Algorithm classification tables
# ---------------------------------------------------------------------------

_WEAK_KEX = {
    "diffie-hellman-group1-sha1":        "DH Group 1 (768-bit) — cryptographically broken",
    "diffie-hellman-group14-sha1":       "DH Group 14 with SHA-1 — deprecated (RFC 8270)",
    "diffie-hellman-group-exchange-sha1":"DH GEX with SHA-1 — deprecated hash",
    "gss-gex-sha1-*":                    "GSS KEX with SHA-1 hash",
    "gss-group1-sha1-*":                 "GSS Group 1 with SHA-1",
    "gss-group14-sha1-*":                "GSS Group 14 with SHA-1",
}

_CLASSICAL_WEAK_KEX = {
    # Classically acceptable but fully broken by Shor's algorithm on a CRQC
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "curve448-sha512",
}

_PQC_HYBRID_KEX = {
    # Hybrid PQC+classical KEX — provides harvest-now/decrypt-later protection
    "sntrup761x25519-sha512@openssh.com",       # OpenSSH 8.5+ (NTRU Prime hybrid)
    "mlkem768x25519-sha256",                     # ML-KEM-768 + X25519 (IETF draft)
    "mlkem768x25519-sha256@openssh.com",         # OpenSSH vendor variant
    "mlkem1024x25519-sha256",                    # ML-KEM-1024 + X25519
    "mlkem1024x25519-sha256@openssh.com",        # OpenSSH vendor variant
    "kyber-512r3-x25519-sha256",                 # early Kyber draft
    "kyber-768r3-x25519-sha384",                 # early Kyber draft
    "kyber-1024r3-x25519-sha512",                # early Kyber draft
    "x25519-kyber-512r3v1@openquantumsafe.org",  # OQS vendor
    "x25519-kyber-768r3v1@openquantumsafe.org",  # OQS vendor
}

_WEAK_HOST_KEY = {
    "ssh-dss":      "DSA (1024-bit fixed) — broken, RFC 9142 recommends removal",
    "ssh-rsa":      "RSA with SHA-1 digest — deprecated by RFC 8332",
    "x509v3-ssh-dss": "X.509 DSA — deprecated",
}

_WEAK_CIPHER = {
    "3des-cbc":    "3DES-CBC — Sweet32 attack (CVE-2016-2183); deprecated",
    "blowfish-cbc":"Blowfish-CBC — deprecated, short block size",
    "cast128-cbc": "CAST-128-CBC — deprecated",
    "arcfour":     "RC4 — cryptographically broken",
    "arcfour128":  "RC4-128 — broken",
    "arcfour256":  "RC4-256 — broken",
    "aes128-cbc":  "AES-128-CBC — not AEAD; vulnerable to BEAST/CBC padding attacks",
    "aes192-cbc":  "AES-192-CBC — not AEAD",
    "aes256-cbc":  "AES-256-CBC — not AEAD; prefer GCM or ChaCha20",
}

_WEAK_MAC = {
    "hmac-md5":                      "HMAC-MD5 — MD5 deprecated (RFC 6151)",
    "hmac-md5-96":                   "HMAC-MD5-96 — deprecated",
    "hmac-md5-etm@openssh.com":      "HMAC-MD5-ETM — MD5 deprecated (RFC 6151)",
    "hmac-md5-96-etm@openssh.com":   "HMAC-MD5-96-ETM — deprecated",
    "hmac-sha1":                     "HMAC-SHA1 — SHA-1 deprecated (NIST 2030)",
    "hmac-sha1-96":                  "HMAC-SHA1-96 — deprecated",
    "hmac-sha1-etm@openssh.com":     "HMAC-SHA1-ETM — SHA-1 deprecated (NIST 2030)",
    "hmac-sha1-96-etm@openssh.com":  "HMAC-SHA1-96-ETM — deprecated",
    "hmac-ripemd160":                "HMAC-RIPEMD160 — deprecated",
    "hmac-ripemd160@openssh.com":    "HMAC-RIPEMD160 — deprecated",
    "hmac-ripemd160-etm@openssh.com":"HMAC-RIPEMD160-ETM — deprecated",
}


# ---------------------------------------------------------------------------
# SSH binary protocol helpers
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf


def _read_banner(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\n"):
        byte = sock.recv(1)
        if not byte:
            break
        data += byte
        if len(data) > 512:   # guard against misbehaving server
            break
    return data.decode("utf-8", errors="replace").strip()


def _encode_namelist(algos: list) -> bytes:
    s = ",".join(algos).encode()
    return struct.pack(">I", len(s)) + s


def _make_kexinit_packet() -> bytes:
    """Build a minimal SSH_MSG_KEXINIT (msg_type=20)."""
    msg_type = bytes([20])
    cookie   = os.urandom(16)
    payload  = (
        msg_type + cookie
        + _encode_namelist(["curve25519-sha256"])
        + _encode_namelist(["ecdsa-sha2-nistp256", "rsa-sha2-256"])
        + _encode_namelist(["aes256-gcm@openssh.com"])
        + _encode_namelist(["aes256-gcm@openssh.com"])
        + _encode_namelist(["hmac-sha2-256"])
        + _encode_namelist(["hmac-sha2-256"])
        + _encode_namelist(["none"])
        + _encode_namelist(["none"])
        + _encode_namelist([])
        + _encode_namelist([])
        + bytes([0])              # first_kex_follows = False
        + struct.pack(">I", 0)   # reserved
    )
    padding_len = 8 - (len(payload) + 5) % 8
    if padding_len < 4:
        padding_len += 8
    pkt  = struct.pack(">IB", len(payload) + padding_len + 1, padding_len)
    pkt += payload + os.urandom(padding_len)
    return pkt


def _read_packet(sock: socket.socket) -> Optional[bytes]:
    raw_len = _recv_exactly(sock, 4)
    pkt_len = struct.unpack(">I", raw_len)[0]
    if pkt_len > 65_536:
        return None   # sanity guard
    rest        = _recv_exactly(sock, pkt_len)
    padding_len = rest[0]
    payload_len = pkt_len - 1 - padding_len
    return rest[1: 1 + payload_len]


def _parse_kexinit(payload: bytes) -> Optional[dict]:
    """Parse SSH_MSG_KEXINIT payload into a dict of algorithm lists."""
    if not payload or payload[0] != 20:
        return None
    pos = 17  # skip msg_type (1) + cookie (16)
    fields = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]
    result = {}
    for name in fields:
        if pos + 4 > len(payload):
            break
        list_len = struct.unpack(">I", payload[pos: pos + 4])[0]
        pos += 4
        raw    = payload[pos: pos + list_len].decode("utf-8", errors="replace")
        result[name] = [a.strip() for a in raw.split(",") if a.strip()]
        pos += list_len
    return result


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _analyse_kexinit(kex: dict, hostname: str, port: int) -> dict:
    weak_findings: list = []
    pqc_indicators: list = []
    recommendations: list = []

    kex_algos  = kex.get("kex_algorithms", [])
    hk_algos   = kex.get("server_host_key_algorithms", [])
    enc_algos  = kex.get("encryption_algorithms_client_to_server", [])
    enc_algos += [a for a in kex.get("encryption_algorithms_server_to_client", [])
                  if a not in enc_algos]
    mac_algos  = kex.get("mac_algorithms_client_to_server", [])
    mac_algos += [a for a in kex.get("mac_algorithms_server_to_client", [])
                  if a not in mac_algos]

    # --- key exchange ---
    for algo in kex_algos:
        if algo in _WEAK_KEX:
            weak_findings.append({
                "category": "Key Exchange",
                "algorithm": algo,
                "severity": "High",
                "detail": _WEAK_KEX[algo],
                "recommendation": "Remove from KexAlgorithms in sshd_config",
            })
        if algo in _PQC_HYBRID_KEX:
            pqc_indicators.append(algo)

    quantum_weak = [a for a in kex_algos if a in _CLASSICAL_WEAK_KEX]
    if quantum_weak and not pqc_indicators:
        recommendations.append(
            "SSH KEX is NOT PQC-ready — all key-exchange algorithms are broken by "
            "Shor's algorithm on a cryptographically relevant quantum computer (CRQC). "
            "Add 'sntrup761x25519-sha512@openssh.com' (OpenSSH >= 8.5) to KexAlgorithms "
            "as the first entry to enable harvest-now/decrypt-later protection."
        )
    elif pqc_indicators:
        recommendations.append(
            f"PQC-hybrid KEX present: {', '.join(pqc_indicators)}. "
            "Verify it is the first (most-preferred) algorithm in KexAlgorithms."
        )
    else:
        recommendations.append(
            "No known KEX algorithms advertised. Check SSH server configuration."
        )

    # --- host key ---
    for algo in hk_algos:
        if algo in _WEAK_HOST_KEY:
            weak_findings.append({
                "category": "Host Key",
                "algorithm": algo,
                "severity": "High",
                "detail": _WEAK_HOST_KEY[algo],
                "recommendation": "Remove deprecated host key types from HostKeyAlgorithms",
            })

    # --- cipher ---
    for algo in enc_algos:
        if algo in _WEAK_CIPHER:
            weak_findings.append({
                "category": "Cipher",
                "algorithm": algo,
                "severity": "Medium",
                "detail": _WEAK_CIPHER[algo],
                "recommendation": "Use aes256-gcm@openssh.com or chacha20-poly1305@openssh.com",
            })

    # --- MAC ---
    for algo in mac_algos:
        if algo in _WEAK_MAC:
            weak_findings.append({
                "category": "MAC",
                "algorithm": algo,
                "severity": "Medium",
                "detail": _WEAK_MAC[algo],
                "recommendation": "Use hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com",
            })

    return {
        "hostname":        hostname,
        "port":            port,
        "kex_init":        kex,
        "pqc_indicators":  pqc_indicators,
        "pqc_ready":       bool(pqc_indicators),
        "weak_findings":   weak_findings,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_ssh_server(hostname: str, port: int = 22, timeout: int = 10) -> dict:
    """Connect to *hostname*:*port*, retrieve SSH KEXINIT, and analyse algorithms."""
    result: dict = {"hostname": hostname, "port": port}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            banner = _read_banner(sock)
            result["banner"] = banner

            if not banner.startswith("SSH-"):
                result["error"] = f"Not an SSH service (banner: {banner!r})"
                return result

            if banner.startswith("SSH-1."):
                result["error"] = "SSH-1 detected — obsolete, upgrade to SSH-2 immediately"
                return result

            # Send our version string and KEXINIT
            sock.sendall(b"SSH-2.0-PQCScanner_1.0\r\n")
            sock.sendall(_make_kexinit_packet())

            # Read up to 5 packets to find KEXINIT (msg_type=20)
            kexinit_payload = None
            for _ in range(5):
                try:
                    payload = _read_packet(sock)
                except Exception:
                    break
                if payload and payload[0] == 20:
                    kexinit_payload = payload
                    break

        if kexinit_payload is None:
            result["error"] = "Server did not send SSH_MSG_KEXINIT"
            return result

        kex = _parse_kexinit(kexinit_payload)
        if kex is None:
            result["error"] = "Failed to parse KEXINIT payload"
            return result

        result.update(_analyse_kexinit(kex, hostname, port))

    except (socket.timeout, TimeoutError):
        result["error"] = f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused at {hostname}:{port}"
    except OSError as exc:
        result["error"] = f"Network error: {exc}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


def scan_ssh(
    hostname: str,
    ports: list,
    timestamp,
    suffix: str,
    root: Path,
) -> Optional[Path]:
    from loguru import logger

    results = []
    for port in ports:
        logger.info(f"[SSH] Checking {hostname}:{port} ...")
        res = check_ssh_server(hostname, port)
        if "error" in res:
            logger.warning(f"[SSH] {hostname}:{port} — {res['error']}")
        else:
            tag    = "PQC-HYBRID" if res.get("pqc_ready") else "NOT PQC-READY"
            weak_n = len(res.get("weak_findings", []))
            logger.success(
                f"[SSH] {hostname}:{port} — "
                f"{res.get('banner', '?')} | {tag} | weak_algorithms={weak_n}"
            )
        results.append(res)

    out_dir  = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"6_ssh_check_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"ssh_checks": results}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[SSH] Results saved to: '{out_file}'")
    return out_file

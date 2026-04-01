#!/usr/bin/env python3
"""Port discovery — Stage 0.

Performs a TCP connect scan across a fixed set of cryptography-relevant
ports and a UDP probe on key management / VPN ports.  Results are used
by downstream stages to decide which protocol-specific scanners to run.
"""

import json
import os
import socket
import struct
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Port lists
# ---------------------------------------------------------------------------

# port → service label
_TCP_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1812:  "RADIUS",
    2083:  "RadSec",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",
    6379:  "Redis",
    6380:  "Redis-TLS",
    8443:  "HTTPS-Alt",
    27017: "MongoDB",
}

# port → service label for UDP probes
_UDP_PORTS: dict[int, str] = {
    88:   "Kerberos",
    161:  "SNMP",
    162:  "SNMP-Trap",
    500:  "IKE",
    4500: "IKE-NAT-T",
}

# Single probe byte used for all UDP checks
_UDP_PROBE = b"\x00"


# ---------------------------------------------------------------------------
# TCP connect scan
# ---------------------------------------------------------------------------

def _tcp_scan(hostname: str, ports: dict[int, str], timeout: float) -> dict[str, str]:
    """Return a dict of {str(port): label} for each TCP port that accepts a connection."""
    open_ports: dict[str, str] = {}
    for port, label in ports.items():
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                open_ports[str(port)] = label
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError):
            pass
    return open_ports


# ---------------------------------------------------------------------------
# UDP probe
# ---------------------------------------------------------------------------

def _udp_probe(hostname: str, ports: dict[int, str], timeout: float) -> dict[str, str]:
    """
    Send a single byte to each UDP port and record any port that replies.

    A response (even an ICMP port-unreachable that Python surfaces as an
    OSError with errno ECONNREFUSED) indicates the host is reachable, but
    only an actual data reply is counted as "responsive".
    """
    responsive: dict[str, str] = {}

    try:
        server_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        server_ip = hostname

    for port, label in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.sendto(_UDP_PROBE, (server_ip, port))
            data, _ = sock.recvfrom(4096)
            if data:
                responsive[str(port)] = label
        except (socket.timeout, TimeoutError):
            pass  # no reply — filtered or closed
        except ConnectionRefusedError:
            pass  # ICMP port-unreachable — closed but host alive
        except OSError:
            pass
        finally:
            sock.close()

    return responsive


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_open_ports(
    hostname: str,
    timestamp,
    suffix,
    timeout: float = 1.0,
    root: Optional[Path] = None,
) -> Path:
    """TCP connect scan + UDP probe; save results to output/raw/0_ports_*.json."""
    from loguru import logger

    if root is None:
        root = Path(__file__).resolve().parent.parent

    logger.info(f"[PORTS] Starting port discovery on '{hostname}' (timeout={timeout}s) ...")
    t_start = time.monotonic()

    # TCP
    logger.info(f"[PORTS] TCP scan — {len(_TCP_PORTS)} ports ...")
    tcp_open = _tcp_scan(hostname, _TCP_PORTS, timeout)
    if tcp_open:
        logger.success(
            f"[PORTS] TCP open: "
            + ", ".join(f"{p}/{_TCP_PORTS[int(p)]}" for p in sorted(tcp_open, key=int))
        )
    else:
        logger.warning("[PORTS] TCP — no open ports found")

    # UDP
    logger.info(f"[PORTS] UDP probe — {len(_UDP_PORTS)} ports ...")
    udp_responsive = _udp_probe(hostname, _UDP_PORTS, timeout)
    if udp_responsive:
        logger.success(
            f"[PORTS] UDP responsive: "
            + ", ".join(f"{p}/{_UDP_PORTS[int(p)]}" for p in sorted(udp_responsive, key=int))
        )
    else:
        logger.info("[PORTS] UDP — no responsive ports (all filtered or closed)")

    duration = round(time.monotonic() - t_start, 2)
    logger.info(f"[PORTS] Scan complete in {duration}s")

    result = {
        "target":               hostname,
        "tcp_open":             tcp_open,
        "udp_responsive":       udp_responsive,
        "scan_duration_seconds": duration,
    }

    out_dir = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"0_ports_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps(result, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[PORTS] Results saved to: '{out_file}'")
    return out_file

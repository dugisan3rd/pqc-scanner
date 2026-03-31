#!/usr/bin/env python3
"""Certificate and private-key file scanner — Stage 7.

Walks a directory tree, finds all X.509 certificate files (.pem, .crt,
.cer, .der), parses each with the `cryptography` library, and flags
quantum-weak key algorithms, small key sizes, SHA-1 signatures, and
near-expiry certificates.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Certificate file extensions to look for
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}
_KEY_EXTENSIONS  = {".pem", ".key", ".p8", ".pk8"}

# Directories to skip (performance / irrelevant)
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", "site-packages",
}

# Quantum-weak thresholds  (NIST SP 800-227 / CNSA 2.0)
_RSA_QUANTUM_WEAK_BITS = 3072   # RSA < 3072 → quantum-weak (Shor's algo)
_EC_QUANTUM_WEAK_BITS  = 384    # EC < P-384 → quantum-weak
_DSA_DEPRECATED        = True   # DSA fully deprecated regardless of size


def _import_cryptography():
    """Lazy-import cryptography library with a helpful error if missing."""
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.asymmetric import (
            rsa as _rsa,
            ec as _ec,
            dsa as _dsa,
            ed25519 as _ed25519,
            ed448 as _ed448,
            x25519 as _x25519,
            x448 as _x448,
        )
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_der_private_key,
        )
        from cryptography.exceptions import InvalidSignature
        return _x509, _rsa, _ec, _dsa, _ed25519, _ed448, _x25519, _x448, load_pem_private_key, load_der_private_key
    except ImportError:
        return None


def _key_info(pub_key) -> dict:
    """Extract algorithm name, key size, and quantum risk from a public key object."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448
    except ImportError:
        return {"algorithm": "unknown", "key_bits": None, "quantum_risk": "Unknown"}

    if isinstance(pub_key, rsa.RSAPublicKey):
        bits = pub_key.key_size
        risk = "Sangat Tinggi" if bits < _RSA_QUANTUM_WEAK_BITS else "Tinggi"
        note = f"RSA-{bits}: vulnerable to Shor's algorithm on CRQC"
        return {"algorithm": f"RSA-{bits}", "key_bits": bits, "quantum_risk": risk, "quantum_detail": note}

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve.name
        bits  = pub_key.key_size
        risk  = "Sangat Tinggi" if bits < _EC_QUANTUM_WEAK_BITS else "Tinggi"
        note  = f"EC ({curve}, {bits}-bit): vulnerable to Shor's algorithm on CRQC"
        return {"algorithm": f"EC-{curve}", "key_bits": bits, "quantum_risk": risk, "quantum_detail": note}

    if isinstance(pub_key, dsa.DSAPublicKey):
        bits = pub_key.key_size
        return {"algorithm": f"DSA-{bits}", "key_bits": bits, "quantum_risk": "Sangat Tinggi",
                "quantum_detail": "DSA deprecated (RFC 8813); vulnerable to Shor's algorithm"}

    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_bits": 256, "quantum_risk": "Tinggi",
                "quantum_detail": "Ed25519: classically secure, quantum-weak (Shor's)"}

    if isinstance(pub_key, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_bits": 448, "quantum_risk": "Tinggi",
                "quantum_detail": "Ed448: classically secure, quantum-weak (Shor's)"}

    if isinstance(pub_key, x25519.X25519PublicKey):
        return {"algorithm": "X25519", "key_bits": 256, "quantum_risk": "Tinggi",
                "quantum_detail": "X25519: classically secure, quantum-weak (Shor's)"}

    return {"algorithm": type(pub_key).__name__, "key_bits": None, "quantum_risk": "Unknown"}


def _sig_algo_info(sig_hash_name: str) -> dict:
    """Classify a signature hash algorithm for PQC risk."""
    h = (sig_hash_name or "").lower()
    if "md5"  in h or "md2" in h:
        return {"severity": "Critical", "detail": "MD5/MD2 signature hash — cryptographically broken"}
    if "sha1" in h and "sha1" not in ["sha1-hmac"]:
        return {"severity": "High", "detail": "SHA-1 signature hash — deprecated (NIST 2030)"}
    if "sha256" in h or "sha384" in h or "sha512" in h or "sha3" in h:
        return {"severity": "Info", "detail": f"Signature hash {sig_hash_name} — classically acceptable"}
    return {"severity": "Info", "detail": f"Signature hash: {sig_hash_name}"}


def _parse_cert_pem(data: bytes) -> Optional[dict]:
    """Parse a PEM or DER X.509 certificate and return a metadata dict."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return None

    cert = None
    # Try PEM first, then DER
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(data)
            break
        except Exception:
            continue
    if cert is None:
        return None

    now      = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    days_left = (not_after - now).days

    try:
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value
    except Exception:
        cn = ""

    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value
    except Exception:
        issuer_cn = ""

    try:
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig_algo = "unknown"

    key_info  = _key_info(cert.public_key())
    sig_info  = _sig_algo_info(sig_algo)

    findings = []

    if sig_info["severity"] in ("Critical", "High"):
        findings.append({
            "type":     "Weak Signature Algorithm",
            "severity": sig_info["severity"],
            "detail":   sig_info["detail"],
            "recommendation": "Re-issue certificate with SHA-256 or stronger signature hash",
        })

    if days_left < 0:
        findings.append({
            "type": "Expired Certificate",
            "severity": "Critical",
            "detail": f"Certificate expired {abs(days_left)} days ago",
            "recommendation": "Renew certificate immediately",
        })
    elif days_left < 30:
        findings.append({
            "type": "Certificate Expiring Soon",
            "severity": "High" if days_left < 7 else "Medium",
            "detail": f"Certificate expires in {days_left} days",
            "recommendation": "Schedule certificate renewal",
        })

    # Quantum-weak key
    if key_info.get("quantum_risk") in ("Sangat Tinggi", "Tinggi"):
        findings.append({
            "type":     "Quantum-Weak Public Key",
            "severity": key_info["quantum_risk"],
            "detail":   key_info.get("quantum_detail", ""),
            "recommendation": (
                "Migrate to ML-DSA (CRYSTALS-Dilithium) or Falcon for digital signatures. "
                "Interim: use RSA-3072 or ECDSA P-384 minimum."
            ),
        })

    return {
        "type":            "X.509 Certificate",
        "subject_cn":      cn,
        "issuer_cn":       issuer_cn,
        "not_before":      cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before),
        "not_after":       not_after.isoformat(),
        "days_until_expiry": days_left,
        "signature_algorithm": sig_algo,
        **key_info,
        "findings":        findings,
    }


def _parse_private_key_pem(data: bytes) -> Optional[dict]:
    """Detect a PEM private key and return basic info (no key material extracted)."""
    text = data.decode("utf-8", errors="ignore")
    for marker, algo in [
        ("RSA PRIVATE KEY",    "RSA (PKCS#1)"),
        ("EC PRIVATE KEY",     "EC (SEC1)"),
        ("DSA PRIVATE KEY",    "DSA"),
        ("PRIVATE KEY",        "PKCS#8 (unknown type)"),
        ("OPENSSH PRIVATE KEY","OpenSSH private key"),
    ]:
        if f"-----BEGIN {marker}-----" in text:
            # Try to load and get key size
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                priv = load_pem_private_key(data, password=None)
                info = _key_info(priv.public_key())
                return {
                    "type":    "Private Key",
                    "format":  marker,
                    **info,
                    "findings": [{
                        "type":     "Private Key File Found",
                        "severity": "Critical",
                        "detail":   f"Private key ({info.get('algorithm','?')}) stored as plain file",
                        "recommendation": "Store private keys in HSM or encrypted key store, never as plain files",
                    }],
                }
            except Exception:
                return {
                    "type":    "Private Key",
                    "format":  marker,
                    "algorithm": algo,
                    "findings": [{
                        "type":     "Private Key File Found",
                        "severity": "Critical",
                        "detail":   f"Private key file detected ({algo})",
                        "recommendation": "Store private keys in HSM or encrypted key store",
                    }],
                }
    return None


def scan_certfiles(
    target_path: str,
    timestamp,
    suffix: str,
    root: Path,
) -> Optional[Path]:
    from loguru import logger

    # Quick check that cryptography is available
    if _import_cryptography() is None:
        logger.error("[CERT] 'cryptography' library not installed — skipping cert file scan. Run: pip install cryptography")
        return None

    target = Path(target_path).resolve()
    if not target.exists():
        logger.error(f"[CERT] Target path does not exist: {target}")
        return None

    logger.info(f"[CERT] Scanning certificate/key files under: {target}")

    results = []
    scanned = 0
    skipped = 0

    for file_path in target.rglob("*"):
        # Skip unwanted directories
        if any(part in _SKIP_DIRS for part in file_path.parts):
            continue
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        if ext not in (_CERT_EXTENSIONS | _KEY_EXTENSIONS):
            continue

        try:
            data = file_path.read_bytes()
        except (PermissionError, OSError):
            skipped += 1
            continue

        scanned += 1
        relative = str(file_path.relative_to(target) if file_path.is_relative_to(target) else file_path)

        # Try certificate first, then private key
        parsed = _parse_cert_pem(data) or _parse_private_key_pem(data)

        if parsed:
            entry = {"file": relative, **parsed}
            results.append(entry)
            n_findings = len(parsed.get("findings", []))
            if n_findings:
                logger.warning(
                    f"[CERT] {relative} — {parsed.get('algorithm','?')} — {n_findings} finding(s)"
                )
            else:
                logger.info(f"[CERT] {relative} — {parsed.get('algorithm','?')} — OK")
        else:
            logger.debug(f"[CERT] {relative} — unrecognised or encrypted, skipped")

    total_findings = sum(len(r.get("findings", [])) for r in results)
    logger.success(
        f"[CERT] Scan complete — {scanned} files checked, "
        f"{len(results)} parsed, {total_findings} finding(s), {skipped} skipped (permission denied)"
    )

    out_dir  = root / "output" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"7_cert_files_{timestamp}_{suffix}.json"
    out_file.write_text(
        json.dumps({"cert_file_scan": results, "summary": {
            "files_scanned": scanned, "files_parsed": len(results),
            "total_findings": total_findings,
        }}, indent=2, default=str),
        encoding="utf-8",
    )
    logger.success(f"[CERT] Results saved to: '{out_file}'")
    return out_file

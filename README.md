# PQC Scanner

A 9-stage Post-Quantum Cryptography (PQC) readiness assessment tool. Scans source code, system libraries, TLS/SSH servers, certificate files, and configuration files for weak cryptographic algorithms, then outputs a structured Excel workbook following the **BUKUKERJA BENGKEL MIGRASI PQC 2025** template.

---

## Features

| Stage | What it does |
|-------|--------------|
| 1 — SBOM | Software Bill of Materials via [Syft](https://github.com/anchore/syft) |
| 2 — Vulnerability Assessment | CVE scan of SBOM packages via [Grype](https://github.com/anchore/grype) |
| 3 — PQC System Readiness | OS-level crypto check (OpenSSL, SSH, libs) via [mini-pqc-scanner](https://github.com/mini-pqc/mini-pqc-scanner) |
| 4 — CBOM | Cryptographic Bill of Materials from source code via [Semgrep](https://semgrep.dev) |
| 5 — TLS/SSL Analysis | Live cipher suite, protocol version, certificate expiry, PQC indicator detection |
| 6 — SSH Analysis | Binary SSH_MSG_KEXINIT parsing; flags weak KEX, host-key, cipher, and MAC algorithms |
| 7 — Certificate & Key Files | Recursive directory scan for X.509 certs and private keys; flags quantum-weak key sizes, SHA-1 signatures, expiry |
| 8 — Config File Scan | 35+ regex rules against nginx/Apache/SSH/OpenSSL configs; flags weak protocols, ciphers, disabled TLS verification |
| 9 — Excel Report | Consolidated workbook (BUKUKERJA template) with all findings combined into sheets 0–4 |

### Excel output sheets

| Sheet | Content |
|-------|---------|
| `0_Inventory` | Asset inventory (apps, services, cert files, config files) with readiness level |
| `1_SBOM` | Software components with CVE severity |
| `2_CBOM` | All cryptographic findings — source code + TLS + SSH + certs + configs |
| `3_RiskRegister` | Per-algorithm risk entries in Malay (Kritikal / Tinggi / Sederhana / Rendah) |
| `4_RiskAssessment` | Detailed impact × likelihood assessment with NIST SP 800-227 mitigation plans |
| `5_RiskMatrix` | Static reference — risk score matrix |
| `6_ProtocolCryptoMap` | Static reference — protocol-to-algorithm mapping |
| `00_ReadMe` | Static reference — workbook guide |

---

## Requirements

- Python 3.8+
- External binaries: **Syft**, **Grype**, **mini-pqc-scanner**, **Semgrep**
- A `.env` file with binary paths and Semgrep config (see [Configuration](#configuration))

### Install Python dependencies

```bash
pip install -r requirements.txt
```

### Install Syft and Grype (Linux)

```bash
curl -sSfL https://get.anchore.io/syft  | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
```

On Windows, pre-built Syft and Grype binaries are included under `bin/windows/`.

---

## Configuration

Copy `.env.example` to `.env` and fill in your paths:

```env
# Binary paths (Windows example — adjust for Linux)
WINDOWS_BIN_SYFT=bin/windows/syft/syft.exe
WINDOWS_BIN_GRYPE=bin/windows/grype/grype.exe
WINDOWS_BIN_MINIPQC=bin/mini-pqc-scanner/mini-pqc-scanner.exe
WINDOWS_BIN_SEMGREP=semgrep

# Linux binaries (auto-resolved if installed in PATH)
LINUX_BIN_SYFT=syft
LINUX_BIN_GRYPE=grype
LINUX_BIN_MINIPQC=bin/mini-pqc-scanner/mini-pqc-scanner
LINUX_BIN_SEMGREP=semgrep

# Semgrep ruleset for CBOM detection
SEMGREP_CONF=https://your-semgrep-config-url-or-local-path
```

---

## Usage

### Full scan — source code + server

```bash
# Linux
python3 pqc_auto_scan.py --path /var/www/html --server example.com

# Windows
python3 pqc_auto_scan.py --path "C:\inetpub\wwwroot" --server example.com
```

### Source code only (no server)

```bash
python3 pqc_auto_scan.py --path ./myapp
```

### Custom TLS/SSH ports

```bash
python3 pqc_auto_scan.py --server example.com --ports 443,8443 --ssh-ports 22,2222
```

### Skip individual stages

```bash
# Skip slow stages during development
python3 pqc_auto_scan.py --path ./myapp --skip-va --skip-pqc

# Code-only scan (no server, no cert/config scanning)
python3 pqc_auto_scan.py --path ./myapp --skip-tls --skip-ssh --skip-certs --skip-configs
```

### Custom report filename

```bash
python3 pqc_auto_scan.py --path ./myapp --report-name my_pqc_report.xlsx
```

### All options

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `./testing/DVWA` | Target directory to scan |
| `--server` | *(none)* | Hostname/IP for TLS and SSH checks |
| `--ports` | `443` | Comma-separated HTTPS port(s) |
| `--ssh-ports` | `22` | Comma-separated SSH port(s) |
| `--skip-sbom` | | Skip Stage 1 — SBOM generation |
| `--skip-va` | | Skip Stage 2 — Vulnerability Assessment |
| `--skip-pqc` | | Skip Stage 3 — PQC system readiness |
| `--skip-cbom` | | Skip Stage 4 — CBOM/Semgrep scan |
| `--skip-tls` | | Skip Stage 5 — TLS/SSL server check |
| `--skip-ssh` | | Skip Stage 6 — SSH algorithm analysis |
| `--skip-certs` | | Skip Stage 7 — Certificate/key file scan |
| `--skip-configs` | | Skip Stage 8 — Config file scan |
| `--skip-report` | | Skip Stage 9 — Excel report generation |
| `--report-name` | `pqc_report_<timestamp>.xlsx` | Custom output filename |

---

## Output

All raw scan results are saved to `output/raw/` as timestamped JSON files:

```
output/raw/
  1_syft_sbom_<ts>.json        # SBOM (Syft format)
  2_grype_va_<ts>.json         # Vulnerability matches (Grype format)
  3_mini_pqc_<ts>.json         # PQC system readiness
  4_semgrep_cbom_<ts>.json     # Cryptographic findings (Semgrep format)
  5_tls_check_<ts>.json        # TLS/SSL analysis
  6_ssh_check_<ts>.json        # SSH algorithm analysis
  7_cert_files_<ts>.json       # Certificate and key file findings
  8_config_scan_<ts>.json      # Config file weak-crypto findings
```

The consolidated Excel report is saved to `output/`:

```
output/pqc_report_<timestamp>.xlsx
```

---

## Project structure

```
pqc-scanner/
├── pqc_auto_scan.py               # Main orchestrator (all 9 stages)
├── requirements.txt
├── .env                           # Binary paths + Semgrep config (not committed)
│
├── scripts/
│   ├── scan_1_syft_sbom.py        # Stage 1 — SBOM via Syft
│   ├── scan_2_grype_va.py         # Stage 2 — Vulnerability Assessment via Grype
│   ├── scan_3_mini_pqc.py         # Stage 3 — PQC system readiness via mini-pqc-scanner
│   ├── scan_4_semgrep_static.py   # Stage 4 — CBOM via Semgrep
│   ├── scan_5_ssh.py              # Stage 6 — SSH algorithm analysis
│   ├── scan_6_certfiles.py        # Stage 7 — Certificate & key file scan
│   ├── scan_7_configfiles.py      # Stage 8 — Config file weak-crypto scan
│   │
│   ├── excel2/
│   │   └── pqc_export_full.py     # Stage 9 — Excel report generator
│   │
│   └── utils/
│       ├── setup_binaries.py      # Binary path resolution
│       ├── setup_env.py           # .env loading
│       ├── setup_logging.py       # Loguru logger setup
│       ├── setup_os.py            # OS detection
│       ├── setup_packages.py      # pip dependency installer
│       └── setup_timestamp.py     # Timestamp + random suffix helper
│
├── bin/
│   ├── pqc_migration/
│   │   └── BUKUKERJA_BENGKEL MIGRASI PQC 2025.xlsx   # Excel template
│   ├── mini-pqc-scanner/          # mini-pqc-scanner binary + config
│   └── windows/                   # Pre-built Syft and Grype for Windows
│
├── output/                        # Generated reports (gitignored)
│   └── raw/                       # Raw JSON scan artifacts
│
├── logs/                          # Rotating log files (gitignored)
└── testing/
    └── DVWA/                      # Default test target (Damn Vulnerable Web App)
```

---

## PQC risk classification

| Risk Level | Algorithms | Reason |
|------------|-----------|--------|
| **Sangat Tinggi** (Very High) | RSA, ECDSA, ECDH, DSA, DH, MD5, SHA-1, RC4, DES/3DES | Broken classically or broken by Shor/Grover |
| **Tinggi** (High) | RSA-2048, EC P-256 | Vulnerable to Shor on a CRQC (~4096 logical qubits) |
| **Sederhana** (Medium) | AES-128, SHA-256 | Grover halves effective key strength |
| **Rendah** (Low) | AES-256, SHA-512 | Safe with doubled key sizes per NIST SP 800-227 |
| **PQC Ready** | ML-KEM, ML-DSA, SLH-DSA | NIST FIPS 203/204/205 standardised algorithms |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `openpyxl` | Excel workbook generation |
| `python-dotenv` | `.env` file loading |
| `loguru` | Structured logging with file rotation |
| `semgrep` | Semgrep binary (CBOM ruleset execution) |
| `cryptography` | X.509 certificate and private key parsing |

External binaries (not Python packages): **Syft**, **Grype**, **mini-pqc-scanner**

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes and test against `./testing/DVWA`
4. Submit a pull request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Syft](https://github.com/anchore/syft) — SBOM generation
- [Grype](https://github.com/anchore/grype) — Vulnerability assessment
- [mini-pqc-scanner](https://github.com/mini-pqc/mini-pqc-scanner) — PQC system readiness
- [Semgrep](https://semgrep.dev) — Static code analysis for CBOM
- NIST SP 800-227 — PQC migration guidance

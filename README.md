# PQC Auto Server Scanner

The PQC Auto Server Scanner is a tool designed for automating a full Post-Quantum Cryptography (PQC) readiness assessment on a server. It conducts various scans to evaluate the security posture of your systems in the context of quantum-resilient cryptography.

## Features

- **SBOM Generation**: Software Bill of Materials (SBOM) using Syft.
- **Vulnerability Assessment**: Scans for known vulnerabilities using Grype.
- **PQC System Readiness**: Assess your system for quantum-resilient cryptographic algorithms.
- **CBOM**: Cryptographic Bill of Materials using Semgrep.
- **TLS/SSL Analysis**: Analyze the TLS configuration and check for weak ciphers, deprecated protocols, and PQC readiness.
- **SSH Algorithm Analysis**: Analyze the algorithms used by SSH servers.
- **Certificate/Key File Scan**: Scan for weak or deprecated certificates and keys.
- **Config File Scan**: Check for weak cryptography configurations.
- **Excel Report Generation**: Generate a detailed Excel report summarizing all findings.

## Installation

### Requirements

- Python 3.8+
- Required packages listed in `requirements.txt`
- Syft, Grype, Mini-PQC Scanner, Semgrep, and other binaries (automatically handled by the tool)

### Clone the repository

```bash
git clone https://github.com/dugisan3rd/pqc-scanner.git
cd pqc-scanner

# Install dependencies
pip install -r requirements.txt

# Install the required binaries (Syft, Grype, etc.)
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
```

# Usage
## Full scan (local code + server TLS check)
### Linux:
```bash
python3 pqc_auto_scan.py --path /var/www/html --server example.com
```

### Windows:
```bash
python3 pqc_auto_scan.py --path "C:\\inetpub\\wwwroot" --server example.com
```

# Output
The results from each stage will be displayed in the terminal and saved into an Excel file. The Excel file will include the following stages:

SBOM: Software Bill of Materials scan results.
VA: Vulnerability assessment results.
PQC: Post-Quantum Cryptography readiness.
CBOM: Cryptographic Bill of Materials.
TLS: TLS/SSL analysis results.
SSH: SSH algorithm analysis.
Certs: Certificate and key file scan results.
Config: Weak cryptographic configurations.
Report: A detailed Excel report with all findings.

# Contributing
Contributions are welcome! If you would like to improve the pqc-scanner tool or add new features, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Make your changes.
4. Test your changes.
5. Submit a pull request.

# License
This project is licensed under the MIT License.

# Acknowledgments
The pqc-scanner tool leverages several open-source libraries and binaries including Syft, Grype, Mini-PQC Scanner, and Semgrep. Thanks to the developers of these tools for making this project possible.

# Known Issues
Some system environments may require additional configuration for binaries (e.g., Syft, Grype).
PQC readiness is a developing area, and some results may not be 100% accurate for all systems.
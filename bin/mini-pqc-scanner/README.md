# Mini PQC Scanner

## The Quantum Threat is Real - Are You Ready?

Post-Quantum Cryptography (PQC) represents the next evolution in cybersecurity, designed to protect against the imminent threat of quantum computers that will render current encryption methods obsolete. With quantum computers advancing rapidly and NIST standardizing PQC algorithms in 2024, organizations must act **now** to assess and upgrade their cryptographic infrastructure.

**Why PQC Matters:**
- **Quantum computers will break RSA, ECDSA, and ECDH** - the foundation of today's internet security
- **"Harvest now, decrypt later" attacks** are already happening - adversaries are collecting encrypted data today to decrypt once quantum computers are available
- **NIST has standardized PQC algorithms** (ML-KEM, ML-DSA, SLH-DSA) - the migration window is closing
- **Regulatory compliance** requirements are emerging globally for quantum-safe cryptography

Mini PQC Scanner is a streamlined, command-line tool that helps organizations assess their quantum readiness by scanning systems, services, and cryptographic implementations. This lightweight version focuses on core scanning functionality, making it perfect for automated assessments, CI/CD integration, and rapid security audits.

**Enterprise Solutions:** For comprehensive PQC migration planning, automated remediation, and enterprise-grade reporting, explore our full PQC platform at [quantumcrafts.ai](https://quantumcrafts.ai). Our enterprise version includes advanced features like automated certificate management, policy enforcement, compliance reporting, and guided migration workflows.

## Overview

Mini PQC Scanner is a command-line tool that audits systems for post-quantum cryptography readiness. It performs comprehensive scans of various system components including:

- **Environment** - System environment and security settings
- **Firmware** - Firmware security configurations  
- **Kernel** - Linux kernel PQC support
- **Libraries** - Cryptographic library analysis
- **Certificate Authority** - CA configuration assessment
- **Runtime** - Runtime environment PQC readiness
- **Network Services** - OpenSSH, OpenVPN, IPsec, WireGuard
- **Web Services** - Nginx, Apache configurations
- **Mail Services** - Postfix configuration
- **Certificates** - Certificate parsing and analysis
- **PGP** - PGP/GPG configuration assessment
- **TLS** - TLS handshake analysis
- **Network Traffic** - tcpdump-based traffic analysis

## Features

- **CLI-only Interface** - Pure command-line operation with optional TUI
- **Comprehensive Scanning** - Multiple security modules
- **JSON Output** - Machine-readable output format
- **Interactive Mode** - Built-in terminal UI for interactive use
- **Batch Mode** - Single command execution for automation

## Installation

### Build from Source

```bash
# Clone or extract the mini-pqc repository
cd mini-pqc

# Install dependencies
make deps

# Build the binary
make build

# The binary will be available at ./bin/mini-pqc-scanner
```

### Cross-Platform Builds

```bash
# Build for Linux
make build-linux

# Build for Windows  
make build-windows

# Build for macOS
make build-mac

# Build for all platforms
make build-all-platforms
```

## Usage

### Interactive Mode

Run without arguments to start the interactive TUI:

```bash
./bin/mini-pqc-scanner
```

This launches a terminal UI with:
- **Left Panel**: CLI input/output
- **Right Panel**: Recommendations and results
- **Tab Navigation**: Switch between panels

### Command Line Mode

Execute specific commands directly:

```bash
# Show version
./bin/mini-pqc-scanner version

# Show help
./bin/mini-pqc-scanner help

# Run environment scan
./bin/mini-pqc-scanner env

# Run comprehensive scan
./bin/mini-pqc-scanner all

# Run with JSON output
./bin/mini-pqc-scanner env -json
```

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `version` | Display version information |
| `config` | Configure scanner settings |
| `env` | Check environment security |
| `firmware` | Check firmware security |
| `kernel` | Check kernel PQC support |
| `lib` | Test cryptographic libraries |
| `ca` | Check Certificate Authority config |
| `runtime` | Check runtime environment |
| `openssh` | Check OpenSSH configuration |
| `openvpn` | Check OpenVPN configuration |
| `ipsec` | Check IPsec configuration |
| `wireguard` | Check WireGuard configuration |
| `nginx` | Check Nginx configuration |
| `apache` | Check Apache configuration |
| `postfix` | Check Postfix configuration |
| `pgp` | Check PGP configuration |
| `parsecrt` | Parse and analyze certificates |
| `tls` | Test TLS configuration |
| `tcpdump` | Network traffic analysis and PQC readiness |
| `all` | Run all scan modules |

### Configuration

First-time setup requires configuration:

```bash
./bin/mini-pqc-scanner config
```

This will prompt for:
- Organization name
- License key (if applicable)
- Other scanner settings

### JSON Output
Machine-readable format for automation:

```bash
./bin/mini-pqc-scanner env -json
```

## Examples

### Basic System Scan
```bash
# Quick environment check
./bin/mini-pqc-scanner env

# Check kernel PQC support
./bin/mini-pqc-scanner kernel

# Analyze certificates
./bin/mini-pqc-scanner parsecrt -verbose
```

### Comprehensive Assessment
```bash
# Run all modules with JSON output
./bin/mini-pqc-scanner all -json > pqc-report.json

# Test specific service
./bin/mini-pqc-scanner openssh
./bin/mini-pqc-scanner nginx
```

### Network Analysis
```bash
# Test TLS configuration
./bin/mini-pqc-scanner tls example.com

# Check tcpdump capabilities and PQC readiness
./bin/mini-pqc-scanner tcpdump

# Capture network traffic (requires sudo)
./bin/mini-pqc-scanner tcpdump -dump

# Parse captured traffic from default location
./bin/mini-pqc-scanner tcpdump -parse

# Parse specific capture file
./bin/mini-pqc-scanner tcpdump -parse -f /path/to/capture.pcap

# List available network interfaces
./bin/mini-pqc-scanner tcpdump -list
```

### tcpdump Module Details

The tcpdump module provides network traffic analysis for PQC readiness assessment:

#### Basic Usage
```bash
# Check tcpdump installation and capabilities
./bin/mini-pqc-scanner tcpdump
```
This command:
- Verifies tcpdump and tshark installation
- Checks protocol support (TLS, SSH, IPsec, QUIC)
- Reports version information
- Identifies missing PQC-relevant capabilities

#### Traffic Capture
```bash
# Capture network traffic (requires sudo privileges)
./bin/mini-pqc-scanner tcpdump -dump
```
This command:
- Captures encrypted traffic for 30 seconds by default
- Monitors ports: 443, 8443, 22, 500, 4500, 51820, 25, 465, 587, 993, 995
- Saves capture to `./dump/` directory with timestamp
- Limits file size to 1MB maximum
- Requires sudo access for packet capture

**Note**: To avoid sudo prompts, run:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

#### Traffic Analysis
```bash
# Parse most recent capture file
./bin/mini-pqc-scanner tcpdump -parse

# Parse specific capture file
./bin/mini-pqc-scanner tcpdump -parse -f /path/to/capture.pcap
```
This command:
- Analyzes TLS handshakes for PQC readiness
- Identifies non-quantum-resistant algorithms
- Reports cipher suites and key exchange methods
- Provides recommendations for PQC migration

#### Advanced Options
```bash
# List network interfaces
./bin/mini-pqc-scanner tcpdump -list

# Extended capture with process tracking (if BCC tools installed)
./bin/mini-pqc-scanner tcpdump -dump -process-track -s 60
```

## Development

### Project Structure

```
mini-pqc/
├── cmd/                    # Main application and CLI commands
│   ├── main.go            # Application entry point
│   └── commands/linux/    # Linux-specific command implementations
├── scan/                  # Core scanning functionality
├── rules/                 # PQC rules and definitions
├── config/                # Configuration sample
├── pkg/config/           # Configuration management
├── bin/                  # Built binaries
├── version/              # Version tracking
├── Makefile              # Build configuration
├── go.mod                # Go module definition
└── README.md             # This file
```

### Building

```bash
# Clean and rebuild
make clean && make build

# Run tests
make test

# Install to GOPATH/bin
make install
```

### Version Management

The build system automatically increments version numbers when source code changes are detected. Version information is stored in `version/scanner_version`.

## Differences from Full PQC Scanner

This mini version excludes:
- **Web Interface** - No webapp or webui components
- **Docker Testing** - No docker-test framework
- **A2A Server** - No agent-to-agent communication
- **CBOM Tools** - No Crypto Bill of Materials functionality
- **Deployment Scripts** - No remote installation scripts
- **Package Management** - Simplified pkg structure

## Requirements

- **Go 1.23.0+** for building from source
- **Linux Environment** for full functionality
- **Root/Sudo Access** for some system-level scans
- **Network Access** for external service testing

## License

See LICENSE file for licensing information.

## Support

Feel free to contact us at quantumcrafts.ai

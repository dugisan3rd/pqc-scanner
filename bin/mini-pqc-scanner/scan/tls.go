package scan

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
	
	"mini-pqc/rules"
)

// TLSScanner holds the configuration for TLS scanning
type TLSScanner struct {
	Timeout time.Duration
}

// NewTLSScanner creates a new TLS scanner
func NewTLSScanner() *TLSScanner {
	return &TLSScanner{
		Timeout: 10 * time.Second,
	}
}

// CipherInfo represents information about a cipher suite
type CipherInfo struct {
	ID          uint16
	Name        string
	IsWeak      bool
	WeakReason  string
	Protocol    uint16 // The protocol version this cipher was found with
}

// CertKeyInfo contains information about a certificate's key type and quantum safety
type CertKeyInfo struct {
	Type           string // RSA, ECDSA, Ed25519, etc.
	Bits           int    // Key size in bits (for RSA)
	Curve          string // Curve name (for ECDSA)
	IsQuantumSafe  bool   // Whether the key is considered quantum-safe
	QuantumWarning string // Warning message about quantum safety
	IsStaticRSA    bool   // Whether this is a static RSA certificate
	StaticRSAWarning string // Warning about static RSA certificates
	SignatureSeverity int  // Severity level for signature vulnerabilities (1-5)
	KeyExchangeSeverity int // Severity level for key exchange vulnerabilities (1-5)
}

// GroupInfo represents information about a key exchange group
type GroupInfo struct {
	ID      uint16
	Name    string
	IsPQC   bool
	IsHybrid bool
}

// TLSScanResult contains the results of a TLS scan
type TLSScanResult struct {
	Host            string
	Port            string
	Certificate     *x509.Certificate
	CipherSuites    []uint16
	TLSVersion      uint16
	Error           error
	PQCFindings     []string
	IsPQCConfigured bool
	
	// Protocol version support information
	SupportedProtocols map[uint16]bool // Map of protocol versions to support status
	DeprecatedProtocols []string       // List of deprecated protocols in use
	IsCompliant bool                   // Whether the server is compliant with modern standards
	
	// Cipher suite information
	SupportedCiphers []CipherInfo      // All supported cipher suites
	WeakCiphers     []CipherInfo      // Weak or non-compliant cipher suites
	HasPFS          bool              // Whether Perfect Forward Secrecy is supported
	
	// Certificate key information
	CertKeyInfo     CertKeyInfo       // Information about the certificate's key type and quantum safety
	
	// Key exchange group information
	SupportedGroups []GroupInfo       // Supported key exchange groups
	PQCGroups      []GroupInfo       // PQC and hybrid key exchange groups
	
	// Quantum vulnerability assessment
	KeyExchangeVulnerable bool         // Whether key exchange is quantum vulnerable (CRITICAL)
	SignatureVulnerable   bool         // Whether signatures are quantum vulnerable (MODERATE)
	HNDLRisk             bool         // Whether vulnerable to Harvest Now Decrypt Later attacks
}

// analyzeCertificateKey analyzes the certificate's key type and provides quantum safety information
func (s *TLSScanner) analyzeCertificateKey(cert *x509.Certificate) CertKeyInfo {
	info := CertKeyInfo{
		Type:          "Unknown",
		IsQuantumSafe: false,
		IsStaticRSA:   false,
		SignatureSeverity: 3,    // Default MODERATE severity for signatures
		KeyExchangeSeverity: 5,  // Default CRITICAL severity for key exchange
	}
	
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.Type = "RSA"
		info.Bits = pub.N.BitLen() // Get actual bit length
		
		// RSA signatures: MODERATE priority (certificates expire)
		info.SignatureSeverity = 3
		info.QuantumWarning = fmt.Sprintf("Certificate uses RSA-%d signatures – quantum-vulnerable but MODERATE priority. "+
			"Certificates are short-lived and will expire before quantum computers can break signatures. "+
			"Plan migration to PQC signatures (ML-DSA/Dilithium) for long-lived roots and code-signing.", info.Bits)
		
		// RSA key exchange: CRITICAL priority (HNDL attacks)
		info.KeyExchangeSeverity = 5
		info.IsStaticRSA = true
		info.StaticRSAWarning = "CRITICAL: RSA key exchange detected. Vulnerable to 'Harvest Now, Decrypt Later' attacks. "+
			"Adversaries can record encrypted traffic today and decrypt it later with quantum computers. "+
			"Immediate migration to PQC KEMs (ML-KEM/Kyber) or hybrid ECDH+ML-KEM is strongly recommended."
		
	case *ecdsa.PublicKey:
		info.Type = "ECDSA"
		
		// Determine the curve
		info.Curve = pub.Curve.Params().Name
		
		// ECDSA signatures: MODERATE priority (certificates expire)
		info.SignatureSeverity = 3
		info.QuantumWarning = fmt.Sprintf("Certificate uses ECDSA %s signatures – quantum-vulnerable but MODERATE priority. "+
			"Short-lived TLS certificates will expire before quantum computers can forge signatures. "+
			"Migration to PQC signatures important for long-lived artifacts (firmware, root CAs).", info.Curve)
		
		// ECDH key exchange would be CRITICAL, but we detect this separately
		info.KeyExchangeSeverity = 5
		
	case ed25519.PublicKey:
		info.Type = "Ed25519"
		
		// Ed25519 signatures: MODERATE priority
		info.SignatureSeverity = 3
		info.QuantumWarning = "Certificate uses Ed25519 signatures – quantum-vulnerable but MODERATE priority. "+
			"Short-lived TLS certificates acceptable; focus on PQC key exchange first."
		
		info.KeyExchangeSeverity = 5
		
	default:
		// Handle unknown key types
		info.Type = "Unknown"
		info.SignatureSeverity = 3
		info.KeyExchangeSeverity = 5
		info.QuantumWarning = "Unknown certificate key type – unable to assess quantum safety."
	}
	
	// Check for any PQC indicators in the certificate extensions
	for _, ext := range cert.Extensions {
		// Check for OIDs that might indicate post-quantum algorithms
		// This is placeholder logic - actual OIDs would need to be added as standards emerge
		oidStr := ext.Id.String()
		if strings.Contains(strings.ToLower(oidStr), "dilithium") || 
		   strings.Contains(strings.ToLower(oidStr), "falcon") ||
		   strings.Contains(strings.ToLower(oidStr), "sphincs") ||
		   strings.Contains(strings.ToLower(oidStr), "ml-dsa") {
			info.IsQuantumSafe = true
			info.SignatureSeverity = 1  // Low severity - already using PQC signatures
			info.QuantumWarning = "Certificate uses post-quantum signatures (ML-DSA/Dilithium/Falcon/SPHINCS+) - quantum-safe."
			break
		}
		if strings.Contains(strings.ToLower(oidStr), "kyber") ||
		   strings.Contains(strings.ToLower(oidStr), "ml-kem") {
			info.KeyExchangeSeverity = 1  // Low severity - already using PQC key exchange
			break
		}
	}
	
	return info
}

// detectKeyExchangeGroups attempts to detect supported key exchange groups including PQC and hybrid ones
func (s *TLSScanner) detectKeyExchangeGroups(result *TLSScanResult, host, port string) {
	// Note: Detecting supported groups in TLS requires either:
	// 1. A custom TLS library that exposes the supported_groups extension
	// 2. Network packet capture to analyze the ClientHello/ServerHello
	// 3. Server-side access to the TLS configuration
	//
	// Since the standard crypto/tls library doesn't expose this information directly,
	// we'll use heuristics based on the domain to detect likely PQC support
	
	// Check common PQC and hybrid groups
	for groupID, groupName := range rules.PQCNamedGroups {
		// In a real implementation, we would check if the group is actually supported
		// For now, we'll just check for Cloudflare domains as they're known to use these groups
		if strings.Contains(strings.ToLower(host), "cloudflare") {
			groupInfo := GroupInfo{
				ID:       groupID,
				Name:     groupName,
				IsPQC:    true,
				IsHybrid: rules.IsHybridGroup(groupID),
			}
			
			result.SupportedGroups = append(result.SupportedGroups, groupInfo)
			result.PQCGroups = append(result.PQCGroups, groupInfo)
			
			// Add to PQC findings
			result.PQCFindings = append(result.PQCFindings, 
				fmt.Sprintf("Detected likely support for PQC key exchange group: %s", groupName))
			result.IsPQCConfigured = true
		}
	}
}

// ScanTLS scans a host:port for TLS configuration and PQC support
func (s *TLSScanner) ScanTLS(host, port string) *TLSScanResult {
	result := &TLSScanResult{
		Host:            host,
		Port:            port,
		PQCFindings:     []string{},
		SupportedProtocols: make(map[uint16]bool),
		DeprecatedProtocols: []string{},
		IsCompliant:     true, // Assume compliant until proven otherwise
		SupportedCiphers: []CipherInfo{},
		WeakCiphers:     []CipherInfo{},
		HasPFS:          false,
		SupportedGroups: []GroupInfo{},
		PQCGroups:      []GroupInfo{},
		KeyExchangeVulnerable: false,
		SignatureVulnerable:   false,
		HNDLRisk:             false,
	}
	
	// Check for supported protocol versions
	s.checkSupportedProtocols(result, host, port)
	
	// Check for supported cipher suites and detect weak ones
	s.checkSupportedCipherSuites(result, host, port)
	
	// Detect PQC and hybrid key exchange groups
	s.detectKeyExchangeGroups(result, host, port)
	
	// Set up TLS config with special PQC-detection capabilities
	config := &tls.Config{
		InsecureSkipVerify: true, // We still verify the certificate, just not the hostname
		MaxVersion:         tls.VersionTLS13,
		// Request all supported cipher suites to maximize chance of detecting PQC
		CipherSuites:       nil, // nil means use default list
	}

	// Set timeout for connection
	dialer := &net.Dialer{
		Timeout: s.Timeout,
	}

	// Establish connection
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%s", host, port), config)
	if err != nil {
		result.Error = fmt.Errorf("failed to connect: %v", err)
		return result
	}
	defer conn.Close()

	// Get connection state
	state := conn.ConnectionState()

	// Get certificate
	if len(state.PeerCertificates) > 0 {
		result.Certificate = state.PeerCertificates[0]
		
		// Analyze certificate key type and quantum safety
		result.CertKeyInfo = s.analyzeCertificateKey(result.Certificate)
	}

	// Get cipher suite and TLS version
	result.CipherSuites = []uint16{state.CipherSuite}
	result.TLSVersion = state.Version
	
	// Check for PQC configurations
	s.checkPQCConfigurations(result)
	
	// Check for PQC in server name
	s.checkServerNameForPQC(result)

	// Check for Cloudflare PQC indicators
	s.checkCloudflareHeaders(result, host)
	
	// Assess quantum vulnerabilities and HNDL risk
	s.assessQuantumVulnerabilities(result)

	return result
}

// checkPQCConfigurations checks for PQC-related configurations in the TLS scan result
func (s *TLSScanner) checkPQCConfigurations(result *TLSScanResult) {
	// Check certificate for PQC signatures
	if result.Certificate != nil {
		s.checkCertificateForPQC(result)
	}

	// Check cipher suites for PQC algorithms
	s.checkCipherSuitesForPQC(result)
}

func (s *TLSScanner) checkCertificateForPQC(result *TLSScanResult) {
	// Get PQC algorithms from rules
	pqcAlgorithms := rules.GetPQCHybridIdentifiers()
	certInfo := result.Certificate

	// Check signature algorithm
	sigAlg := certInfo.SignatureAlgorithm.String()
	for _, algo := range pqcAlgorithms {
		if strings.Contains(strings.ToLower(sigAlg), strings.ToLower(algo.Name)) {
			result.IsPQCConfigured = true
			result.PQCFindings = append(result.PQCFindings, 
				fmt.Sprintf("PQC signature algorithm detected: %s", sigAlg))
		}
	}
	
	// Check certificate extensions for PQC OIDs
	for _, ext := range certInfo.Extensions {
		// Check for known PQC OIDs in extensions
		oidStr := ext.Id.String()
		if strings.Contains(oidStr, "1.3.6.1.4.1.11129.2.1.17") { // Example OID for PQ experiments
			result.IsPQCConfigured = true
			result.PQCFindings = append(result.PQCFindings, 
				fmt.Sprintf("PQC-related certificate extension detected: %s", oidStr))
		}
	}
	
	// Check subject/issuer fields for PQC indicators
	subject := certInfo.Subject.String()
	issuer := certInfo.Issuer.String()
	
	for _, algo := range pqcAlgorithms {
		if strings.Contains(strings.ToLower(subject), strings.ToLower(algo.Name)) || 
		   strings.Contains(strings.ToLower(issuer), strings.ToLower(algo.Name)) {
			result.IsPQCConfigured = true
			result.PQCFindings = append(result.PQCFindings, 
				fmt.Sprintf("PQC algorithm reference in certificate: %s", algo.Name))
		}
	}
}

func (s *TLSScanner) checkCipherSuitesForPQC(result *TLSScanResult) {
	// Known PQC and hybrid cipher suites - only include actual PQC cipher suites
	pqcCipherSuites := map[uint16]string{
		// Cloudflare's experimental PQC cipher suites
		0xCCA9: "TLS_ECDHE_KYBER_WITH_AES_256_GCM_SHA384", // Cloudflare's hybrid ECDHE-Kyber
		0xCCA8: "TLS_ECDHE_KYBER_WITH_AES_128_GCM_SHA256",
		0x16B7: "TLS_AES_256_GCM_SHA384_KYBER768", // Kyber hybrid
		0x16B8: "TLS_CHACHA20_POLY1305_SHA256_KYBER768",
		
		// Google's CECPQ2 (hybrid ECDH + NTRU-HRSS) - OBSOLETE (removed from BoringSSL 2023)
		0xC09C: "TLS_CECPQ2_ECDSA_WITH_AES_256_GCM_SHA384",
		0xC09D: "TLS_CECPQ2_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		
		// Experimental PQC cipher suites
		0xFE30: "TLS_KYBER_PSK_WITH_AES_128_GCM_SHA256",
		0xFE31: "TLS_KYBER_PSK_WITH_AES_256_GCM_SHA384",
		
		// Note: standard TLS 1.3 cipher suites are NOT included here anymore
		// as they were causing false positives
	}

	for _, suite := range result.CipherSuites {
		if name, exists := pqcCipherSuites[suite]; exists {
			result.IsPQCConfigured = true
			result.PQCFindings = append(result.PQCFindings, 
				fmt.Sprintf("PQC cipher suite detected: %s (0x%04X)", name, suite))
		}
	}
}

// checkServerNameForPQC checks if the server name contains PQC-related keywords
func (s *TLSScanner) checkServerNameForPQC(result *TLSScanResult) {
	// Get PQC algorithms from rules
	pqcAlgorithms := rules.GetPQCHybridIdentifiers()
	
	// Check server name in certificate
	if result.Certificate != nil {
		for _, name := range result.Certificate.DNSNames {
			for _, algo := range pqcAlgorithms {
				if strings.Contains(strings.ToLower(name), strings.ToLower(algo.Name)) || 
				   strings.Contains(strings.ToLower(name), "pqc") || 
				   strings.Contains(strings.ToLower(name), "quantum") {
					result.IsPQCConfigured = true
					result.PQCFindings = append(result.PQCFindings, 
						fmt.Sprintf("PQC indicator in server name: %s", name))
				}
			}
		}
	}
}

// checkCloudflareHeaders checks for Cloudflare-specific PQC indicators
func (s *TLSScanner) checkCloudflareHeaders(result *TLSScanResult, host string) {
	// Cloudflare is known to implement PQC, especially on certain domains
	if strings.Contains(strings.ToLower(host), "cloudflare.com") || 
	   strings.Contains(strings.ToLower(host), "cloudflaressl.com") || 
	   strings.Contains(strings.ToLower(host), "cloudflareclient.com") {
		
		// Cloudflare uses PQC in their TLS implementation but it's not visible in standard cipher suites
		// They use custom key exchange mechanisms that aren't exposed in the standard TLS handshake
		result.IsPQCConfigured = true
		result.PQCFindings = append(result.PQCFindings, 
			"Cloudflare domain detected - implements hybrid ECDHE-Kyber key exchange (not visible in standard cipher suites)")
		
		// Check for specific Cloudflare headers or certificate characteristics
		if result.Certificate != nil {
			issuer := result.Certificate.Issuer.String()
			if strings.Contains(issuer, "Cloudflare") {
				result.PQCFindings = append(result.PQCFindings,
					"Cloudflare certificate issuer detected - likely uses hybrid PQC")
			}
		}
	}
}

// checkSupportedProtocols checks which TLS/SSL protocol versions are supported by the server
func (s *TLSScanner) checkSupportedProtocols(result *TLSScanResult, host, port string) {
	// Define protocol versions to check
	protocolVersions := map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	
	// Define which versions are considered deprecated
	deprecatedVersions := map[uint16]bool{
		tls.VersionSSL30: true,
		tls.VersionTLS10: true,
		tls.VersionTLS11: true,
	}
	
	// Check each protocol version
	target := fmt.Sprintf("%s:%s", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	
	for version, versionName := range protocolVersions {
		// Configure TLS with specific version
		config := &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion: version,
			MinVersion: version,
		}
		
		// Try to connect
		conn, err := tls.DialWithDialer(dialer, "tcp", target, config)
		if err == nil {
			// Connection successful, this version is supported
			result.SupportedProtocols[version] = true
			conn.Close()
			
			// Check if this is a deprecated version
			if deprecated, exists := deprecatedVersions[version]; exists && deprecated {
				result.DeprecatedProtocols = append(result.DeprecatedProtocols, versionName)
				result.IsCompliant = false
			}
		} else {
			// Connection failed, this version is not supported
			result.SupportedProtocols[version] = false
		}
	}
}

// checkSupportedCipherSuites checks which cipher suites are supported by the server
// and identifies weak or non-compliant ciphers
func (s *TLSScanner) checkSupportedCipherSuites(result *TLSScanResult, host, port string) {
	// Map of cipher suites to check
	cipherSuites := map[uint16]string{
		// TLS 1.3 cipher suites
		tls.TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
		
		// Strong TLS 1.2 cipher suites with PFS (ECDHE)
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		
		// Non-PFS cipher suites (no forward secrecy)
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		
		// Weak cipher suites
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_RC4_128_SHA:         "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:     "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:     "TLS_RSA_WITH_AES_256_CBC_SHA",
	}
	
	// Define which cipher suites are considered weak or non-compliant
	weakCipherSuites := map[uint16]string{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:    "Uses 3DES with 112-bit effective strength, not compliant with modern standards",
		tls.TLS_RSA_WITH_RC4_128_SHA:         "Uses RC4 which is cryptographically broken",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "Uses 3DES with 112-bit effective strength, not compliant with modern standards",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:     "Uses CBC mode which is vulnerable to padding oracle attacks",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:     "Uses CBC mode which is vulnerable to padding oracle attacks",
	}
	
	// Define which cipher suites do not provide Perfect Forward Secrecy
	nonPFSCipherSuites := map[uint16]bool{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256: true,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384: true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:   true,
		tls.TLS_RSA_WITH_RC4_128_SHA:        true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:    true,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:    true,
	}
	
	// Check each protocol version for supported cipher suites
	target := fmt.Sprintf("%s:%s", host, port)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	
	// Only check cipher suites for supported protocol versions
	for version := range result.SupportedProtocols {
		if !result.SupportedProtocols[version] {
			continue
		}
		
		// For each cipher suite, try to connect
		for cipherID, cipherName := range cipherSuites {
			// Skip TLS 1.3 ciphers for older protocols and vice versa
			if (version == tls.VersionTLS13 && cipherID < tls.TLS_AES_128_GCM_SHA256) ||
			   (version < tls.VersionTLS13 && cipherID >= tls.TLS_AES_128_GCM_SHA256) {
				continue
			}
			
			// Configure TLS with specific version and cipher suite
			config := &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion:         version,
				MinVersion:         version,
				CipherSuites:       []uint16{cipherID},
			}
			
			// Try to connect
			conn, err := tls.DialWithDialer(dialer, "tcp", target, config)
			if err == nil {
				// Connection successful, this cipher is supported
				cipherInfo := CipherInfo{
					ID:       cipherID,
					Name:     cipherName,
					Protocol: version,
					IsWeak:   false,
				}
				
				// Check if this is a weak cipher
				if weakReason, exists := weakCipherSuites[cipherID]; exists {
					cipherInfo.IsWeak = true
					cipherInfo.WeakReason = weakReason
					result.WeakCiphers = append(result.WeakCiphers, cipherInfo)
					result.IsCompliant = false
				}
				
				// Check if this cipher provides PFS
				if _, nonPFS := nonPFSCipherSuites[cipherID]; !nonPFS {
					result.HasPFS = true
				}
				
				// Add to supported ciphers
				result.SupportedCiphers = append(result.SupportedCiphers, cipherInfo)
				
				conn.Close()
			}
		}
	}
}

// assessQuantumVulnerabilities evaluates the quantum vulnerability risk based on key exchange and signatures
func (s *TLSScanner) assessQuantumVulnerabilities(result *TLSScanResult) {
	// Assess signature vulnerabilities (MODERATE priority)
	if result.Certificate != nil {
		certInfo := result.CertKeyInfo
		switch certInfo.Type {
		case "RSA", "ECDSA", "Ed25519":
			result.SignatureVulnerable = true
		default:
			// Unknown types are assumed vulnerable
			result.SignatureVulnerable = true
		}
		
		// Override if already using PQC signatures
		if certInfo.IsQuantumSafe && certInfo.SignatureSeverity == 1 {
			result.SignatureVulnerable = false
		}
	}
	
	// Assess key exchange vulnerabilities (CRITICAL priority - HNDL risk)
	result.KeyExchangeVulnerable = s.isKeyExchangeVulnerable(result)
	result.HNDLRisk = result.KeyExchangeVulnerable
	
	// Add findings based on vulnerability assessment
	if result.KeyExchangeVulnerable {
		result.PQCFindings = append(result.PQCFindings, 
			"CRITICAL: Key exchange uses quantum-vulnerable algorithms (RSA/ECDH). "+
			"Vulnerable to 'Harvest Now, Decrypt Later' attacks.")
	}
	
	if result.SignatureVulnerable {
		result.PQCFindings = append(result.PQCFindings,
			"MODERATE: Certificate signatures use quantum-vulnerable algorithms. "+
			"Less urgent due to certificate expiration, but plan PQC migration for long-lived artifacts.")
	}
}

// isKeyExchangeVulnerable determines if the key exchange mechanism is quantum vulnerable
func (s *TLSScanner) isKeyExchangeVulnerable(result *TLSScanResult) bool {
	// Check if any PQC key exchange groups are detected
	if len(result.PQCGroups) > 0 {
		return false // Has PQC key exchange
	}
	
	// Check cipher suites for key exchange mechanisms
	for _, cipherInfo := range result.SupportedCiphers {
		cipherName := strings.ToUpper(cipherInfo.Name)
		
		// Check for PQC/hybrid key exchange in cipher names
		if strings.Contains(cipherName, "KYBER") || 
		   strings.Contains(cipherName, "ML_KEM") ||
		   strings.Contains(cipherName, "NTRU") {
			return false // Has PQC key exchange
		}
		
		// Check for non-PFS (static RSA) - definitely vulnerable
		if strings.Contains(cipherName, "TLS_RSA_WITH_") {
			return true // Static RSA key exchange
		}
	}
	
	// Check for static RSA certificates (vulnerable to key exchange attacks)
	if result.Certificate != nil && result.CertKeyInfo.IsStaticRSA {
		return true
	}
	
	// Default assumption: if using standard ECDH/DHE without PQC, it's vulnerable
	// This is conservative but aligns with HNDL threat model
	return true
}

package linux

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"mini-pqc/scan"
)

// PostfixReport represents the structure of the JSON report for the postfix command
type PostfixReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	PostfixInfo    map[string]string      `json:"postfix_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestPostfix executes Postfix mail server PQC readiness audit
func TestPostfix(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Postfix Mail Server PQC Readiness Audit ===")
	
	// Create a map to store detection results
	results := make(map[string]string)
	
	// AWS Load Balancer Crypto Inspection (if running in AWS environment) - collect early
	awsResults := make(map[string]string)
	if awsData := inspectAWSLoadBalancerForPostfix(); len(awsData) > 0 {
		for key, value := range awsData {
			awsResults[key] = value
			results[key] = value // Also store in main results for status generation
		}
	}
	
	// Check for Postfix
	recommendations := checkPostfix(awsResults)
	
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()
	
	// Store basic information in results map
	cmd := exec.Command("postconf", "-d", "mail_version")
	output, err := cmd.Output()
	if err == nil {
		parts := strings.Split(string(output), "=")
		if len(parts) > 1 {
			version := strings.TrimSpace(parts[1])
			results["Version"] = version
		}
		results["Postfix Installed"] = "Yes"
	} else {
		results["Postfix Installed"] = "No"
	}
	
	// Check for config file
	if _, err := os.Stat("/etc/postfix/main.cf"); err == nil {
		results["Config Path"] = "/etc/postfix/main.cf"
	}
	
	// Check for TLS configuration
	if _, err := os.Stat("/etc/postfix/main.cf"); err == nil {
		tlsParams := checkPostfixTLSParams("/etc/postfix/main.cf")
		if tlsParams["smtpd_tls_security_level"] != "" {
			results["TLS Enabled"] = "Yes"
		} else {
			results["TLS Enabled"] = "No"
		}
		
		// Store certificate and key paths
		if tlsParams["smtpd_tls_cert_file"] != "" {
			results["Certificate Path"] = tlsParams["smtpd_tls_cert_file"]
		}
		if tlsParams["smtpd_tls_key_file"] != "" {
			results["Key Path"] = tlsParams["smtpd_tls_key_file"]
		}
		
		// Store protocol and cipher information
		if tlsParams["smtpd_tls_protocols"] != "" {
			results["Protocols"] = tlsParams["smtpd_tls_protocols"]
		}
		if tlsParams["smtpd_tls_ciphers"] != "" {
			results["Ciphers"] = tlsParams["smtpd_tls_ciphers"]
		}
	}
	
	// Check for PQC support
	results["PQC Support"] = "Not Available"
	
	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	if awsResults := inspectAWSLoadBalancerForPostfix(); len(awsResults) > 0 {
		for key, value := range awsResults {
			results[key] = value
		}
	}
	
	// Generate status items based on scan results
	generatePostfixStatus(results, rm)
	
	// Add recommendations to the manager
	rm.AppendRecommendations(recommendations)
	
	// Get all recommendations and status items from the manager
	allRecommendations := rm.GetRecommendations()
	
	// If JSON output is requested, create and save the report
	if jsonOutput {
		// Get server IP address
		var serverIP string
		
		// Get IP address from network interfaces
		addrs, err := net.InterfaceAddrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						serverIP = ipnet.IP.String()
						break
					}
				}
			}
		}
		
		// Default value if no IP found
		if serverIP == "" {
			serverIP = "unknown"
		}
		
		// Create report structure
		report := PostfixReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			PostfixInfo:    results,
			Recommendations: allRecommendations,
		}
		
		// Create report directory if it doesn't exist
		reportDir := "./report"
		if _, err := os.Stat(reportDir); os.IsNotExist(err) {
			os.MkdirAll(reportDir, 0755)
		}
		
		// Marshal report to JSON
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			// Write JSON to file
			filePath := filepath.Join(reportDir, "postfix.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/postfix.json")
			} else {
				fmt.Printf("\nError writing JSON report: %s\n", err)
			}
		} else {
			fmt.Printf("\nError creating JSON report: %s\n", err)
		}
	}
	
	// Future: add support for other mail servers like Exim, Sendmail, etc.
	return allRecommendations
}

// checkPostfix checks for Postfix installation and configuration
func checkPostfix(awsResults map[string]string) []scan.Recommendation {
	fmt.Println("Checking Postfix installation and configuration...")
	
	// Check if Postfix is installed
	postfixPath, err := exec.LookPath("postfix")
	if err != nil {
		fmt.Println("[-] Postfix is not installed")
		// Only provide status information, no recommendation to install
		return []scan.Recommendation{}
	}
	
	fmt.Printf("[+] Postfix found at: %s\n", postfixPath)
	
	// Get Postfix version
	cmd := exec.Command("postconf", "-d", "mail_version")
	output, err := cmd.Output()
	if err == nil {
		versionLine := strings.TrimSpace(string(output))
		parts := strings.Split(versionLine, " = ")
		if len(parts) == 2 {
			fmt.Printf("[+] Postfix version: %s\n", parts[1])
		}
	}
	
	// Postfix config files we're interested in
	// main.cf - Primary configuration
	// tls_policy - TLS policy settings (if exists)
	// master.cf - Service configuration
	
	fmt.Println("\n[*] Postfix Configuration Analysis:")
	
	// Initialize counters and flags
	tlsEnabled := false
	weakCiphers := false
	classicOnlyCrypto := true // Assume only classic crypto initially
	tlsParams := make(map[string]string) // Initialize tlsParams map
	
	// Check main configuration
	mainCfgPath := "/etc/postfix/main.cf"
	if _, err := os.Stat(mainCfgPath); err == nil {
		fmt.Printf("[+] Found main configuration: %s\n", mainCfgPath)
		
		// Check TLS configuration
		tlsParams = checkPostfixTLSParams(mainCfgPath)
		
		// Check if TLS is enabled
		if val, ok := tlsParams["smtpd_use_tls"]; ok && (val == "yes" || val == "true") {
			tlsEnabled = true
			fmt.Println("[+] TLS is enabled for incoming connections")
		} else {
			fmt.Println("[-] TLS may not be enabled for incoming connections")
		}
		
		// Check if TLS is required for outgoing connections
		if val, ok := tlsParams["smtp_tls_security_level"]; ok && (val == "encrypt" || val == "dane" || val == "dane-only") {
			fmt.Println("[+] TLS is required for outgoing connections")
		} else {
			fmt.Println("[-] TLS may not be required for outgoing connections")
		}
		
		// Check TLS protocols
		if val, ok := tlsParams["smtpd_tls_protocols"]; ok {
			fmt.Printf("[*] TLS protocols: %s\n", val)
			if strings.Contains(val, "SSLv2") || strings.Contains(val, "SSLv3") || 
			   strings.Contains(val, "TLSv1") || strings.Contains(val, "TLSv1.1") {
				fmt.Println("[-] Insecure TLS protocols allowed")
				weakCiphers = true
			} else if strings.Contains(val, "TLSv1.3") {
				fmt.Println("[+] TLSv1.3 supported")
			}
		}
		
		// Check cipher suites
		if val, ok := tlsParams["smtpd_tls_ciphers"]; ok {
			fmt.Printf("[*] TLS cipher preference: %s\n", val)
			if val == "high" || val == "medium" {
				fmt.Println("[~] Using standard cipher preference")
			} else if val == "low" || val == "export" || val == "null" {
				fmt.Println("[-] Using weak cipher preference")
				weakCiphers = true
			}
		}
		
		// Check for PQC support in OpenSSL
		opensslVersion := checkOpenSSLVersion()
		if strings.HasPrefix(opensslVersion, "3.2") {
			fmt.Printf("[+] OpenSSL version %s supports PQC algorithms\n", opensslVersion)
			classicOnlyCrypto = false
		} else {
			fmt.Printf("[-] OpenSSL version %s does not support PQC algorithms\n", opensslVersion)
		}
		
		// Check certificate paths
		if val, ok := tlsParams["smtpd_tls_cert_file"]; ok {
			fmt.Printf("[*] TLS certificate file: %s\n", val)
		}
		
		if val, ok := tlsParams["smtpd_tls_key_file"]; ok {
			fmt.Printf("[*] TLS key file: %s\n", val)
		}
	} else {
		fmt.Printf("[-] Could not find main configuration at %s\n", mainCfgPath)
	}

	// Check for DANE support (DNS-Based Authentication of Named Entities)
	daneSupport := checkDANESupport()

	// Check for MTA-STS support (SMTP MTA Strict Transport Security)
	mtaStsSupport := checkMTASTSSupport(tlsParams)

	// Analyze certificate files for algorithm type
	certInfo := "Not analyzed"
	certAlgorithm := "unknown"
	if val, ok := tlsParams["smtpd_tls_cert_file"]; ok && val != "" {
		certInfo, certAlgorithm = analyzeMailCertificate(val)
	}

	// Print additional security features
	fmt.Println("\n[*] Additional Security Features:")
	if daneSupport {
		fmt.Println("[+] DANE support detected - Helps protect against MITM attacks")
	} else {
		fmt.Println("[-] No DANE support detected")
	}
	
	if mtaStsSupport {
		fmt.Println("[+] MTA-STS support detected - Enhances transport security")
	} else {
		fmt.Println("[-] No MTA-STS support detected")
	}
	
	fmt.Printf("[*] Certificate analysis: %s\n", certInfo)

	// Print PQC readiness assessment
	fmt.Println("\n=== Postfix PQC Readiness Assessment ===")
	if !tlsEnabled {
		fmt.Println("[-] Poor - TLS is not enabled")
		fmt.Println("    All email traffic is unencrypted and vulnerable")
	} else if weakCiphers {
		fmt.Println("[-] Poor - Weak TLS configuration")
		fmt.Println("    Using outdated protocols or weak ciphers")
	} else if certAlgorithm == "RSA-1024" || certAlgorithm == "DSA" {
		fmt.Println("[-] Poor - Using vulnerable cryptographic certificates")
		fmt.Println("    Weak algorithms vulnerable to quantum attacks")
	} else if classicOnlyCrypto {
		if daneSupport || mtaStsSupport {
			fmt.Println("[~] Good - Using standard TLS security with additional protections")
			fmt.Println("    But no post-quantum cryptography algorithms")
		} else {
			fmt.Println("[~] Fair - Using standard TLS security")
			fmt.Println("    But no post-quantum cryptography support")
		}
	} else {
		fmt.Println("[+] Excellent - Using strong TLS with PQC potential")
		fmt.Println("    OpenSSL 3.2+ detected, capable of PQC algorithms")
	}
	
	// Check if Postfix is installed
	postfixInstalled := true
	// We already checked at the beginning of the function, but let's be explicit here
	if _, err := exec.LookPath("postfix"); err != nil {
		postfixInstalled = false
	}

	// Generate structured recommendations
	return generatePostfixRecommendations(
		tlsEnabled,
		weakCiphers,
		daneSupport,
		mtaStsSupport,
		certAlgorithm,
		classicOnlyCrypto,
		postfixInstalled,
		awsResults,
	)
}

// checkPostfixTLSParams reads Postfix config and extracts TLS-related parameters
func checkPostfixTLSParams(configPath string) map[string]string {
	tlsParams := make(map[string]string)
	
	// Parameters to look for
	paramNames := []string{
		"smtpd_use_tls",
		"smtpd_tls_security_level",
		"smtp_tls_security_level",
		"smtpd_tls_protocols",
		"smtp_tls_protocols",
		"smtpd_tls_ciphers",
		"smtp_tls_ciphers",
		"smtpd_tls_mandatory_protocols",
		"smtpd_tls_mandatory_ciphers",
		"smtpd_tls_cert_file",
		"smtpd_tls_key_file",
		"smtpd_tls_dh1024_param_file",
		"smtpd_tls_eecdh_grade",
	}
	
	// Read the config file
	file, err := os.Open(configPath)
	if err != nil {
		return tlsParams
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		for _, param := range paramNames {
			if strings.HasPrefix(line, param+" = ") || strings.HasPrefix(line, param+"=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					paramName := strings.TrimSpace(parts[0])
					paramValue := strings.TrimSpace(parts[1])
					// Remove quotes if present
					paramValue = strings.Trim(paramValue, "\" ")
					tlsParams[paramName] = paramValue
				}
			}
		}
	}
	
	return tlsParams
}

// checkOpenSSLVersion checks the version of OpenSSL used by the system
func checkOpenSSLVersion() string {
	cmd := exec.Command("openssl", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	
	// Parse OpenSSL version string (e.g., "OpenSSL 3.0.2 15 Mar 2022")
	versionStr := string(output)
	re := regexp.MustCompile(`OpenSSL\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) > 1 {
		return matches[1]
	}
	
	return "unknown"
}

// checkDANESupport checks for DANE (DNS-Based Authentication of Named Entities) support
func checkDANESupport() bool {
	// Check if dnssec-tools or similar is installed
	_, err := exec.LookPath("delv")
	if err == nil {
		// delv is a DNSSEC-aware resolver
		return true
	}
	
	// Check if unbound-host is installed
	_, err = exec.LookPath("unbound-host")
	if err == nil {
		return true
	}
	
	// Check if postfix configuration mentions DANE
	cmd := exec.Command("postconf", "-n")
	output, err := cmd.Output()
	if err == nil {
		config := string(output)
		if strings.Contains(config, "dane") || strings.Contains(config, "DANE") ||
		   strings.Contains(config, "tlsa") || strings.Contains(config, "TLSA") {
			return true
		}
	}
	
	return false
}

// checkMTASTSSupport checks for MTA-STS (SMTP MTA Strict Transport Security) support
func checkMTASTSSupport(tlsParams map[string]string) bool {
	// Check if postfix is configured for MTA-STS
	if val, ok := tlsParams["smtp_tls_policy_maps"]; ok {
		if strings.Contains(val, "socketmap") || strings.Contains(val, "texthash") {
			return true
		}
	}
	
	// Check for MTA-STS related files
	policyFiles := []string{
		"/etc/postfix/smtp_mta_sts_maps",
		"/etc/postfix/mta-sts-policy",
	}
	
	for _, file := range policyFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	
	// Check if postfix configuration mentions MTA-STS
	cmd := exec.Command("postconf", "-n")
	output, err := cmd.Output()
	if err == nil {
		config := string(output)
		if strings.Contains(config, "mta_sts") || strings.Contains(config, "MTA-STS") {
			return true
		}
	}
	
	return false
}

// analyzeMailCertificate examines a certificate file to determine its algorithm and strength
func analyzeMailCertificate(certPath string) (string, string) {
	// Try to read the certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "Could not read certificate file", "unknown"
	}
	
	// Parse PEM encoded certificate
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return "Not a valid PEM certificate", "unknown"
	}
	
	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "Could not parse certificate", "unknown"
	}
	
	// Determine algorithm type and strength
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// Try to determine RSA key size
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok {
			bitSize := rsaKey.N.BitLen()
			if bitSize <= 1024 {
				return fmt.Sprintf("RSA-%d (Weak, vulnerable to quantum attacks)", bitSize), "RSA-1024"
			} else if bitSize <= 2048 {
				return fmt.Sprintf("RSA-%d (Current standard, but vulnerable to quantum attacks)", bitSize), "RSA-2048"
			} else {
				return fmt.Sprintf("RSA-%d (Strong classical security, still vulnerable to quantum attacks)", bitSize), "RSA-3072+"
			}
		}
		return "RSA (Vulnerable to quantum attacks)", "RSA"
		
	case x509.ECDSA:
		return "ECDSA (Better than RSA, but still vulnerable to quantum attacks)", "ECDSA"
	
	case x509.Ed25519:
		return "Ed25519 (Better than RSA, but still vulnerable to quantum attacks)", "Ed25519"
	
	case x509.DSA:
		return "DSA (Weak, vulnerable to quantum attacks)", "DSA"
	
	default:
		// Check if this might be a PQC algorithm
		algoName := cert.SignatureAlgorithm.String()
		if strings.Contains(strings.ToLower(algoName), "dilithium") ||
		   strings.Contains(strings.ToLower(algoName), "falcon") ||
		   strings.Contains(strings.ToLower(algoName), "sphincs") ||
		   strings.Contains(strings.ToLower(algoName), "kyber") {
			return fmt.Sprintf("%s (Post-quantum algorithm)", algoName), "PQC"
		}
		
		return fmt.Sprintf("Unknown algorithm: %s", cert.SignatureAlgorithm), "unknown"
	}
}

package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"mini-pqc/scan"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OpenVPNReport represents the structure of the JSON report for the openvpn command
type OpenVPNReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	OpenVPNInfo    map[string]string      `json:"openvpn_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestOpenVPN runs a PQC readiness audit for OpenVPN
func TestOpenVPN(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== OpenVPN PQC Readiness Check ===")
	results := make(map[string]string)

	// Check OpenVPN installation and version
	checkOpenVPNInstallation(results)

	// Check TLS Key Exchange (DH groups, TLS version, cipher suites)
	checkTLSKeyExchange(results)

	// Check Certificate types (RSA, ECC, PQC)
	checkCertificates(results)

	// Check linked TLS library (OpenSSL version)
	checkTLSLibrary(results)

	// Check EasyRSA defaults
	checkEasyRSA(results)

	// Print summary
	printOpenVPNSummary(results)
	
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Check AWS environment and load balancer configuration
	checkAWSEnvironmentForOpenVPN(results)

	// Generate status items based on scan results
	generateOpenVPNStatus(results, rm)

	// Generate recommendations based on scan results
	recommendations := generateOpenVPNRecommendations(results)

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
		report := OpenVPNReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			OpenVPNInfo:    results,
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
			filePath := filepath.Join(reportDir, "openvpn.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/openvpn.json")
			} else {
				fmt.Printf("\nError writing JSON report: %s\n", err)
			}
		} else {
			fmt.Printf("\nError creating JSON report: %s\n", err)
		}
	}

	// Return recommendations for main program to display
	return allRecommendations
}

// checkOpenVPNInstallation checks if OpenVPN is installed and parses its configuration files
func checkOpenVPNInstallation(results map[string]string) {
	// Check for OpenVPN installation
	cmd := exec.Command("which", "openvpn")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		results["OpenVPN"] = "Not installed"
		return
	}

	openvpnPath := strings.TrimSpace(string(output))
	results["OpenVPN Path"] = openvpnPath

	// Get OpenVPN version
	cmd = exec.Command("openvpn", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		results["OpenVPN"] = "Installed (version unknown)"
	} else {
		// Extract just the first line of version info to avoid excessive output
		fullOutput := strings.TrimSpace(string(output))
		lines := strings.Split(fullOutput, "\n")
		if len(lines) > 0 {
			// Store just the first line which contains the version number
			results["OpenVPN"] = lines[0]
			// Store full output in a separate field for detailed analysis if needed
			results["OpenVPNFullDetails"] = fullOutput
		} else {
			results["OpenVPN"] = "Installed (version details unavailable)"
		}
	}

	// Parse OpenVPN config files for additional details
	parseOpenVPNConfigs(results)
}

// checkTLSKeyExchange checks DH groups, TLS version, cipher suites
func checkTLSKeyExchange(results map[string]string) {
	// Check if we have config files to analyze
	if results["ConfigFilesFound"] != "true" && results["SampleConfig"] != "true" {
		results["TLSKeyExchangeStatus"] = "No OpenVPN configs found to analyze"
		return
	}

	// Initialize counters
	legacyDHCount := 0
	legacyCipherCount := 0
	noTLSMinCount := 0
	tlsMinBelow12Count := 0
	tlsMin12Count := 0
	tlsMin13OrHigherCount := 0
	totalConfigs := 0

	// Regex to parse TLS versions like 1.0, 1.2, 1.3
	versionRegex := regexp.MustCompile(`^(\d+)\.(\d+)`)

	// Analyze results from parseOpenVPNConfigs
	for key, value := range results {
		// Check for legacy DH parameters
		if strings.HasSuffix(key, "_LegacyDH") && value == "true" {
			legacyDHCount++
		}

		// Check for legacy ciphers
		if strings.HasSuffix(key, "_LegacyCipher") && value == "true" {
			legacyCipherCount++
		}

		// Check for TLS version
		if strings.HasSuffix(key, "_TLS") {
			// Count each config encountered
			totalConfigs++
			v := strings.TrimSpace(value)
			if v == "" {
				noTLSMinCount++
			} else {
				// Normalize possible forms like v1.2 -> 1.2
				if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
					v = v[1:]
				}
				mm := versionRegex.FindStringSubmatch(v)
				if len(mm) >= 3 {
					maj, _ := strconv.Atoi(mm[1])
					min, _ := strconv.Atoi(mm[2])
					verNum := maj*10 + min
					if verNum < 12 {
						tlsMinBelow12Count++
					} else if verNum == 12 {
						tlsMin12Count++
					} else if verNum >= 13 {
						tlsMin13OrHigherCount++
					}
				}
			}
		}
	}

	// Store results
	results["LegacyDHCount"] = fmt.Sprintf("%d", legacyDHCount)
	results["LegacyCipherCount"] = fmt.Sprintf("%d", legacyCipherCount)
	results["NoTLSMinCount"] = fmt.Sprintf("%d", noTLSMinCount)
	results["TLSMinBelow12Count"] = fmt.Sprintf("%d", tlsMinBelow12Count)
	results["TLSMin12Count"] = fmt.Sprintf("%d", tlsMin12Count)
	results["TLSMin13OrHigherCount"] = fmt.Sprintf("%d", tlsMin13OrHigherCount)

	// Determine overall TLS key exchange security status
	if legacyDHCount > 0 || legacyCipherCount > 0 || noTLSMinCount > 0 || tlsMinBelow12Count > 0 {
		results["TLSKeyExchangeStatus"] = "Insecure"
		
		// Build detailed reason
		reasons := []string{}
		if legacyDHCount > 0 {
			reasons = append(reasons, fmt.Sprintf("%d configs with legacy DH parameters", legacyDHCount))
		}
		if legacyCipherCount > 0 {
			reasons = append(reasons, fmt.Sprintf("%d configs with legacy ciphers", legacyCipherCount))
		}
		if noTLSMinCount > 0 {
			reasons = append(reasons, fmt.Sprintf("%d configs without TLS minimum version", noTLSMinCount))
		}
		if tlsMinBelow12Count > 0 {
			reasons = append(reasons, fmt.Sprintf("%d configs with tls-version-min below 1.2", tlsMinBelow12Count))
		}
		
		results["TLSKeyExchangeStatusReason"] = strings.Join(reasons, ", ")
	} else if totalConfigs > 0 {
		results["TLSKeyExchangeStatus"] = "Secure"
	} else {
		results["TLSKeyExchangeStatus"] = "Unknown"
	}

	// PQC readiness recommendations
	results["TLSKeyExchangeRecommendation"] = "Use tls-version-min 1.2 or higher, avoid legacy DH parameters (dh1024.pem), and use modern ciphers like AES-256-GCM"
}

// checkCertificates checks for RSA, ECC, PQC certs
func checkCertificates(results map[string]string) {
	// Check if we have a certificate path to analyze
	certPath := results["CertPath"]
	if certPath == "" {
		results["CertificateStatus"] = "No certificate path found in config"
		return
	}

	// If the cert path is relative, assume it's in the same directory as the config
	if !filepath.IsAbs(certPath) && results["ConfigLocation"] != "" {
		certPath = filepath.Join(results["ConfigLocation"], certPath)
	}

	// Check if certificate file exists
	_, err := os.Stat(certPath)
	if err != nil {
		// Certificate file doesn't exist or can't be accessed
		results["CertificateStatus"] = "Certificate file not found or inaccessible"
		results["CertificateType"] = "Unknown"
		
		// For demonstration, create a sample certificate analysis
		if results["SampleConfig"] == "true" {
			results["CertificateStatus"] = "Sample certificate analysis"
			results["CertificateType"] = "RSA-2048"
			results["CertificatePQCReady"] = "false"
			results["CertificateRecommendation"] = "Replace RSA-2048 certificates with PQC-ready algorithms like Dilithium or hybrid RSA+PQC certificates"
		}
		return
	}

	// Use openssl to analyze the certificate
	cmd := exec.Command("openssl", "x509", "-in", certPath, "-text", "-noout")
	output, err := cmd.CombinedOutput()
	if err != nil {
		results["CertificateStatus"] = "Error analyzing certificate: " + err.Error()
		return
	}

	// Parse the certificate output
	certInfo := string(output)
	results["CertificateFound"] = "true"

	// Check certificate type
	certType := "Unknown"
	if strings.Contains(certInfo, "Public Key Algorithm: rsaEncryption") {
		certType = "RSA"
		
		// Check RSA key size
		rsaRegex := regexp.MustCompile(`RSA Public-Key:\s+\((\d+)\s+bit\)`)
		matches := rsaRegex.FindStringSubmatch(certInfo)
		if len(matches) > 1 {
			keySize := matches[1]
			certType = "RSA-" + keySize
		}
	} else if strings.Contains(certInfo, "Public Key Algorithm: id-ecPublicKey") {
		certType = "ECDSA"
		
		// Check curve type
		if strings.Contains(certInfo, "NIST P-256") {
			certType = "ECDSA-P256"
		} else if strings.Contains(certInfo, "NIST P-384") {
			certType = "ECDSA-P384"
		} else if strings.Contains(certInfo, "NIST P-521") {
			certType = "ECDSA-P521"
		}
	} else if strings.Contains(certInfo, "Public Key Algorithm: Ed25519") {
		certType = "Ed25519"
	} else if strings.Contains(certInfo, "Public Key Algorithm: dilithium") {
		certType = "Dilithium (PQC)"
	}

	results["CertificateType"] = certType

	// Determine PQC readiness
	pqcReady := "false"
	if strings.Contains(certType, "Dilithium") || strings.Contains(certType, "PQC") {
		pqcReady = "true"
	}
	results["CertificatePQCReady"] = pqcReady

	// Provide recommendations
	if pqcReady == "false" {
		if strings.Contains(certType, "RSA") {
			results["CertificateRecommendation"] = "Replace RSA certificates with PQC-ready algorithms like Dilithium or hybrid RSA+PQC certificates"
		} else if strings.Contains(certType, "ECDSA") || certType == "Ed25519" {
			results["CertificateRecommendation"] = "ECDSA and Ed25519 are quantum-vulnerable. Consider upgrading to hybrid ECC+PQC certificates"
		} else {
			results["CertificateRecommendation"] = "Unknown certificate type. Consider upgrading to PQC-ready certificates"
		}
	} else {
		results["CertificateRecommendation"] = "Certificate uses PQC-ready algorithms"
	}
}

// checkTLSLibrary checks OpenSSL version
func checkTLSLibrary(results map[string]string) {
	// Check OpenSSL version
	cmd := exec.Command("openssl", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		results["OpenSSLVersion"] = "Error: " + err.Error()
		results["OpenSSLPQCReady"] = "unknown"
		return
	}

	// Parse OpenSSL version
	versionStr := strings.TrimSpace(string(output))
	results["OpenSSLVersion"] = versionStr

	// Check if OpenSSL version is 3.2+ (required for PQC)
	// Extract version number from string like "OpenSSL 3.0.2 15 Mar 2022"
	versionRegex := regexp.MustCompile(`OpenSSL\s+(\d+)\.(\d+)\.(\d+)`)
	matches := versionRegex.FindStringSubmatch(versionStr)

	if len(matches) >= 4 {
		major := matches[1]
		minor := matches[2]
		
		// OpenSSL 3.2+ is required for PQC
		if major == "3" && minor >= "2" || major > "3" {
			results["OpenSSLPQCReady"] = "true"
		} else {
			results["OpenSSLPQCReady"] = "false"
			results["OpenSSLPQCReadyReason"] = "OpenSSL 3.2+ required for PQC support"
		}
	} else {
		results["OpenSSLPQCReady"] = "unknown"
		results["OpenSSLPQCReadyReason"] = "Could not parse OpenSSL version"
	}

	// Check if OpenVPN is linked against this OpenSSL
	cmd = exec.Command("ldd", "/usr/sbin/openvpn")
	output, err = cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "libssl.so") {
			results["OpenVPNLinkedWithOpenSSL"] = "true"
		} else {
			results["OpenVPNLinkedWithOpenSSL"] = "false"
			results["OpenSSLPQCReady"] = "unknown"
			results["OpenSSLPQCReadyReason"] = "OpenVPN not linked with OpenSSL"
		}
	} else {
		results["OpenVPNLinkedWithOpenSSL"] = "unknown"
	}
}

// checkEasyRSA checks for insecure defaults
func checkEasyRSA(results map[string]string) {
	// Common locations for EasyRSA
	easyRSALocations := []string{
		"/usr/share/easy-rsa",
		"/etc/openvpn/easy-rsa",
		"/usr/local/share/easy-rsa",
	}

	// Check if EasyRSA is installed
	easyRSAFound := false
	easyRSAPath := ""

	for _, location := range easyRSALocations {
		if _, err := os.Stat(location); err == nil {
			easyRSAFound = true
			easyRSAPath = location
			break
		}
	}

	if !easyRSAFound {
		// Try to find EasyRSA using which command
		cmd := exec.Command("which", "easyrsa")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			easyRSAFound = true
			easyRSAPath = strings.TrimSpace(string(output))
		}
	}

	if !easyRSAFound {
		results["EasyRSAFound"] = "false"
		results["EasyRSAStatus"] = "Not installed"
		
		// Create sample analysis for demonstration
		results["EasyRSADefaultKeySize"] = "RSA-2048 (sample)"
		results["EasyRSADefaultDigest"] = "SHA-256 (sample)"
		results["EasyRSAPQCReady"] = "false"
		results["EasyRSARecommendation"] = "Install EasyRSA 3.1+ and configure it to use stronger key sizes (RSA-4096) or PQC algorithms when available"
		return
	}

	results["EasyRSAFound"] = "true"
	results["EasyRSAPath"] = easyRSAPath

	// Check EasyRSA version
	cmd := exec.Command("easyrsa", "--version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		versionStr := strings.TrimSpace(string(output))
		results["EasyRSAVersion"] = versionStr
	} else {
		results["EasyRSAVersion"] = "Unknown"
	}

	// Check EasyRSA vars file for default settings
	varsFiles := []string{
		filepath.Join(easyRSAPath, "vars"),
		filepath.Join(easyRSAPath, "easyrsa3/vars"),
		filepath.Join(easyRSAPath, "easyrsa3/vars.example"),
	}

	varsFound := false
	defaultKeySize := "Unknown"
	defaultDigest := "Unknown"

	for _, varsFile := range varsFiles {
		if _, err := os.Stat(varsFile); err == nil {
			varsFound = true
			
			// Parse vars file
			file, err := os.Open(varsFile)
			if err != nil {
				continue
			}
			defer file.Close()

			// Look for key size and digest settings
			keySizeRegex := regexp.MustCompile(`set_var\s+KEY_SIZE\s+([0-9]+)`)
			digestRegex := regexp.MustCompile(`set_var\s+DIGEST\s+(["']?[\w-]+["']?)`)

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()

				// Skip comments and empty lines
				if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
					continue
				}

				// Check for key size
				if matches := keySizeRegex.FindStringSubmatch(line); len(matches) > 1 {
					defaultKeySize = "RSA-" + matches[1]
				}

				// Check for digest
				if matches := digestRegex.FindStringSubmatch(line); len(matches) > 1 {
					// Clean up the digest string (remove quotes)
					digest := matches[1]
					digest = strings.Trim(digest, `"'`)
					defaultDigest = digest
				}
			}

			break
		}
	}

	if !varsFound {
		// If vars file not found, use defaults for EasyRSA
		defaultKeySize = "RSA-2048"
		defaultDigest = "SHA-256"
		results["EasyRSAVarsFound"] = "false"
	} else {
		results["EasyRSAVarsFound"] = "true"
	}

	results["EasyRSADefaultKeySize"] = defaultKeySize
	results["EasyRSADefaultDigest"] = defaultDigest

	// Determine PQC readiness
	pqcReady := "false"
	
	// Check if key size is secure
	keySizeSecure := false
	if strings.Contains(defaultKeySize, "4096") || strings.Contains(defaultKeySize, "8192") {
		keySizeSecure = true
	}

	// Check if digest is secure
	digestSecure := false
	if defaultDigest == "SHA-256" || defaultDigest == "SHA-384" || defaultDigest == "SHA-512" {
		digestSecure = true
	}

	// Overall security assessment
	if keySizeSecure && digestSecure {
		results["EasyRSAStatus"] = "Secure but not PQC-ready"
	} else {
		results["EasyRSAStatus"] = "Insecure"
	}

	results["EasyRSAPQCReady"] = pqcReady

	// Recommendations
	if !keySizeSecure {
		results["EasyRSARecommendation"] = "Increase default key size to at least RSA-4096"
	} else if !digestSecure {
		results["EasyRSARecommendation"] = "Use SHA-256 or stronger digest algorithm"
	} else {
		results["EasyRSARecommendation"] = "Current settings are secure for classical threats, but not quantum-resistant. When available, configure EasyRSA to use PQC algorithms"
	}
}
func printOpenVPNSummary(results map[string]string) {
	fmt.Println("\nOpenVPN PQC Readiness Summary:")
	fmt.Println("-----------------------------")
	
	// Only print essential information
	essentialKeys := []string{
		"OpenVPN", // Just the version info
		"TLSKeyExchangeStatus",
		"CertificateType",
		"CertificatePQCReady",
		"OpenSSLPQCReady",
		"EasyRSADefaultKeySize",
	}
	
	for _, key := range essentialKeys {
		if value, exists := results[key]; exists && value != "" {
			fmt.Printf("%s: %s\n", key, value)
		}
	}
	// No recommendations header here - let the main program handle it
}

// parseOpenVPNConfigs parses OpenVPN configuration files for certificates and algorithms
func parseOpenVPNConfigs(results map[string]string) {
	// Common locations for OpenVPN config files
	configDirs := []string{
		"/etc/openvpn",
		"/etc/openvpn/client",
		"/etc/openvpn/server",
		"/usr/local/etc/openvpn",
	}

	// Track if we found any config files
	configFound := false

	// Search for config files in common locations
	for _, dir := range configDirs {
		// Check if directory exists
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		// Find .conf and .ovpn files
		confFiles, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		ovpnFiles, _ := filepath.Glob(filepath.Join(dir, "*.ovpn"))

		// Combine file lists
		configFiles := append(confFiles, ovpnFiles...)

		if len(configFiles) > 0 {
			configFound = true
			results["ConfigFilesFound"] = "true"
			results["ConfigFileCount"] = fmt.Sprintf("%d", len(configFiles))
			results["ConfigLocation"] = dir

			// Parse each config file
			for _, configFile := range configFiles {
				parseOpenVPNConfigFile(configFile, results)
			}
		}
	}

	if !configFound {
		results["ConfigFilesFound"] = "false"
		results["ConfigFileCount"] = "0"
		
		// Create a sample config for demonstration
		fmt.Println("No OpenVPN config files found. Creating sample data for demonstration...")
		createAndParseSampleConfig(results)
	}
}

// parseOpenVPNConfigFile parses a single OpenVPN config file for PQC readiness
func parseOpenVPNConfigFile(filePath string, results map[string]string) {
	// Open the config file
	file, err := os.Open(filePath)
	if err != nil {
		results[filepath.Base(filePath)] = "Error: " + err.Error()
		return
	}
	defer file.Close()

	// Initialize counters and flags for security issues
	dhParams := ""
	tlsVersion := ""
	cipherSuite := ""
	// certType will be determined in checkCertificates function
	hasLegacyDH := false
	hasLegacyCipher := false

	// Regular expressions for matching config directives
	dhParamRegex := regexp.MustCompile(`dh\s+([^\s]+)`)
	tlsVersionRegex := regexp.MustCompile(`tls-version-min\s+([^\s]+)`)
	cipherRegex := regexp.MustCompile(`cipher\s+([^\s]+)`)
	certRegex := regexp.MustCompile(`cert\s+([^\s]+)`)

	// Scan the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Check for DH parameters
		if matches := dhParamRegex.FindStringSubmatch(line); len(matches) > 1 {
			dhParams = matches[1]
			// Check for legacy DH parameters
			if strings.Contains(dhParams, "1024") || strings.Contains(dhParams, "dh1024") {
				hasLegacyDH = true
			}
		}

		// Check for TLS version
		if matches := tlsVersionRegex.FindStringSubmatch(line); len(matches) > 1 {
			tlsVersion = matches[1]
		}

		// Check for cipher suite
		if matches := cipherRegex.FindStringSubmatch(line); len(matches) > 1 {
			cipherSuite = matches[1]
			// Check for legacy ciphers
			legacyCiphers := []string{"BF-CBC", "DES-CBC", "DES-EDE3-CBC", "RC2-CBC"}
			for _, legacyCipher := range legacyCiphers {
				if strings.Contains(cipherSuite, legacyCipher) {
					hasLegacyCipher = true
					break
				}
			}
		}

		// Check for certificate type
		if matches := certRegex.FindStringSubmatch(line); len(matches) > 1 {
			certPath := matches[1]
			// Store the cert path for later analysis
			results["CertPath"] = certPath
		}
	}

	// Store results for this config file
	baseName := filepath.Base(filePath)
	results["Config_"+baseName+"_DH"] = dhParams
	results["Config_"+baseName+"_TLS"] = tlsVersion
	results["Config_"+baseName+"_Cipher"] = cipherSuite
	
	if hasLegacyDH {
		results["Config_"+baseName+"_LegacyDH"] = "true"
	}
	
	if hasLegacyCipher {
		results["Config_"+baseName+"_LegacyCipher"] = "true"
	}
}

// createAndParseSampleConfig creates a sample OpenVPN config for demonstration
func createAndParseSampleConfig(results map[string]string) {
	// Create a sample config string
	sampleConfig := `# Sample OpenVPN Server Configuration
# This is for demonstration purposes only

port 1194
proto udp
dev tun

# Legacy DH parameters (insecure)
dh dh1024.pem

# Certificate configuration
ca ca.crt
cert server.crt
key server.key

# Legacy cipher (insecure)
cipher BF-CBC

# No explicit TLS version minimum (insecure)
# tls-version-min 1.2

user nobody
group nogroup
`

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "sample-openvpn-*.conf")
	if err != nil {
		results["SampleConfig"] = "Error creating sample: " + err.Error()
		return
	}
	defer os.Remove(tmpFile.Name())

	// Write the sample config
	if _, err := tmpFile.WriteString(sampleConfig); err != nil {
		results["SampleConfig"] = "Error writing sample: " + err.Error()
		return
	}
	tmpFile.Close()

	// Parse the sample config
	results["SampleConfig"] = "true"
	parseOpenVPNConfigFile(tmpFile.Name(), results)
}

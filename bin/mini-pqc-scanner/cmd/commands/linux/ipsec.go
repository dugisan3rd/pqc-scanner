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
	"strings"
	"time"
)

// CheckIPsecInstallation checks if IPsec (strongSwan or libreswan) is installed
func CheckIPsecInstallation(results map[string]string) {
	// Check for strongSwan installation
	cmd := exec.Command("which", "strongswan")
	strongswanOutput, strongswanErr := cmd.Output()
	
	// Check for libreswan installation
	cmd = exec.Command("which", "ipsec")
	ipsecOutput, ipsecErr := cmd.Output()
	
	if (strongswanErr != nil || len(strongswanOutput) == 0) && 
	   (ipsecErr != nil || len(ipsecOutput) == 0) {
		results["IPsec"] = "Not installed"
		return
	}
	
	// Determine which implementation is installed
	if strongswanErr == nil && len(strongswanOutput) > 0 {
		strongswanPath := strings.TrimSpace(string(strongswanOutput))
		results["IPsec"] = "strongSwan installed"
		results["strongSwan Path"] = strongswanPath
		
		// Get strongSwan version
		cmd = exec.Command("strongswan", "version")
		versionOutput, err := cmd.Output()
		if err == nil {
			version := strings.TrimSpace(string(versionOutput))
			results["strongSwan Version"] = version
		}
	}
	
	if ipsecErr == nil && len(ipsecOutput) > 0 {
		ipsecPath := strings.TrimSpace(string(ipsecOutput))
		results["IPsec Command"] = ipsecPath
		
		// Get ipsec version
		cmd = exec.Command("ipsec", "version")
		versionOutput, err := cmd.Output()
		if err == nil {
			version := strings.TrimSpace(string(versionOutput))
			
			// Determine if it's strongSwan, libreswan or openswan
			if strings.Contains(strings.ToLower(version), "strongswan") {
				results["IPsec"] = "strongSwan installed"
				results["strongSwan Version"] = version
			} else if strings.Contains(strings.ToLower(version), "libreswan") {
				results["IPsec"] = "Libreswan installed"
				results["Libreswan Version"] = version
			} else if strings.Contains(strings.ToLower(version), "openswan") {
				results["IPsec"] = "Openswan installed"
				results["Openswan Version"] = version
			} else {
				results["IPsec"] = "Unknown IPsec implementation"
				results["IPsec Version"] = version
			}
		}
	}
	
	// Check for IPsec configuration files
	checkIPsecConfigs(results)
}

// checkIPsecConfigs checks for IPsec configuration files
func checkIPsecConfigs(results map[string]string) {
	// Common IPsec configuration paths
	configPaths := []string{
		"/etc/ipsec.conf",           // Main IPsec configuration
		"/etc/ipsec.secrets",        // IPsec secrets
		"/etc/strongswan/ipsec.conf", // strongSwan specific
		"/etc/strongswan/strongswan.conf", // strongSwan specific
		"/etc/swanctl/swanctl.conf", // Modern strongSwan config
	}
	
	configFound := false
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configFound = true
			results["Config Found"] = "true"
			results["Config Path"] = path
			
			// Parse the config file for crypto settings
			parseIPsecConfig(path, results)
		}
	}
	
	if !configFound {
		results["Config Found"] = "false"
	}
	
	// Check for certificates and analyze them
	checkIPsecCertificates(results)
	
	// Check runtime status of IPsec connections
	checkIPsecRuntimeStatus(results)
}

// parseIPsecConfig parses IPsec configuration files for crypto settings
func parseIPsecConfig(configPath string, results map[string]string) {
	file, err := os.Open(configPath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	
	// Regular expressions for crypto settings
	ikeRegex := regexp.MustCompile(`ike\s*=\s*(.+)`)
	espRegex := regexp.MustCompile(`esp\s*=\s*(.+)`)
	dhGroupRegex := regexp.MustCompile(`(modp\d+|ecp\d+|curve\w+)`)
	
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || line == "" {
			continue
		}
		
		// Check for IKE (Internet Key Exchange) settings
		if match := ikeRegex.FindStringSubmatch(line); len(match) > 1 {
			ikeAlgorithms := match[1]
			results["IKE Algorithms"] = ikeAlgorithms
			
			// Check for legacy/weak algorithms
			if strings.Contains(ikeAlgorithms, "des") || 
			   strings.Contains(ikeAlgorithms, "md5") || 
			   strings.Contains(ikeAlgorithms, "sha1") {
				results["Legacy IKE Algorithms"] = "true"
			}
			
			// Extract DH groups
			dhGroups := dhGroupRegex.FindAllString(ikeAlgorithms, -1)
			if len(dhGroups) > 0 {
				results["DH Groups"] = strings.Join(dhGroups, ", ")
				
				// Check for legacy/weak DH groups
				for _, group := range dhGroups {
					if group == "modp1024" || group == "modp1536" || group == "modp2048" {
						results["Legacy DH Groups"] = "true"
						results["DH Groups Security"] = "Insecure"
					} else if group == "modp4096" || group == "ecp256" {
						if results["DH Groups Security"] != "Insecure" {
							results["DH Groups Security"] = "Acceptable (Not PQC)"
						}
					} else if group == "modp8192" || strings.Contains(group, "curve25519") {
						if results["DH Groups Security"] != "Insecure" && 
						   results["DH Groups Security"] != "Acceptable (Not PQC)" {
							results["DH Groups Security"] = "Better (Still Not PQC)"
						}
					}
				}
			}
		}
		
		// Check for ESP (Encapsulating Security Payload) settings
		if match := espRegex.FindStringSubmatch(line); len(match) > 1 {
			espAlgorithms := match[1]
			results["ESP Algorithms"] = espAlgorithms
			
			// Check for legacy/weak algorithms
			if strings.Contains(espAlgorithms, "des") || 
			   strings.Contains(espAlgorithms, "md5") || 
			   strings.Contains(espAlgorithms, "sha1") {
				results["Legacy ESP Algorithms"] = "true"
			}
		}
	}
}

// checkIPsecCertificates checks for IPsec certificates and analyzes them
func checkIPsecCertificates(results map[string]string) {
	// Common certificate paths for IPsec
	certPaths := []string{
		"/etc/ipsec.d/certs",
		"/etc/strongswan/ipsec.d/certs",
		"/etc/swanctl/x509",
	}
	
	// Check for certificate directories
	certFound := false
	for _, certPath := range certPaths {
		if _, err := os.Stat(certPath); err == nil {
			certFound = true
			results["Certificate Path"] = certPath
			
			// Find PEM certificates in the directory
			certFiles, err := filepath.Glob(filepath.Join(certPath, "*.pem"))
			if err == nil && len(certFiles) > 0 {
				// Analyze the first certificate found
				analyzeCertificate(certFiles[0], results)
				break
			}
		}
	}
	
	// Check for private key directories
	privatePaths := []string{
		"/etc/ipsec.d/private",
		"/etc/strongswan/ipsec.d/private",
		"/etc/swanctl/private",
	}
	
	for _, privPath := range privatePaths {
		if _, err := os.Stat(privPath); err == nil {
			results["Private Key Path"] = privPath
			break
		}
	}
	
	if !certFound {
		results["Certificates"] = "Not found"
	}
}

// analyzeCertificate uses OpenSSL to analyze a certificate
func analyzeCertificate(certPath string, results map[string]string) {
	// Use OpenSSL to get certificate details
	cmd := exec.Command("openssl", "x509", "-in", certPath, "-text", "-noout")
	output, err := cmd.Output()
	if err != nil {
		results["Certificate Analysis"] = "Failed to analyze certificate"
		return
	}
	
	certInfo := string(output)
	results["Certificate Found"] = "true"
	
	// Check signature algorithm
	sigAlgRegex := regexp.MustCompile(`Signature Algorithm: (.+)`)
	if match := sigAlgRegex.FindStringSubmatch(certInfo); len(match) > 1 {
		sigAlg := match[1]
		results["Certificate Signature Algorithm"] = sigAlg
		
		// Check for legacy algorithms
		if strings.Contains(sigAlg, "md5") || strings.Contains(sigAlg, "sha1") {
			results["Legacy Certificate Algorithm"] = "true"
			results["Certificate Security"] = "Insecure"
		}
	}
	
	// Check public key algorithm
	pubKeyRegex := regexp.MustCompile(`Public Key Algorithm: (.+)`)
	if match := pubKeyRegex.FindStringSubmatch(certInfo); len(match) > 1 {
		pubKey := match[1]
		results["Certificate Public Key Algorithm"] = pubKey
		
		// Check for RSA vs ECC
		if strings.Contains(pubKey, "rsa") {
			// Check RSA key size
			rsaSizeRegex := regexp.MustCompile(`RSA Public-Key: \(([0-9]+) bit\)`)
			if sizeMatch := rsaSizeRegex.FindStringSubmatch(certInfo); len(sizeMatch) > 1 {
				results["RSA Key Size"] = sizeMatch[1] + " bit"
				
				// Evaluate RSA key size security
				if sizeMatch[1] == "1024" || sizeMatch[1] == "2048" {
					if results["Certificate Security"] != "Insecure" {
						results["Certificate Security"] = "Vulnerable to quantum attacks"
					}
				} else if sizeMatch[1] == "4096" {
					if results["Certificate Security"] != "Insecure" && 
					   results["Certificate Security"] != "Vulnerable to quantum attacks" {
						results["Certificate Security"] = "Better but still quantum vulnerable"
					}
				}
			}
		} else if strings.Contains(pubKey, "ec") || strings.Contains(pubKey, "id-ecPublicKey") {
			// ECC is better than RSA for classical security but still quantum vulnerable
			if results["Certificate Security"] != "Insecure" {
				results["Certificate Security"] = "ECC (better classical security, still quantum vulnerable)"
			}
		}
	}
}

// checkIPsecRuntimeStatus checks the runtime status of IPsec connections
func checkIPsecRuntimeStatus(results map[string]string) {
	// First check if IPsec processes are running
	cmd := exec.Command("ps", "-ef")
	psOutput, err := cmd.Output()
	
	if err == nil {
		processList := string(psOutput)
		
		// Look for common IPsec process names
		isRunning := strings.Contains(processList, "/usr/lib/ipsec/charon") || 
			        strings.Contains(processList, "pluto") || 
			        strings.Contains(processList, "strongswan") ||
			        strings.Contains(processList, "/usr/sbin/ipsec")
		
		if isRunning {
			results["Runtime Status"] = "Running"
			results["Is Running"] = "true"
		} else {
			results["Runtime Status"] = "Not running"
			results["Is Running"] = "false"
			// If not running, we can skip checking active connections
			results["Active Connections"] = "false"
			return
		}
	}
	
	// If processes are running, check for active connections
	cmd = exec.Command("ipsec", "statusall")
	statusOutput, err := cmd.Output()
	if err != nil {
		// ipsec statusall failed, try status instead
		cmd = exec.Command("ipsec", "status")
		statusOutput, err = cmd.Output()
		if err != nil {
			// If we couldn't get status but we know it's running from ps
			if results["Is Running"] == "true" {
				results["Connection Status"] = "Running but connection status unknown"
				results["Active Connections"] = "unknown"
			} else {
				results["Runtime Status"] = "Status unknown"
			}
			return
		}
	}
	
	status := string(statusOutput)
	
	// Check for active connections
	if strings.Contains(status, "ESTABLISHED") {
		results["Active Connections"] = "true"
		results["Connection Status"] = "Active connections established"
		
		// Extract active connection details (simplified)
		connRegex := regexp.MustCompile(`([^\s]+)\[\d+\]:.*ESTABLISHED`)
		matches := connRegex.FindAllStringSubmatch(status, -1)
		
		if len(matches) > 0 {
			connections := make([]string, 0, len(matches))
			for _, match := range matches {
				if len(match) > 1 {
					connections = append(connections, match[1])
				}
			}
			
			if len(connections) > 0 {
				results["Active Connection Names"] = strings.Join(connections, ", ")
			}
		}
	} else {
		results["Active Connections"] = "false"
		results["Connection Status"] = "Running but no active connections"
	}
}

// CheckIPsecPQCReadiness checks if the IPsec implementation supports PQC
func CheckIPsecPQCReadiness(results map[string]string) {
	// Check if strongSwan is installed
	if _, ok := results["strongSwan Path"]; ok {
		// Check if strongSwan has OQS plugin
		cmd := exec.Command("strongswan", "list-plugins")
		output, err := cmd.Output()
		if err == nil {
			plugins := string(output)
			if strings.Contains(plugins, "oqs") {
				results["PQC Support"] = "Experimental support via OQS plugin"
				results["PQC Readiness"] = "Partial - Experimental OQS plugin available"
			} else {
				results["PQC Support"] = "Not detected"
				
				// Check DH groups and certificates for PQC readiness assessment
				dhSecurity, dhOK := results["DH Groups Security"]
				certSecurity, certOK := results["Certificate Security"]
				
				if dhOK && certOK {
					if strings.Contains(dhSecurity, "Insecure") || strings.Contains(certSecurity, "Insecure") {
						results["PQC Readiness"] = "Poor - Using insecure algorithms, upgrade needed before PQC"
					} else if strings.Contains(dhSecurity, "Acceptable") && strings.Contains(certSecurity, "Acceptable") {
						results["PQC Readiness"] = "Fair - Using acceptable algorithms, but not PQC-ready"
					} else if strings.Contains(dhSecurity, "Better") || strings.Contains(certSecurity, "Better") {
						results["PQC Readiness"] = "Good - Using strong algorithms, but still not PQC-ready"
					} else {
						results["PQC Readiness"] = "Unknown - Could not assess cryptographic strength"
					}
				} else {
					results["PQC Readiness"] = "Unknown - Could not assess cryptographic configuration"
				}
			}
		} else {
			results["PQC Support"] = "Unknown (could not check plugins)"
			results["PQC Readiness"] = "Unknown - Could not check for PQC plugins"
		}
	} else {
		results["PQC Support"] = "Not available (IPsec implementation does not support PQC)"
		results["PQC Readiness"] = "Poor - Current implementation has no PQC support"
	}
	
	// Add recommendations
	pqcRecommendation := "Monitor for PQC support in future releases. " +
		"Consider using strongSwan with the OQS plugin for experimental PQC support. " +
		"Use the strongest available DH groups and certificates in the meantime."
	
	results["PQC Recommendation"] = pqcRecommendation
}

// Note: printIPsecAuditResults function has been removed as recommendations are now handled centrally

// IpsecReport represents the structure of the JSON report for the ipsec command
type IpsecReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	IpsecInfo      map[string]string      `json:"ipsec_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestIPsec command audits IPsec configuration for PQC readiness
func TestIPsec(jsonOutput bool) []scan.Recommendation {
	// Create a map to store detection results
	results := make(map[string]string)
	
	// Print header
	fmt.Println("=== IPsec PQC Configuration Check ===")
	
	// Check if IPsec is installed
	CheckIPsecInstallation(results)
	
	if ipsec, ok := results["IPsec"]; ok && !strings.Contains(ipsec, "Not installed") {
		// Print installation status
		fmt.Printf("\u2713 %s\n", ipsec)
		
		// Print version if available
		if version, ok := results["strongSwan Version"]; ok {
			fmt.Printf("  Version: %s\n", version)
		} else if version, ok := results["Libreswan Version"]; ok {
			fmt.Printf("  Version: %s\n", version)
		} else if version, ok := results["Openswan Version"]; ok {
			fmt.Printf("  Version: %s\n", version)
		} else if version, ok := results["IPsec Version"]; ok {
			fmt.Printf("  Version: %s\n", version)
		}
		
		// Check IPsec configurations
		fmt.Println("\nAnalyzing IPsec configuration:")
		checkIPsecConfigs(results)
		
		// Print configuration results
		if configFile, ok := results["Config File"]; ok {
			fmt.Printf("  \u2713 Configuration found: %s\n", configFile)
		} else {
			fmt.Println("  \u2717 No IPsec configuration file found")
		}
		
		if secretsFile, ok := results["Secrets File"]; ok {
			fmt.Printf("  \u2713 Secrets configuration found: %s\n", secretsFile)
		}
		
		if connsDir, ok := results["Conn Dir"]; ok {
			fmt.Printf("  \u2713 Connection directory found: %s\n", connsDir)
		}
		
		// Print DH Groups if available
		if dhGroups, ok := results["DH Groups"]; ok {
			fmt.Println("\nDiffie-Hellman Groups:")
			fmt.Printf("  %s\n", dhGroups)
			if security, ok := results["DH Groups Security"]; ok {
				if strings.Contains(security, "Insecure") {
					fmt.Printf("  \u2717 %s\n", security)
				} else if strings.Contains(security, "Acceptable") {
					fmt.Printf("  \u26A0 %s\n", security)
				} else {
					fmt.Printf("  \u2713 %s\n", security)
				}
			}
		}
		
		// Print Certificate info if available
		if certPath, ok := results["Certificate Path"]; ok {
			fmt.Println("\nIPsec Certificate Analysis:")
			fmt.Printf("  \u2713 Certificate found: %s\n", certPath)
			
			if keyAlg, ok := results["Certificate Key Algorithm"]; ok {
				fmt.Printf("  Key Algorithm: %s\n", keyAlg)
			}
			
			if keySecurity, ok := results["Certificate Security"]; ok {
				if strings.Contains(keySecurity, "Insecure") {
					fmt.Printf("  \u2717 %s\n", keySecurity)
				} else if strings.Contains(keySecurity, "Acceptable") {
					fmt.Printf("  \u26A0 %s\n", keySecurity)
				} else {
					fmt.Printf("  \u2713 %s\n", keySecurity)
				}
			}
		} else {
			fmt.Println("\nIPsec Certificate Analysis:")
			fmt.Println("  \u2717 No certificates found")
		}
		
		// Check PQC readiness
		fmt.Println("\nPQC Readiness Assessment:")
		CheckIPsecPQCReadiness(results)
		
		// Print PQC readiness results
		if pqcSupport, ok := results["PQC Support"]; ok {
			if strings.Contains(pqcSupport, "Not") {
				fmt.Printf("  \u2717 %s\n", pqcSupport)
			} else if strings.Contains(pqcSupport, "Experimental") {
				fmt.Printf("  \u26A0 %s\n", pqcSupport)
			} else {
				fmt.Printf("  \u2713 %s\n", pqcSupport)
			}
		}
		
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(pqcReadiness, "Poor") {
				fmt.Printf("  \u2717 %s\n", pqcReadiness)
			} else if strings.Contains(pqcReadiness, "Fair") || strings.Contains(pqcReadiness, "Unknown") {
				fmt.Printf("  \u26A0 %s\n", pqcReadiness)
			} else {
				fmt.Printf("  \u2713 %s\n", pqcReadiness)
			}
		}
		
		fmt.Println("\nIPsec PQC Support Summary:")
		pqcStatus := "Not supported"
		if pqcSupport, ok := results["PQC Support"]; ok && strings.Contains(pqcSupport, "Experimental") {
			pqcStatus = "Experimental support via OQS plugin"
		}
		fmt.Printf("  PQC Support: %s\n", pqcStatus)
		
		// Print final message

	} else {
		fmt.Println("\u2717 IPsec is not installed")

	}
	
	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	if awsResults := inspectAWSLoadBalancerForIPsec(); len(awsResults) > 0 {
		for key, value := range awsResults {
			results[key] = value
		}
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateIPsecStatus(results, rm)

	// Generate recommendations based on scan results
	recommendations := generateIPsecRecommendations(results)

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
		report := IpsecReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			IpsecInfo:      results,
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
			filePath := filepath.Join(reportDir, "ipsec.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/ipsec.json")
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

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

// CAReport represents the structure of the JSON report for the ca command
type CAReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	CAInfo         map[string]string      `json:"ca_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestCA command audits Certificate Authority configurations for PQC readiness
func TestCA(jsonOutput bool) []scan.Recommendation {
	// Create a map to store detection results
	results := make(map[string]string)
	
	// Print header
	fmt.Println("=== CA PQC Configuration Check ===")
	
	// Check CA installations and configurations
	fmt.Println("\nCA Software Installations:")
	checkCAInstallations(results)
	
	// Print installation statuses with visual indicators
	if openssl, ok := results["OpenSSL"]; ok {
		if openssl == "Installed" {
			fmt.Printf("  \u2713 OpenSSL is installed")
			if version, ok := results["OpenSSL Version"]; ok {
				fmt.Printf(": %s\n", version)
			} else {
				fmt.Println()
			}
		} else {
			fmt.Println("  \u2717 OpenSSL is not installed")
		}
	}
	
	if easyRSA, ok := results["EasyRSA"]; ok {
		if strings.Contains(easyRSA, "Installed") {
			fmt.Printf("  \u2713 EasyRSA is %s\n", strings.ToLower(easyRSA))
		} else {
			fmt.Println("  \u2717 EasyRSA is not installed")
		}
	}
	
	if certbot, ok := results["Certbot"]; ok {
		if certbot == "Installed" {
			fmt.Printf("  \u2713 Certbot is installed")
			if version, ok := results["Certbot Version"]; ok {
				fmt.Printf(": %s\n", version)
			} else {
				fmt.Println()
			}
		} else {
			fmt.Println("  \u2717 Certbot is not installed")
		}
	}
	
	if stepCA, ok := results["Step-CA"]; ok {
		if strings.Contains(stepCA, "Installed") {
			fmt.Printf("  \u2713 %s\n", stepCA)
		} else {
			fmt.Println("  \u2717 Step-CA is not installed")
		}
	}
	
	if cfssl, ok := results["CFSSL"]; ok {
		if cfssl == "Installed" {
			fmt.Printf("  \u2713 CFSSL is installed")
			if version, ok := results["CFSSL Version"]; ok {
				fmt.Printf(": %s\n", version)
			} else {
				fmt.Println()
			}
			
			if cfsslJSON, ok := results["CFSSL JSON"]; ok && cfsslJSON == "Installed" {
				fmt.Println("  \u2713 CFSSL JSON is installed")
			} else {
				fmt.Println("  \u2717 CFSSL JSON is not installed")
			}
		} else {
			fmt.Println("  \u2717 CFSSL is not installed")
		}
	}
	
	// Check system CA certificates
	fmt.Println("\nSystem CA Certificate Analysis:")
	checkSystemCACertificates(results)
	
	// Print system CA certificates information
	if caPath, ok := results["System CA Path"]; ok {
		fmt.Printf("  \u2713 System CA directory found: %s\n", caPath)
		if certCount, ok := results["System CA Certificate Count"]; ok {
			fmt.Printf("  System contains %s trusted certificates\n", certCount)
		}
	} else {
		fmt.Println("  \u2717 No system CA directory found")
	}
	
	if bundle, ok := results["Mozilla CA Bundle"]; ok {
		fmt.Printf("  \u2713 Mozilla CA bundle found: %s\n", bundle)
	} else {
		fmt.Println("  \u2717 No Mozilla CA bundle found")
	}
	
	// Check for custom CA certificates
	fmt.Println("\nCustom CA Certificate Analysis:")
	checkCustomCACertificates(results)
	
	// Print custom CA information
	if customCACount, ok := results["Custom CA Count"]; ok {
		count, _ := fmt.Sscanf(customCACount, "%d", new(int))
		if count > 0 && customCACount != "0" {
			fmt.Printf("  \u2713 Found %s potential custom CA private keys\n", customCACount)
		} else {
			fmt.Println("  \u2717 No custom CA private keys detected")
		}
	}
	
	// Check for PQC readiness
	fmt.Println("\nPQC Readiness Assessment:")
	checkCAPQCReadiness(results)
	
	// Print PQC readiness information
	if opensslSupport, ok := results["OpenSSL PQC Support"]; ok {
		if strings.Contains(opensslSupport, "Yes") {
			fmt.Printf("  \u2713 %s\n", opensslSupport)
		} else if strings.Contains(opensslSupport, "Partial") {
			fmt.Printf("  \u26A0 %s\n", opensslSupport)
		} else {
			fmt.Printf("  \u2717 %s\n", opensslSupport)
		}
	}
	
	if oqsProvider, ok := results["OQS Provider"]; ok {
		if strings.Contains(oqsProvider, "Installed") {
			fmt.Printf("  \u2713 %s\n", oqsProvider)
		} else {
			fmt.Printf("  \u2717 %s\n", oqsProvider)
		}
	}
	
	fmt.Println("\nCA PQC Support Summary:")
	if pqcReadiness, ok := results["PQC Readiness"]; ok {
		if strings.Contains(pqcReadiness, "Good") {
			fmt.Printf("  \u2713 %s\n", pqcReadiness)
		} else if strings.Contains(pqcReadiness, "Fair") {
			fmt.Printf("  \u26A0 %s\n", pqcReadiness)
		} else {
			fmt.Printf("  \u2717 %s\n", pqcReadiness)
		}
	}
	
	if pqcRecommendation, ok := results["PQC Recommendation"]; ok {
		fmt.Println("\nSuggested Next Steps:")
		fmt.Printf("  %s\n", pqcRecommendation)
	}
	
	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	if awsResults := inspectAWSLoadBalancerForCA(); len(awsResults) > 0 {
		for key, value := range awsResults {
			results[key] = value
		}
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateCAStatus(results, rm)

	// Generate recommendations based on detection results
	recommendations := generateCARecommendations(results)

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
		report := CAReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			CAInfo:         results,
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
			filePath := filepath.Join(reportDir, "ca.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/ca.json")
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

// checkCAInstallations checks for common CA software installations
func checkCAInstallations(results map[string]string) {
	fmt.Println("Checking for CA software installations...")
	
	// Check for OpenSSL (most basic CA tool)
	if opensslPath, err := exec.LookPath("openssl"); err == nil {
		results["OpenSSL"] = "Installed"
		
		// Get OpenSSL version
		cmd := exec.Command(opensslPath, "version")
		output, err := cmd.Output()
		if err == nil {
			results["OpenSSL Version"] = strings.TrimSpace(string(output))
		}
	} else {
		results["OpenSSL"] = "Not installed"
	}
	
	// Check for easy-rsa
	if _, err := exec.LookPath("easyrsa"); err == nil {
		results["EasyRSA"] = "Installed"
	} else if _, err := os.Stat("/usr/share/easy-rsa"); err == nil {
		results["EasyRSA"] = "Installed (package)"
	} else {
		results["EasyRSA"] = "Not installed"
	}
	
	// Check for certbot (Let's Encrypt)
	if certbotPath, err := exec.LookPath("certbot"); err == nil {
		results["Certbot"] = "Installed"
		
		// Get Certbot version
		cmd := exec.Command(certbotPath, "--version")
		output, err := cmd.Output()
		if err == nil {
			results["Certbot Version"] = strings.TrimSpace(string(output))
		}
	} else {
		results["Certbot"] = "Not installed"
	}
	
	// Check for step-ca (smallstep CA)
	stepCAInstalled := false
	
	// First check for step-ca binary
	if _, err := exec.LookPath("step-ca"); err == nil {
		cmd := exec.Command("step-ca", "version")
		output, err := cmd.Output()
		if err == nil {
			results["Step-CA"] = fmt.Sprintf("Installed (step-ca %s)", strings.TrimSpace(string(output)))
		} else {
			results["Step-CA"] = "Installed"
		}
		stepCAInstalled = true
	}
	
	// If step-ca binary not found, check for step binary (CLI tool that can also function as CA)
	if !stepCAInstalled {
		if _, err := exec.LookPath("step"); err == nil {
			cmd := exec.Command("step", "version")
			output, err := cmd.Output()
			if err == nil {
				results["Step-CA"] = fmt.Sprintf("Installed (step CLI %s)", strings.TrimSpace(string(output)))
				stepCAInstalled = true
			}
		}
	}
	
	// If neither step-ca nor step found
	if !stepCAInstalled {
		results["Step-CA"] = "Not installed"
	}
	
	// Check for CFSSL (Cloudflare's PKI toolkit)
	if cfsslPath, err := exec.LookPath("cfssl"); err == nil {
		results["CFSSL"] = "Installed"
		
		// Get CFSSL version
		cmd := exec.Command(cfsslPath, "version")
		output, err := cmd.Output()
		if err == nil {
			results["CFSSL Version"] = strings.TrimSpace(string(output))
		}
		
		// Check for cfssljson tool
		if _, err := exec.LookPath("cfssljson"); err == nil {
			results["CFSSL JSON"] = "Installed"
		} else {
			results["CFSSL JSON"] = "Not installed"
		}
	} else {
		results["CFSSL"] = "Not installed"
	}
}

// checkSystemCACertificates checks system CA certificates
func checkSystemCACertificates(results map[string]string) {
	fmt.Println("Checking system CA certificates...")
	
	// Common paths for system CA certificates
	caPaths := []string{
		"/etc/ssl/certs",
		"/etc/pki/tls/certs",
		"/etc/pki/ca-trust/extracted/pem",
		"/usr/local/share/ca-certificates",
	}
	
	certCount := 0
	for _, caPath := range caPaths {
		if _, err := os.Stat(caPath); err == nil {
			results["System CA Path"] = caPath
			
			// Count certificates in the directory
			filepath.Walk(caPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				if !info.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".pem") || 
									 strings.HasSuffix(strings.ToLower(path), ".crt") || 
									 strings.HasSuffix(strings.ToLower(path), ".cer")) {
					certCount++
				}
				return nil
			})
			
			break
		}
	}
	
	results["System CA Certificate Count"] = fmt.Sprintf("%d", certCount)
	
	// Check for Mozilla CA certificate bundle
	mozillaBundlePaths := []string{
		"/etc/ssl/certs/ca-certificates.crt",  // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",    // RHEL/CentOS
	}
	
	for _, bundlePath := range mozillaBundlePaths {
		if _, err := os.Stat(bundlePath); err == nil {
			results["Mozilla CA Bundle"] = bundlePath
			break
		}
	}
}

// checkCustomCACertificates checks for custom CA certificates
func checkCustomCACertificates(results map[string]string) {
	fmt.Println("Checking for custom CA certificates...")
	
	// Common paths for custom CA certificates
	customCAPaths := []string{
		"/etc/ssl/private",
		"/etc/pki/CA/private",
		"/etc/openvpn/easy-rsa/pki",
		"/etc/ipsec.d/private",
		"/etc/letsencrypt/live",
	}
	
	customCACount := 0
	for _, caPath := range customCAPaths {
		if _, err := os.Stat(caPath); err == nil {
			// Count private keys in the directory
			filepath.Walk(caPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				if !info.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".key") || 
									 strings.HasSuffix(strings.ToLower(path), ".pem")) {
					// Try to determine if it's a CA certificate
					if isPrivateKeyFile(path) {
						customCACount++
					}
				}
				return nil
			})
		}
	}
	
	results["Custom CA Count"] = fmt.Sprintf("%d", customCACount)
}

// isPrivateKeyFile checks if a file is likely a private key
func isPrivateKeyFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "PRIVATE KEY") {
			return true
		}
	}
	
	return false
}

// checkCAPQCReadiness assesses CA PQC readiness
func checkCAPQCReadiness(results map[string]string) {
	fmt.Println("Assessing PQC readiness...")
	
	// Check OpenSSL version for PQC support
	if version, ok := results["OpenSSL Version"]; ok {
		// Extract version number
		re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
		match := re.FindStringSubmatch(version)
		if len(match) > 1 {
			versionStr := match[1]
			
			// OpenSSL 3.2.0+ has PQC support
			if strings.HasPrefix(versionStr, "3.") && (strings.HasPrefix(versionStr, "3.2.") || strings.HasPrefix(versionStr, "3.3.")) {
				results["OpenSSL PQC Support"] = "Yes - Native ML-KEM support"
			} else if strings.HasPrefix(versionStr, "3.") {
				results["OpenSSL PQC Support"] = "Partial - Supports OQS provider plugin"
			} else {
				results["OpenSSL PQC Support"] = "No - Upgrade to OpenSSL 3.2.0+ recommended"
			}
		}
	}
	
	// Check for OQS provider for OpenSSL using a comprehensive approach
	// First, try using 'openssl list -providers' to check if OQS is registered
	cmd := exec.Command("openssl", "list", "-providers")
	output, err := cmd.Output()
	oqsInstalled := false
	oqsPath := ""
	
	if err == nil && strings.Contains(string(output), "oqs") {
		oqsInstalled = true
		results["OQS Provider"] = "Installed (registered with OpenSSL)"
	} else {
		// If not found via openssl command, check common file paths
		// Common base directories to search
		baseDirs := []string{
			"/usr/lib",
			"/usr/lib64",
			"/usr/local/lib",
			"/usr/local/lib64",
			"/opt/lib",
			"/opt/lib64",
		}
		
		// Common OQS provider subdirectories
		oqsSubdirs := []string{
			"ossl-modules",
			"openssl/ossl-modules",
			"oqs-provider",
			"oqsprovider",
			"openssl/oqs-provider",
			"openssl/providers",
			"providers",
			"", // Check directly in lib directories
		}
		
		// Common OQS provider filenames
		oqsFilenames := []string{
			"oqsprovider.so",
			"liboqsprov.so",
		}
		
		// Check for OQS provider
		for _, baseDir := range baseDirs {
			for _, subdir := range oqsSubdirs {
				for _, filename := range oqsFilenames {
					path := filepath.Join(baseDir, subdir, filename)
					if _, err := os.Stat(path); err == nil {
						oqsInstalled = true
						oqsPath = path
						break
					}
				}
				if oqsInstalled {
					break
				}
			}
			if oqsInstalled {
				break
			}
		}
		
		// Also check in home directory if not found in system paths
		if !oqsInstalled {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				// Common subdirectories in home where OQS might be installed
				homeSubdirs := []string{
					"oqs-provider/build/lib",
					"liboqs/build/lib",
				}
				
				for _, subdir := range homeSubdirs {
					for _, filename := range oqsFilenames {
						path := filepath.Join(homeDir, subdir, filename)
						if _, err := os.Stat(path); err == nil {
							oqsInstalled = true
							oqsPath = path
							break
						}
					}
					if oqsInstalled {
						break
					}
				}
			}
		}
		
		// Check if OPENSSL_MODULES environment variable is set
		if !oqsInstalled {
			if modulesPath := os.Getenv("OPENSSL_MODULES"); modulesPath != "" {
				for _, filename := range oqsFilenames {
					path := filepath.Join(modulesPath, filename)
					if _, err := os.Stat(path); err == nil {
						oqsInstalled = true
						oqsPath = path
						break
					}
				}
			}
		}
		
		if oqsInstalled {
			results["OQS Provider"] = fmt.Sprintf("Installed (%s)", oqsPath)
		}
	}
	
	// If OQS provider is not found after all checks
	if _, ok := results["OQS Provider"]; !ok {
		results["OQS Provider"] = "Not installed"
	}
	
	// Overall PQC readiness assessment
	if opensslSupport, ok := results["OpenSSL PQC Support"]; ok {
		if strings.Contains(opensslSupport, "Yes") {
			results["PQC Readiness"] = "Good - Native PQC support available"
		} else if strings.Contains(opensslSupport, "Partial") && strings.Contains(results["OQS Provider"], "Installed") {
			results["PQC Readiness"] = "Fair - PQC support via OQS provider"
		} else if strings.Contains(opensslSupport, "Partial") {
			results["PQC Readiness"] = "Limited - OpenSSL supports OQS provider but it's not installed"
		} else {
			results["PQC Readiness"] = "Poor - No PQC support detected"
		}
	} else {
		results["PQC Readiness"] = "Unknown - Could not determine PQC readiness"
	}
	
	// Generate recommendations
	if strings.Contains(results["PQC Readiness"], "Poor") || strings.Contains(results["PQC Readiness"], "Limited") {
		results["PQC Recommendation"] = "Upgrade to OpenSSL 3.2.0+ for native ML-KEM support or install the OQS provider"
	} else if strings.Contains(results["PQC Readiness"], "Fair") {
		results["PQC Recommendation"] = "Consider upgrading to OpenSSL 3.2.0+ for native ML-KEM support"
	} else {
		// No specific recommendation needed for good PQC support
		delete(results, "PQC Recommendation")
	}
}

// Note: printCAAuditResults function has been removed as recommendations are now handled by generateCARecommendations

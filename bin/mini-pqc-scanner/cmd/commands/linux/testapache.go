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

// checkApacheRunning checks if Apache is running
func checkApacheRunning(results map[string]string) bool {
	// Try to detect if Apache is running using ps
	cmd := exec.Command("ps", "-ef")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	
	outputStr := string(output)
	
	// Look for Apache process
	apacheRunning := false
	for _, processName := range []string{"httpd", "apache2"} {
		if strings.Contains(outputStr, processName) && !strings.Contains(outputStr, "grep "+processName) {
			apacheRunning = true
			break
		}
	}
	
	if !apacheRunning {
		results["Apache Status"] = "Not running"
		return false
	}
	
	results["Apache Status"] = "Running"
	return true
}

// checkApacheInstallation checks if Apache is installed and gets its version
func checkApacheInstallation(results map[string]string) {
	// Try both common Apache binary names
	apacheBinaries := []string{"httpd", "apache2"}
	apacheInstalled := false

	for _, binary := range apacheBinaries {
		cmd := exec.Command("which", binary)
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			apachePath := strings.TrimSpace(string(output))
			results["Apache Path"] = apachePath
			apacheInstalled = true

			// Get Apache version
			cmd = exec.Command(binary, "-v")
			output, err = cmd.CombinedOutput()
			if err == nil {
				version := strings.TrimSpace(string(output))
				results["Apache"] = version
			} else {
				results["Apache"] = "Installed (version unknown)"
			}

			break
		}
	}

	if !apacheInstalled {
		results["Apache"] = "Not installed"
		return
	}

	// Check if Apache is running
	apacheRunningResults := make(map[string]string)
	if checkApacheRunning(apacheRunningResults) {
		results["Apache Status"] = "Running"
	} else {
		results["Apache Status"] = "Not running"
	}

	// Get OpenSSL version used by Apache if available
	if apachePath, ok := results["Apache Path"]; ok {
		apacheOpenSSLResults := make(map[string]string)
		checkApacheOpenSSLVersion(apachePath, apacheOpenSSLResults)
		if version, ok := apacheOpenSSLResults["OpenSSL Version"]; ok && version != "Unknown" {
			results["Apache OpenSSL"] = version
		}
	}
}


// testApachePQCConnection tests if Apache can negotiate PQC algorithms
func testApachePQCConnection(results map[string]string) {
	// Check if Apache is running first
	if !checkApacheRunning(results) {
		results["PQC Connection Test"] = "Apache is not running"
		return
	}
	
	// First, determine the port Apache is listening on
	port := "443" // Default HTTPS port
	portsToTry := []string{"443", "8443"} // Default ports to try if no SSL port is found
	portFound := false
	
	// Check if we can find a different port from the config
	if configPath, ok := results["SSL Config"]; ok {
		// Try to find the port in the config file
		portRe := regexp.MustCompile(`(?i)Listen\s+([0-9]+).*SSL`)
		if file, err := os.Open(configPath); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if match := portRe.FindStringSubmatch(line); match != nil {
					port = match[1]
					portsToTry = []string{port} // Only try the found port
					portFound = true
					break
				}
			}
		}
	}
	
	// Also check ports.conf if available and we haven't found a port yet
	if !portFound {
		portsConfPaths := []string{
			"/etc/apache2/ports.conf",
			"/etc/httpd/conf/ports.conf",
		}
		
		for _, portsPath := range portsConfPaths {
			if _, err := os.Stat(portsPath); err == nil {
				if file, err := os.Open(portsPath); err == nil {
					defer file.Close()
					scanner := bufio.NewScanner(file)
					portRe := regexp.MustCompile(`(?i)Listen\s+([0-9]+).*SSL`)
					for scanner.Scan() {
						line := scanner.Text()
						if match := portRe.FindStringSubmatch(line); match != nil {
							port = match[1]
							portsToTry = []string{port} // Only try the found port
							portFound = true
							break
						}
					}
				}
				if portFound {
					break
				}
			}
		}
	}
	
	// Try each port until we find one that works
	for _, currentPort := range portsToTry {
		// First, test basic SSL connectivity without PQC parameters
		basicCmd := exec.Command("timeout", "5", "openssl", "s_client", "-connect", "localhost:"+currentPort)
		basicOutput, basicErr := basicCmd.CombinedOutput()
		basicOutputStr := string(basicOutput)
		
		// Check if basic connection was successful
		if basicErr == nil || strings.Contains(basicOutputStr, "CONNECTED") && strings.Contains(basicOutputStr, "Server certificate") {
			// Basic connection successful, now test PQC support
			cmd := exec.Command("timeout", "5", "openssl", "s_client", "-connect", "localhost:"+currentPort, "-curves", "kyber768")
			output, _ := cmd.CombinedOutput()
			outputStr := string(output)
			
			// Extract server temp key info if available
			tempKeyRe := regexp.MustCompile(`Server Temp Key:\s+(.+)`)
			tempKeyMatch := tempKeyRe.FindStringSubmatch(outputStr)
			
			// Check for PQC negotiation
			if strings.Contains(outputStr, "Server Temp Key: X25519, kyber") {
				results["PQC Connection Test"] = "Successfully negotiated Kyber on port " + currentPort
			} else if tempKeyMatch != nil {
				results["PQC Connection Test"] = "Connected on port " + currentPort + " but using " + tempKeyMatch[1] + " (no PQC)"
			} else if strings.Contains(outputStr, "Server certificate") {
				results["PQC Connection Test"] = "Connected on port " + currentPort + " but no PQC support detected"
			} else {
				// Extract protocol and cipher if available
				protocolRe := regexp.MustCompile(`Protocol\s+:\s+(.+)`)
				protocolMatch := protocolRe.FindStringSubmatch(outputStr)
				protocolInfo := ""
				if protocolMatch != nil {
					protocolInfo = " using " + protocolMatch[1]
				}
				results["PQC Connection Test"] = "Connected on port " + currentPort + protocolInfo + " but could not determine key exchange"
			}
			return
		}
	}
	
	// If we get here, all connection attempts failed
	results["PQC Connection Test"] = "Failed to connect to Apache SSL on port " + port
}

// ApacheReport represents the structure of the JSON report for the apache command
type ApacheReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	ApacheInfo     map[string]string      `json:"apache_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestApache checks Apache configuration for PQC support
func TestApache(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Apache PQC Configuration Check ===")

	// Results map
	results := make(map[string]string)

	// Check AWS environment and load balancers for Apache context
	checkAWSEnvironmentForApache(results)

	// Check for OQS provider installation
	checkOQSProviderInstallation(results)

	// Find Apache configuration using the improved finder

	// Check if Apache is installed
	apacheInstalled := false
	apachePath := ""
	if _, err := os.Stat("/usr/sbin/apache2"); err == nil {
		apacheInstalled = true
		apachePath = "/usr/sbin/apache2"
		results["Apache Installed"] = "Yes (/usr/sbin/apache2)"
		fmt.Println("Apache installed:", apachePath)
	} else if _, err := os.Stat("/usr/sbin/httpd"); err == nil {
		apacheInstalled = true
		apachePath = "/usr/sbin/httpd"
		results["Apache Installed"] = "Yes (/usr/sbin/httpd)"
		fmt.Println("Apache installed:", apachePath)
	} else {
		results["Apache Installed"] = "No"
		fmt.Println("Apache not detected on this system.")
		return generateApacheRecommendations(results)
	}

	// Check OpenSSL version used by Apache
	if apacheInstalled {
		checkApacheOpenSSLVersion(apachePath, results)
		if version, ok := results["OpenSSL Version"]; ok && version != "Unknown" {
			fmt.Println("OpenSSL version:", version)
		} else {
			fmt.Println("Could not determine OpenSSL version used by Apache")
		}
	}

	// Check for OQS provider
	if provider, ok := results["OQS Provider"]; ok {
		if strings.Contains(provider, "Installed") {
			fmt.Println("OQS Provider found:", provider)
		} else {
			fmt.Println("OQS Provider not found")
		}
	} else {
		fmt.Println("OQS Provider not found")
	}

	// Find Apache config using the improved finder
	apacheConfPath, err := FindApacheConfigFile()

	fmt.Println("\nAnalyzing Apache configuration:")
	if err != nil || apacheConfPath == "" {
		fmt.Println("Standard Apache configuration not found")
		results["Apache Config"] = "Not found in standard locations"
	} else {
		fmt.Println("Apache config found:", apacheConfPath)
		results["Apache Config"] = apacheConfPath
		
		// Parse the config file
		fmt.Println("  Looking for PQC-related settings...")
		parseApacheConfig(apacheConfPath, results)
		
		// Show detected PQC settings
		if kyber, ok := results["Kyber KEM"]; ok && kyber == "Configured" {
			fmt.Println("Kyber KEM support found in Apache config")
		} else {
			fmt.Println("Kyber KEM support not found in Apache config")
		}
		
		if hybrid, ok := results["Hybrid Groups"]; ok && hybrid == "Configured" {
			fmt.Println("Hybrid Groups support found in Apache config")
		} else {
			fmt.Println("Hybrid Groups support not found in Apache config")
		}
		
		if tls, ok := results["TLS 1.3"]; ok && tls == "Enabled" {
			fmt.Println("TLS 1.3 support found in Apache config")
		} else {
			fmt.Println("TLS 1.3 support not found in Apache config - required for PQC")
		}
	}

	// Check for SSL module configuration
	sslConfPath := ""
	sslConfPaths := FindApacheSSLConfigFiles()

	if len(sslConfPaths) > 0 {
		sslConfPath = sslConfPaths[0] // Use the first found SSL config
		results["SSL Config"] = sslConfPath
		fmt.Println("\nSSL module configuration found:", sslConfPath)
		fmt.Println("  Looking for SSL PQC-related settings...")
		parseApacheConfig(sslConfPath, results)
	}
	
	if sslConfPath == "" {
		fmt.Println("\nSSL module configuration not found in standard locations")
	}

	// Check for included config files
	if includeDir, ok := results["Include Directory"]; ok {
		fmt.Println("\nChecking included config files in:", includeDir)
		checkApacheIncludedConfigs(includeDir, results)
	}

	// Test PQC connection if Apache is installed
	fmt.Println("\nTesting PQC connection to Apache:")
	testApachePQCConnection(results)
	if connTest, ok := results["PQC Connection Test"]; ok {
		fmt.Println("  " + connTest)
	}

	// Print summary
	fmt.Println("\nApache PQC Support Summary:")
	if kyber, ok := results["Kyber KEM"]; ok {
		fmt.Println("  Kyber KEM Support:", kyber)
	} else {
		fmt.Println("  Kyber KEM Support: Not configured")
	}
	
	if hybrid, ok := results["Hybrid Groups"]; ok {
		fmt.Println("  Hybrid Groups Support:", hybrid)
	} else {
		fmt.Println("  Hybrid Groups Support: Not configured")
	}
	
	if connTest, ok := results["PQC Connection Test"]; ok {
		fmt.Println("  Connection Test:", connTest)
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateApacheStatus(results, rm)

	// Generate recommendations based on scan results
	recommendations := generateApacheRecommendations(results)

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
		report := ApacheReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			ApacheInfo:     results,
			Recommendations: recommendations,
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
			filePath := filepath.Join(reportDir, "apache.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/apache.json")
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

// parseApacheConfig parses Apache config files for PQC-related settings
func parseApacheConfig(configPath string, results map[string]string) {
	file, err := os.Open(configPath)
	if err != nil {
		results["Config Parse Error"] = err.Error()
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Patterns to look for
	sslProtocolRe := regexp.MustCompile(`(?i)SSLProtocol\s+(.+)`)
	sslCipherRe := regexp.MustCompile(`(?i)SSLCipherSuite\s+(.+)`)
	sslOpenSSLConfCmdRe := regexp.MustCompile(`(?i)SSLOpenSSLConfCmd\s+(\S+)\s+(.+)`)
	includeRe := regexp.MustCompile(`(?i)Include\s+(.+)`)

	hasTLS13 := false
	hasKyber := false
	hasHybrid := false
	hasPQCCiphers := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// Check for TLS 1.3
		if match := sslProtocolRe.FindStringSubmatch(line); match != nil {
			protocols := match[1]
			if strings.Contains(strings.ToLower(protocols), "tlsv1.3") ||
				strings.Contains(strings.ToLower(protocols), "all") {
				hasTLS13 = true
				results["TLS 1.3"] = "Enabled"
			}
		}

		// Check for PQC ciphers
		if match := sslCipherRe.FindStringSubmatch(line); match != nil {
			ciphers := strings.ToLower(match[1])
			results["SSL Ciphers"] = match[1]

			// Check for any PQC-related cipher strings
			if strings.Contains(ciphers, "kyber") ||
				strings.Contains(ciphers, "oqs") ||
				strings.Contains(ciphers, "pqc") ||
				strings.Contains(ciphers, "quantum") {
				hasPQCCiphers = true
				results["PQC Ciphers"] = "Detected in SSLCipherSuite directive"
			}
		}

		// Check for OpenSSL configuration commands
		if match := sslOpenSSLConfCmdRe.FindStringSubmatch(line); match != nil {
			cmd := match[1]
			value := match[2]

			// Check for Kyber or hybrid groups in Curves
			if strings.ToLower(cmd) == "curves" {
				results["SSL Curves"] = value

				// Check for Kyber
				if strings.Contains(strings.ToLower(value), "kyber") {
					hasKyber = true
					results["Kyber KEM"] = "Configured"
				}

				// Check for hybrid
				if strings.Contains(strings.ToLower(value), "hybrid") ||
					strings.Contains(strings.ToLower(value), "p256_kyber") ||
					strings.Contains(strings.ToLower(value), "x25519_kyber") {
					hasHybrid = true
					results["Hybrid Groups"] = "Configured"
				}
			}

			// Check for PQC provider
			if strings.ToLower(cmd) == "providers" &&
				strings.Contains(strings.ToLower(value), "oqs") {
				results["OQS Provider Configured"] = "Yes"
			}
			
			// Check for OpenSSL config file that might contain OQS provider
			if strings.ToLower(cmd) == "configfile" || strings.ToLower(cmd) == "config" {
				if _, err := os.Stat(value); err == nil {
					results["OpenSSL Config File"] = value
					checkOpenSSLConfigForOQS(value, results)
				}
			}
		}

		// Check for include directives
		if match := includeRe.FindStringSubmatch(line); match != nil {
			includePath := match[1]
			if strings.Contains(includePath, "sites-enabled") ||
				strings.Contains(includePath, "conf.d") {
				results["Include Directory"] = includePath
			}
		}
	}

	if !hasTLS13 {
		results["TLS 1.3"] = "Not explicitly enabled"
	}

	if !hasKyber {
		results["Kyber KEM"] = "Not configured"
	}

	if !hasHybrid {
		results["Hybrid Groups"] = "Not configured"
	}

	if !hasPQCCiphers {
		results["PQC Ciphers"] = "Not detected in SSLCipherSuite directives"
	}
}

// checkApacheIncludedConfigs checks included Apache config files for PQC settings
func checkApacheIncludedConfigs(includePattern string, results map[string]string) {
	// Handle glob patterns in include directives
	matches, err := filepath.Glob(includePattern)
	if err != nil {
		results["Include Error"] = err.Error()
		fmt.Printf("  Error scanning included configs: %s\n", err)
		return
	}

	// Check if it's a directory
	info, err := os.Stat(includePattern)
	if err == nil && info.IsDir() {
		// It's a directory, look for .conf files
		dirMatches, _ := filepath.Glob(filepath.Join(includePattern, "*.conf"))
		matches = append(matches, dirMatches...)
		fmt.Printf("  Scanning %d config files in %s\n", len(dirMatches), includePattern)
	}

	if len(matches) == 0 {
		fmt.Println("  No included config files found")
		return
	}

	hasKyberInIncludes := false
	hasHybridInIncludes := false
	foundPQCSettings := false

	for _, match := range matches {
		// Check if it's a file
		info, err := os.Stat(match)
		if err != nil || info.IsDir() {
			continue
		}

		// Parse the included config
		fmt.Printf("  Checking %s...\n", match)
		includeResults := make(map[string]string)
		parseApacheConfig(match, includeResults)

		// Check for Kyber and hybrid configs
		fmt.Println("  Looking for PQC-related settings...")
		if kyber, ok := includeResults["Kyber KEM"]; ok && kyber == "Configured" {
			hasKyberInIncludes = true
			foundPQCSettings = true
			results["Kyber in Includes"] = fmt.Sprintf("Found in %s", match)
			fmt.Printf("    Found Kyber KEM configuration\n")
		} else {
			fmt.Printf("    Kyber KEM support not found\n")
		}

		if hybrid, ok := includeResults["Hybrid Groups"]; ok && hybrid == "Configured" {
			hasHybridInIncludes = true
			foundPQCSettings = true
			results["Hybrid in Includes"] = fmt.Sprintf("Found in %s", match)
			fmt.Printf("    Found Hybrid Groups configuration\n")
		} else {
			fmt.Printf("    Hybrid Groups support not found\n")
		}

		if tls, ok := includeResults["TLS 1.3"]; ok && tls == "Enabled" {
			fmt.Printf("    TLS 1.3 support found\n")
		} else {
			fmt.Printf("    TLS 1.3 support not found - required for PQC\n")
		}
	}

	if !foundPQCSettings {
		fmt.Println("  No PQC settings found in included config files")
	}

	if !hasKyberInIncludes && results["Kyber KEM Support"] == "Not configured" {
		results["Kyber in Includes"] = "Not found in included files"
	}

	if !hasHybridInIncludes && results["Hybrid Groups Support"] == "Not configured" {
		results["Hybrid in Includes"] = "Not found in included files"
	}
}

// checkApacheOpenSSLVersion checks which OpenSSL version Apache is using
func checkApacheOpenSSLVersion(apachePath string, results map[string]string) {
	// Method 1: Check linked libraries
	cmd := exec.Command("ldd", apachePath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		// Look for libssl.so in the output
		libs := string(output)
		if strings.Contains(libs, "libssl.so.3") {
			// Try to get the exact version
			libraryPath := ""
			for _, line := range strings.Split(libs, "\n") {
				if strings.Contains(line, "libssl.so.3") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						libraryPath = strings.TrimSpace(parts[2])
						break
					}
				}
			}

			if libraryPath != "" {
				// Extract version from path if possible
				if strings.Contains(libraryPath, "openssl-") {
					version := regexp.MustCompile(`openssl-([0-9.]+)`).FindStringSubmatch(libraryPath)
					if len(version) > 1 {
						results["OpenSSL Version"] = version[1]
						results["OpenSSL Path"] = libraryPath
						return
					}
				}
				results["OpenSSL Version"] = "3.x"
				results["OpenSSL Path"] = libraryPath
				return
			}
		} else if strings.Contains(libs, "libssl.so.1.1") {
			results["OpenSSL Version"] = "1.1.x"
			return
		} else if strings.Contains(libs, "libssl.so.1.0") {
			results["OpenSSL Version"] = "1.0.x"
			return
		}
	}

	// Method 2: Check mod_ssl.so
	modSslPaths := []string{
		"/usr/lib/apache2/modules/mod_ssl.so",
		"/usr/lib64/apache2/modules/mod_ssl.so",
		"/usr/libexec/apache2/mod_ssl.so",
	}

	for _, modPath := range modSslPaths {
		if _, err := os.Stat(modPath); err == nil {
			cmd := exec.Command("ldd", modPath)
			output, err := cmd.CombinedOutput()
			if err == nil {
				libs := string(output)
				if strings.Contains(libs, "libssl.so.3") {
					// Try to get the exact version
					libraryPath := ""
					for _, line := range strings.Split(libs, "\n") {
						if strings.Contains(line, "libssl.so.3") {
							parts := strings.Fields(line)
							if len(parts) >= 3 {
								libraryPath = strings.TrimSpace(parts[2])
								break
							}
						}
					}

					if libraryPath != "" {
						// Extract version from path if possible
						if strings.Contains(libraryPath, "openssl-") {
							version := regexp.MustCompile(`openssl-([0-9.]+)`).FindStringSubmatch(libraryPath)
							if len(version) > 1 {
								results["OpenSSL Version"] = version[1]
								results["OpenSSL Path"] = libraryPath
								return
							}
						}
						results["OpenSSL Version"] = "3.x"
						results["OpenSSL Path"] = libraryPath
						return
					}
				} else if strings.Contains(libs, "libssl.so.1.1") {
					results["OpenSSL Version"] = "1.1.x"
					return
				} else if strings.Contains(libs, "libssl.so.1.0") {
					results["OpenSSL Version"] = "1.0.x"
					return
				}
			}
			break
		}
	}

	// Method 3: Use the system OpenSSL version if we couldn't determine Apache's version
	cmd = exec.Command("openssl", "version")
	output, err = cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// Extract version from output (format: "OpenSSL 3.2.2 23 Apr 2024")
		versionRe := regexp.MustCompile(`OpenSSL\s+([0-9.]+[a-z]*)\s+`)
		if match := versionRe.FindStringSubmatch(outputStr); match != nil {
			results["OpenSSL Version"] = match[1] + " (system)"
			return
		}
	}

	// If we couldn't determine the version
	results["OpenSSL Version"] = "Unknown"
}

// checkOQSProviderInstallation checks if OQS provider is installed
func checkOQSProviderInstallation(results map[string]string) {
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
		"oqs-provider",
		"oqsprovider",
		"openssl/oqs-provider",
		"openssl/providers",
		"providers",
		"", // Check directly in lib directories
	}
	
	// Common OQS provider filenames
	oqsFilenames := []string{
		"liboqsprov.so",
		"oqsprovider.so",
	}
	
	// Check for OQS provider
	oqsInstalled := false
	oqsPath := ""
	
	// Try to find the OQS provider library
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
	
	if oqsInstalled {
		results["OQS Provider"] = fmt.Sprintf("Installed (%s)", oqsPath)
	} else {
		results["OQS Provider"] = "Not installed"
	}
	
	// Check if OpenSSL recognizes the OQS provider
	if oqsInstalled {
		cmd := exec.Command("openssl", "list", "-providers")
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(strings.ToLower(string(output)), "oqs") {
			results["OQS Provider Loaded in OpenSSL"] = "Yes"
		}
	}
}

// checkOpenSSLConfigForOQS checks if an OpenSSL config file loads the OQS provider
func checkOpenSSLConfigForOQS(configPath string, results map[string]string) {
	file, err := os.Open(configPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	providerSection := false
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Check for provider section
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "provider_section]") {
			providerSection = true
			continue
		} else if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			providerSection = false
		}
		
		// Check for OQS provider in the provider section
		if providerSection && (strings.Contains(strings.ToLower(line), "oqsprovider") || 
		                       strings.Contains(strings.ToLower(line), "oqs-provider") || 
		                       strings.Contains(strings.ToLower(line), "liboqsprov")) {
			results["OQS Provider Configured"] = "Yes"
			results["OQS Config File"] = configPath
			break
		}
	}
}



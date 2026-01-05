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

// getNginxOpenSSLVersion gets the OpenSSL version used by Nginx
func getNginxOpenSSLVersion() (string, string, error) {
	cmd := exec.Command("which", "nginx")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return "", "", err
	}

	cmd = exec.Command("nginx", "-V")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}

	if err := cmd.Start(); err != nil {
		return "", "", err
	}

	scanner := bufio.NewScanner(stderr)
	openSSLVersionRegex := regexp.MustCompile(`built with OpenSSL\s+([\d\.]+)\s?`)
	openSSLPathRegex := regexp.MustCompile(`--with-openssl=([^\s]+)`)

	var version, path string
	for scanner.Scan() {
		line := scanner.Text()
		if match := openSSLVersionRegex.FindStringSubmatch(line); len(match) > 1 {
			version = match[1]
		}
		if match := openSSLPathRegex.FindStringSubmatch(line); len(match) > 1 {
			path = match[1]

		}
	}

	cmd.Wait()
	return version, path, nil
}

// checkNginxInstallation checks if Nginx is installed and gets its version
func checkNginxInstallation(results map[string]string) {
	cmd := exec.Command("which", "nginx")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		results["Nginx"] = "Not installed"
		return
	}

	nginxPath := strings.TrimSpace(string(output))
	results["Nginx Path"] = nginxPath

	// Get Nginx version
	cmd = exec.Command("nginx", "-v")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		results["Nginx"] = "Installed (version unknown)"
		return
	}

	if err := cmd.Start(); err != nil {
		results["Nginx"] = "Installed (version unknown)"
		return
	}

	scanner := bufio.NewScanner(stderr)
	var version string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "nginx version") {
			version = line
			break
		}
	}

	if err := cmd.Wait(); err != nil {
		results["Nginx"] = "Installed (version unknown)"
		return
	}

	if version != "" {
		results["Nginx"] = version
	} else {
		results["Nginx"] = "Installed (version unknown)"
	}

	// Check if Nginx is running
	cmd = exec.Command("ps", "-ef")
	output, err = cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "nginx") && !strings.Contains(outputStr, "grep nginx") {
			results["Nginx Status"] = "Running"
		} else {
			results["Nginx Status"] = "Not running"
		}
	}

	// Get OpenSSL version used by Nginx
	opensslVersion, opensslPath, err := getNginxOpenSSLVersion()
	if err == nil && opensslVersion != "" {
		results["Nginx OpenSSL"] = opensslVersion
		if opensslPath != "" {
			results["Nginx OpenSSL Path"] = opensslPath
		}
	}
}

// checkNginxOQSProviderInstallation checks if the OQS provider is installed
func checkNginxOQSProviderInstallation(results map[string]string) {
	// Check OQS provider installation
	oqsFound := false

	// Check if OQS library exists
	oqsLibPaths := []string{
		"/usr/lib/ossl-modules/oqsprovider.so",
		"/usr/local/lib/ossl-modules/oqsprovider.so",
		"/usr/lib64/ossl-modules/oqsprovider.so",
	}

	for _, path := range oqsLibPaths {
		if _, err := os.Stat(path); err == nil {
			oqsFound = true
			results["OQS Provider"] = path
			fmt.Printf("✓ OQS Provider installed: %s\n", path)
			break
		}
	}

	// Check LD_LIBRARY_PATH for OQS
	ldLibraryPath := os.Getenv("LD_LIBRARY_PATH")
	if ldLibraryPath != "" && !oqsFound {
		paths := strings.Split(ldLibraryPath, ":")
		for _, path := range paths {
			oqsPath := filepath.Join(path, "ossl-modules/oqsprovider.so")
			if _, err := os.Stat(oqsPath); err == nil {
				oqsFound = true
				results["OQS Provider"] = oqsPath
				fmt.Printf("✓ OQS Provider installed in LD_LIBRARY_PATH: %s\n", oqsPath)
				break
			}
		}
	}

	if !oqsFound {
		results["OQS Provider"] = "Not found"
		fmt.Println("✗ OQS Provider not found")
	}
}

// testNginxPQCConnection tests if Nginx can negotiate PQC algorithms
func testNginxPQCConnection(results map[string]string) {
	// First, determine the port Nginx is listening on
	port := "443" // Default HTTPS port
	portFound := false

	// Check if we can find a different port from the config
	if configPath, ok := results["Nginx Config"]; ok {
		// Try to find the port in the config file
		portRe := regexp.MustCompile(`listen\s+([0-9]+)\s+ssl;`)
		if file, err := os.Open(configPath); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if match := portRe.FindStringSubmatch(line); match != nil {
					port = match[1]
					portFound = true
					break
				}
			}
		}

		// Also check included files for port
		if includeDir, ok := results["Include Directory"]; ok {
			matches, _ := filepath.Glob(includeDir)
			for _, match := range matches {
				info, err := os.Stat(match)
				if err == nil && !info.IsDir() {
					if file, err := os.Open(match); err == nil {
						defer file.Close()
						scanner := bufio.NewScanner(file)
						for scanner.Scan() {
							line := scanner.Text()
							if match := portRe.FindStringSubmatch(line); match != nil {
								port = match[1]
								portFound = true
								break
							}
						}
					}
				}
			}
		}
	}

	// If no SSL port was found in the config, try common SSL ports
	portsToTry := []string{port}
	if !portFound {
		portsToTry = []string{"443", "8443", "4443"}
	}

	// Try each port until we find one that works
	for _, currentPort := range portsToTry {
		fmt.Printf("  Trying port %s... ", currentPort)
		// First, test basic SSL connectivity without PQC parameters
		basicCmd := exec.Command("timeout", "5", "openssl", "s_client", "-connect", "localhost:"+currentPort)
		basicOutput, basicErr := basicCmd.CombinedOutput()
		basicOutputStr := string(basicOutput)

		// Check if basic connection was successful
		if basicErr == nil || strings.Contains(basicOutputStr, "CONNECTED") && strings.Contains(basicOutputStr, "Server certificate") {
			fmt.Println("connected!")
			fmt.Println("  Testing for Kyber negotiation capability...")
			// Basic connection successful, now test PQC support
			cmd := exec.Command("timeout", "5", "openssl", "s_client", "-connect", "localhost:"+currentPort, "-curves", "kyber768")
			output, _ := cmd.CombinedOutput()
			outputStr := string(output)

			// Extract server temp key info if available
			tempKeyRe := regexp.MustCompile(`Server Temp Key:\s+(.+)`)
			tempKeyMatch := tempKeyRe.FindStringSubmatch(outputStr)

			// Check for PQC negotiation
			if strings.Contains(outputStr, "Server Temp Key: X25519, kyber") {
				results["PQC Connection Test"] = "✓ Successfully negotiated Kyber on port " + currentPort
				fmt.Printf("  ✓ Successfully negotiated Kyber on port %s\n", currentPort)
			} else if tempKeyMatch != nil {
				results["PQC Connection Test"] = "✓ Connected on port " + currentPort + " but using " + tempKeyMatch[1] + " (no PQC)"
				fmt.Printf("  ✗ Connected on port %s but using %s (no PQC)\n", currentPort, tempKeyMatch[1])
			} else if strings.Contains(outputStr, "Server certificate") {
				results["PQC Connection Test"] = "✓ Connected on port " + currentPort + " but no PQC support detected"
				fmt.Printf("  ✗ Connected on port %s but no PQC support detected\n", currentPort)
			} else {
				// Extract protocol and cipher if available
				protocolRe := regexp.MustCompile(`Protocol\s+:\s+(.+)`)
				protocolMatch := protocolRe.FindStringSubmatch(outputStr)
				protocolInfo := ""
				if protocolMatch != nil {
					protocolInfo = " using " + protocolMatch[1]
				}
				results["PQC Connection Test"] = "✓ Connected on port " + currentPort + protocolInfo + " but could not determine key exchange"
				fmt.Printf("  ✗ Connected on port %s%s but could not determine key exchange\n", currentPort, protocolInfo)
			}
			return
		} else {
			fmt.Println("not available")
		}
	}

	// If we get here, all connection attempts failed
	results["PQC Connection Test"] = "Failed to connect to Nginx SSL on any port. Check if SSL is properly configured."
	fmt.Println("  ✗ Failed to connect to Nginx SSL on any port. Check if SSL is properly configured.")
}

// TestNginx checks Nginx configuration for PQC support and returns structured recommendations
// NginxReport represents the structure of the JSON report for the nginx command
type NginxReport struct {
	ServerIP        string                `json:"server_ip"`
	ReportTime      string                `json:"report_time"`
	NginxInfo       map[string]string     `json:"nginx_info"`
	Recommendations []scan.Recommendation `json:"recommendations"`
}

func TestNginx(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Nginx PQC Configuration Check ===")

	// Results map
	results := make(map[string]string)

	// Check AWS environment and load balancers
	checkAWSEnvironmentForNginx(results)

	// Find nginx.conf

	// Check if nginx is installed and get version
	checkNginxInstallation(results)
	nginxInstalled := false
	if nginxVer, ok := results["Nginx"]; ok && nginxVer != "Not installed" {
		nginxInstalled = true
		fmt.Printf("✓ Nginx installed: %s\n", nginxVer)
	} else if _, err := os.Stat("/usr/sbin/nginx"); err == nil {
		nginxInstalled = true
		results["Nginx Installed"] = "Yes (/usr/sbin/nginx)"
		fmt.Println("✓ Nginx installed: /usr/sbin/nginx")
	} else if _, err := os.Stat("/usr/local/sbin/nginx"); err == nil {
		nginxInstalled = true
		results["Nginx Installed"] = "Yes (/usr/local/sbin/nginx)"
		fmt.Println("✓ Nginx installed: /usr/local/sbin/nginx")
	} else {
		results["Nginx Installed"] = "No"
		fmt.Println("✗ Nginx not detected on this system")
	}

	// Get OpenSSL version used by Nginx
	if nginxInstalled {
		openSSLVersion, openSSLPath, err := getNginxOpenSSLVersion()
		if err == nil {
			results["OpenSSL Version"] = openSSLVersion
			fmt.Printf("✓ OpenSSL version: %s\n", openSSLVersion)
			if openSSLPath != "" {
				results["OpenSSL Path"] = openSSLPath
				fmt.Printf("  OpenSSL path: %s\n", openSSLPath)
			}
		} else {
			fmt.Println("✗ Could not determine OpenSSL version")
		}

		// Check for OQS provider installation
		checkNginxOQSProviderInstallation(results)
	}

	if !nginxInstalled {
		// Return recommendations for non-installed Nginx
		return generateNginxRecommendations(results)
	}

	// Find nginx.conf using the improved finder
	nginxConfPath, err := FindNginxConfigFile()

	if err != nil || nginxConfPath == "" {
		fmt.Println("✗ Nginx config not found in standard locations")
		results["Nginx Config"] = "Not found in standard locations"
	} else {
		fmt.Printf("✓ Nginx config found: %s\n", nginxConfPath)
		results["Nginx Config"] = nginxConfPath
		// Parse the config file
		fmt.Println("\nAnalyzing Nginx configuration:")

		// Try to get SSL settings using nginx -T
		sslSettings, sslErr := GetNginxSSLSettings(nginxConfPath)
		if sslErr == nil && len(sslSettings) > 0 {
			fmt.Println("  Using nginx -T to analyze configuration")

			// Add SSL settings to results
			for directive, value := range sslSettings {
				results[directive] = value
				fmt.Printf("  Found: %s\n", value)
			}

			// Check for PQC settings
			if _, hasPQC := sslSettings["PQC Settings"]; hasPQC {
				results["PQC Support"] = "Configured"
				fmt.Println("✓ PQC-related settings found in configuration")
			}
		} else {
			// Fall back to traditional config parsing
			parseNginxConfig(nginxConfPath, results)
		}
	}

	// Check for included config files
	if includeDir, ok := results["Include Directory"]; ok {
		fmt.Printf("\nChecking included config files in: %s\n", includeDir)
		checkIncludedConfigs(includeDir, results)
	}

	// Test PQC connection if Nginx is installed
	if nginxInstalled {
		fmt.Println("\nTesting PQC connection to Nginx:")
		testNginxPQCConnection(results)
	}

	// Print summary of findings
	fmt.Println("\nNginx PQC Support Summary:")
	// Check for PQC support in the results
	if kyberSupport, ok := results["Kyber KEM Support"]; ok {
		fmt.Printf("  Kyber KEM Support: %s\n", kyberSupport)
	}

	if hybridSupport, ok := results["Hybrid Groups Support"]; ok {
		fmt.Printf("  Hybrid Groups Support: %s\n", hybridSupport)
	}

	if pqcTest, ok := results["PQC Connection Test"]; ok {
		fmt.Printf("  Connection Test: %s\n", pqcTest)
	}

	// Print summary
	// Print a summary of the nginx scan results
	fmt.Println("\nNginx Security Summary:")
	fmt.Println("-------------------------")

	// Check if we have AWS load balancer information
	hasAWSLoadBalancer := false
	if _, ok := results["Load Balancer ARN"]; ok {
		hasAWSLoadBalancer = true
	}

	if hasAWSLoadBalancer {
		fmt.Println("\n🌐 INTERNET-FACING CONFIGURATION (AWS Load Balancer):")
		fmt.Println("The following represents what external clients see, not instance-level config:")
		fmt.Println("---------------------------------------------------------------------")

		// Print AWS load balancer specific items first
		awsKeys := []string{"Load Balancer ARN", "LB SSL Policy", "LB PQC Ready", "LB Primary Port",
			"LB HTTPS Listeners", "LB Cipher Count", "LB Modern Ciphers", "Application Load Balancer",
			"Classic Load Balancer", "AWS Environment", "EC2 Instance ID", "AWS CLI"}

		for _, key := range awsKeys {
			if value, ok := results[key]; ok {
				switch key {
				case "Load Balancer ARN":
					fmt.Printf("[INFO] LB ARN: %s\n", value)
				case "LB SSL Policy":
					fmt.Printf("[INFO] LB SSL Policy: %s\n", value)
				case "LB PQC Ready":
					if value == "true" {
						fmt.Printf("[PASS] LB PQC Ready: %s\n", value)
					} else {
						fmt.Printf("[WARN] LB PQC Ready: %s\n", value)
					}
				case "LB Primary Port":
					fmt.Printf("[INFO] LB Primary Port: %s\n", value)
				case "LB HTTPS Listeners":
					fmt.Printf("[INFO] LB HTTPS Listeners: %s\n", value)
				case "LB Cipher Count":
					fmt.Printf("[INFO] LB Cipher Count: %s\n", value)
				case "LB Modern Ciphers":
					fmt.Printf("[INFO] LB Modern Ciphers: %s\n", value)
				case "Application Load Balancer":
					fmt.Printf("[INFO] Application Load Balancer: %s\n", value)
				case "Classic Load Balancer":
					fmt.Printf("[INFO] Classic Load Balancer: %s\n", value)
				case "AWS Environment":
					fmt.Printf("[INFO] AWS Environment: %s\n", value)
				case "EC2 Instance ID":
					fmt.Printf("[INFO] EC2 Instance ID: %s\n", value)
				case "AWS CLI":
					fmt.Printf("[INFO] AWS CLI: %s\n", value)
				default:
					fmt.Printf("%s: %s\n", key, value)
				}
			}
		}

		fmt.Println("\n[INFO] INSTANCE-LEVEL CONFIGURATION (Nginx on EC2):")
		fmt.Println("The following represents local Nginx configuration on this instance:")
		fmt.Println("------------------------------------------------------------------")
	}

	// Print remaining (non-AWS) items
	awsKeyMap := map[string]bool{
		"Load Balancer ARN": true, "LB SSL Policy": true, "LB PQC Ready": true, "LB Primary Port": true,
		"LB HTTPS Listeners": true, "LB Cipher Count": true, "LB Modern Ciphers": true,
		"Application Load Balancer": true, "Classic Load Balancer": true, "AWS Environment": true,
		"EC2 Instance ID": true, "AWS CLI": true,
	}

	for key, value := range results {
		if !awsKeyMap[key] {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateNginxStatus(results, rm)

	// Generate recommendations based on scan results
	recommendations := generateNginxRecommendations(results)

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
		report := NginxReport{
			ServerIP:        serverIP,
			ReportTime:      time.Now().Format(time.RFC3339),
			NginxInfo:       results,
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
			filePath := filepath.Join(reportDir, "nginx.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/nginx.json")
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

// parseNginxConfig parses the nginx.conf file for PQC-related settings
func parseNginxConfig(configPath string, results map[string]string) {
	file, err := os.Open(configPath)
	if err != nil {
		results["Config Parse Error"] = err.Error()
		fmt.Printf("✗ Error parsing config: %s\n", err.Error())
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Patterns to look for
	sslProtocolsRe := regexp.MustCompile(`ssl_protocols\s+(.+?);`)
	sslEcdhCurveRe := regexp.MustCompile(`ssl_ecdh_curve\s+(.+?);`)
	includeRe := regexp.MustCompile(`include\s+(.+?);`)

	// Also check for ciphers that might indicate PQC support
	sslCiphersRe := regexp.MustCompile(`ssl_ciphers\s+['"](.*?)['"];`)

	// Check for ssl_conf_command directives
	sslConfCommandProviderRe := regexp.MustCompile(`ssl_conf_command\s+Providers\s+(.+?);`)
	sslConfCommandCurvesRe := regexp.MustCompile(`ssl_conf_command\s+Curves\s+(.+?);`)

	hasKyber := false
	hasHybrid := false
	hasTLS13 := false
	hasPQCCiphers := false

	fmt.Println("  Looking for PQC-related settings...")

	for scanner.Scan() {
		line := scanner.Text()

		// Skip commented lines
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check for SSL/TLS protocol versions
		if match := sslProtocolsRe.FindStringSubmatch(line); match != nil {
			protocols := strings.TrimSpace(match[1])
			results["SSL Protocols"] = protocols
			fmt.Printf("  Found SSL protocols: %s\n", protocols)

			// Check for specific TLS versions
			if strings.Contains(protocols, "TLSv1.3") {
				hasTLS13 = true
				results["TLS 1.3"] = "Enabled"
				fmt.Println("  TLS 1.3: Enabled")
			} else {
				results["TLS 1.3"] = "Not configured"
				fmt.Println("  TLS 1.3: Not configured")
			}

			// Check for older TLS versions (problematic for PQC)
			if strings.Contains(protocols, "TLSv1.2") {
				results["TLS 1.2"] = "Enabled"
				fmt.Println("  TLS 1.2: Enabled")
			}
			if strings.Contains(protocols, "TLSv1.1") {
				results["TLS 1.1"] = "Enabled"
				fmt.Println("  TLS 1.1: Enabled")
			}
			if strings.Contains(protocols, "TLSv1") && !strings.Contains(protocols, "TLSv1.") {
				results["TLS 1.0"] = "Enabled"
				fmt.Println("  TLS 1.0: Enabled")
			}
			if strings.Contains(protocols, "SSLv3") {
				results["SSL 3.0"] = "Enabled"
				fmt.Println("  SSL 3.0: Enabled")
			}
			if strings.Contains(protocols, "SSLv2") {
				results["SSL 2.0"] = "Enabled"
				fmt.Println("  SSL 2.0: Enabled")
			}
		}

		// Check for PQC ciphers
		if match := sslCiphersRe.FindStringSubmatch(line); match != nil {
			ciphers := strings.ToLower(match[1])
			results["SSL Ciphers"] = match[1]

			// Check for any PQC-related cipher strings
			if strings.Contains(ciphers, "kyber") ||
				strings.Contains(ciphers, "oqs") ||
				strings.Contains(ciphers, "pqc") ||
				strings.Contains(ciphers, "quantum") {
				hasPQCCiphers = true
				results["PQC Ciphers"] = "Detected in ssl_ciphers directive"
			}
		}

		// Check for OQS provider configuration
		if (strings.Contains(strings.ToLower(line), "load_module") &&
			strings.Contains(strings.ToLower(line), "oqs")) ||
			(strings.Contains(strings.ToLower(line), "ssl_conf_command") &&
				strings.Contains(strings.ToLower(line), "providers") &&
				strings.Contains(strings.ToLower(line), "oqs")) {
			results["OQS Provider Configured"] = "Yes"
		}

		// Check for ssl_conf_command directive for OQS provider
		if match := sslConfCommandProviderRe.FindStringSubmatch(line); match != nil {
			if strings.Contains(strings.ToLower(match[1]), "oqs") {
				results["OQS Provider Configured"] = "Yes"
			}
		}

		// Check for ssl_conf_command Curves for Kyber support
		if match := sslConfCommandCurvesRe.FindStringSubmatch(line); match != nil {
			curves := match[1]
			if strings.Contains(strings.ToLower(curves), "kyber") {
				hasKyber = true
				results["Kyber KEM Support"] = "Configured"
			}
			if strings.Contains(strings.ToLower(curves), "p256_kyber") ||
				strings.Contains(strings.ToLower(curves), "x25519_kyber") {
				hasHybrid = true
				results["Hybrid Groups Support"] = "Configured"
			}
		}

		// Check for Kyber in ssl_ecdh_curve
		if match := sslEcdhCurveRe.FindStringSubmatch(line); match != nil {
			curves := match[1]
			results["SSL ECDH Curves"] = curves

			// Check for Kyber
			if strings.Contains(strings.ToLower(curves), "kyber") {
				hasKyber = true
				results["Kyber KEM"] = "Configured"
			}

			// Check for hybrid
			if strings.Contains(strings.ToLower(curves), "hybrid") ||
				strings.Contains(strings.ToLower(curves), "p256_kyber") ||
				strings.Contains(strings.ToLower(curves), "x25519_kyber") {
				hasHybrid = true
				results["Hybrid Groups"] = "Configured"
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

	if hasKyber {
		results["Kyber KEM Support"] = "Configured"
		fmt.Println("✓ Kyber KEM support found in nginx config")
	} else {
		results["Kyber KEM Support"] = "Not configured"
		fmt.Println("✗ Kyber KEM support not found in nginx config")
	}

	if hasHybrid {
		results["Hybrid Groups Support"] = "Configured"
		fmt.Println("✓ Hybrid Groups support found in nginx config")
	} else {
		results["Hybrid Groups Support"] = "Not configured"
		fmt.Println("✗ Hybrid Groups support not found in nginx config")
	}

	if hasTLS13 {
		results["TLS 1.3 Support"] = "Configured"
		fmt.Println("✓ TLS 1.3 support found in nginx config")
	} else {
		results["TLS 1.3 Support"] = "Not detected"
		fmt.Println("✗ TLS 1.3 support not found in nginx config - required for PQC")
	}

	if !hasPQCCiphers {
		results["PQC Ciphers"] = "Not detected in ssl_ciphers directives"
	}
}

// checkIncludedConfigs checks included config files for PQC settings
func checkIncludedConfigs(includeDir string, results map[string]string) {
	hasKyberInIncludes := false
	hasHybridInIncludes := false

	// Handle glob patterns in include directives
	matches, err := filepath.Glob(includeDir)
	if err != nil {
		results["Include Error"] = err.Error()
		fmt.Printf("  ✗ Error with include pattern: %s\n", err)
		return
	}

	// Check if it's a directory
	info, err := os.Stat(includeDir)
	if err == nil && info.IsDir() {
		// It's a directory, look for .conf files
		dirMatches, _ := filepath.Glob(filepath.Join(includeDir, "*.conf"))
		matches = append(matches, dirMatches...)
		fmt.Printf("  Scanning %d config files in %s\n", len(dirMatches), includeDir)
	}

	if len(matches) == 0 {
		fmt.Println("  No included config files found")
		return
	}

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
		parseNginxConfig(match, includeResults)

		// Check for Kyber and hybrid configs
		if kyber, ok := includeResults["Kyber KEM Support"]; ok && kyber == "Configured" {
			hasKyberInIncludes = true
			foundPQCSettings = true
			results["Kyber in Includes"] = fmt.Sprintf("Found in %s", match)
			fmt.Printf("    ✓ Found Kyber KEM configuration\n")
		}

		if hybrid, ok := includeResults["Hybrid Groups Support"]; ok && hybrid == "Configured" {
			hasHybridInIncludes = true
			foundPQCSettings = true
			results["Hybrid in Includes"] = fmt.Sprintf("Found in %s", match)
			fmt.Printf("    ✓ Found Hybrid Groups configuration\n")
		}
	}

	if !foundPQCSettings {
		fmt.Println("  ✗ No PQC settings found in included config files")
	}

	if !hasKyberInIncludes && results["Kyber KEM Support"] == "Not configured" {
		results["Kyber in Includes"] = "Not found in included files"
	}

	if !hasHybridInIncludes && results["Hybrid Groups Support"] == "Not configured" {
		results["Hybrid in Includes"] = "Not found in included files"
	}
}

// checkAWSEnvironmentForNginx checks AWS environment and load balancers for Nginx-specific analysis
func checkAWSEnvironmentForNginx(results map[string]string) {
	// Check if we're in AWS environment
	cmd := exec.Command("curl", "-s", "--connect-timeout", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	if err != nil {
		return // Not in AWS
	}
	instanceID := strings.TrimSpace(string(output))
	if instanceID == "" {
		return // Not in AWS
	}
	results["AWS Environment"] = "Detected"
	results["EC2 Instance ID"] = instanceID

	// Check if AWS CLI is available
	cmd = exec.Command("which", "aws")
	if err := cmd.Run(); err != nil {
		results["AWS CLI"] = "Not Available"
		return
	}
	results["AWS CLI"] = "Available"

	// Discover Application/Network Load Balancers - First get all target groups
	cmd = exec.Command("aws", "elbv2", "describe-target-groups", "--output", "json")
	output, err = cmd.Output()
	if err == nil {
		var targetGroupsResp map[string]interface{}
		if json.Unmarshal(output, &targetGroupsResp) == nil {
			if targetGroups, ok := targetGroupsResp["TargetGroups"].([]interface{}); ok {
				for _, tg := range targetGroups {
					if tgMap, ok := tg.(map[string]interface{}); ok {
						if tgArn, ok := tgMap["TargetGroupArn"].(string); ok {
							// Check if this instance is in this target group
							cmd = exec.Command("aws", "elbv2", "describe-target-health", "--target-group-arn", tgArn, "--output", "json")
							thOutput, thErr := cmd.Output()
							if thErr == nil {
								var healthResp map[string]interface{}
								if json.Unmarshal(thOutput, &healthResp) == nil {
									if targets, ok := healthResp["TargetHealthDescriptions"].([]interface{}); ok {
										for _, target := range targets {
											if targetMap, ok := target.(map[string]interface{}); ok {
												if targetInfo, ok := targetMap["Target"].(map[string]interface{}); ok {
													if targetId, ok := targetInfo["Id"].(string); ok && targetId == instanceID {
														// Found our instance in this target group, get the load balancer ARNs
														if lbArns, ok := tgMap["LoadBalancerArns"].([]interface{}); ok {
															for _, lbArn := range lbArns {
																if arnStr, ok := lbArn.(string); ok {
																	// Extract load balancer name from ARN
																	parts := strings.Split(arnStr, "/")
																	if len(parts) >= 2 {
																		lbName := parts[1]
																		results["Application Load Balancer"] = lbName
																		results["Load Balancer ARN"] = arnStr
																		// Analyze SSL policies for this load balancer
																		analyzeLoadBalancerSSLPoliciesForNginx(arnStr, results)
																		return // Found it, exit early
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// analyzeLoadBalancerSSLPoliciesForNginx analyzes SSL policies for a given load balancer ARN (nginx-specific)
func analyzeLoadBalancerSSLPoliciesForNginx(lbArn string, results map[string]string) {
	// Get load balancer listeners
	cmd := exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", lbArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results["LB SSL Policy Analysis"] = "Failed to retrieve listeners"
		return
	}

	var listenersResp map[string]interface{}
	if json.Unmarshal(output, &listenersResp) != nil {
		results["LB SSL Policy Analysis"] = "Failed to parse listeners response"
		return
	}

	listeners, ok := listenersResp["Listeners"].([]interface{})
	if !ok {
		results["LB SSL Policy Analysis"] = "No listeners found"
		return
	}

	var httpsListeners []map[string]interface{}
	for _, listener := range listeners {
		if listenerMap, ok := listener.(map[string]interface{}); ok {
			if protocol, ok := listenerMap["Protocol"].(string); ok {
				if protocol == "HTTPS" || protocol == "TLS" {
					httpsListeners = append(httpsListeners, listenerMap)
				}
			}
		}
	}

	if len(httpsListeners) == 0 {
		results["LB SSL Policy Analysis"] = "No HTTPS/TLS listeners found"
		return
	}

	results["LB HTTPS Listeners"] = fmt.Sprintf("%d", len(httpsListeners))

	// Analyze the first HTTPS listener's SSL policy (most common case)
	if len(httpsListeners) > 0 {
		listener := httpsListeners[0]
		port := "unknown"
		if portNum, ok := listener["Port"].(float64); ok {
			port = fmt.Sprintf("%.0f", portNum)
		}

		sslPolicy := "default"
		if policy, ok := listener["SslPolicy"].(string); ok {
			sslPolicy = policy
		}

		results["LB Primary Port"] = port
		results["LB SSL Policy"] = sslPolicy

		// Analyze SSL policy for PQC readiness
		pqcReady := isNginxSSLPolicyPQCReady(sslPolicy)
		results["LB PQC Ready"] = fmt.Sprintf("%t", pqcReady)

		if !pqcReady {
			recommendedPolicy := "ELBSecurityPolicy-TLS13-1-2-2021-06"
			results["LB Recommended Policy"] = recommendedPolicy
		}

		// Get detailed SSL policy information for nginx context
		analyzeNginxSSLPolicyDetails(sslPolicy, results)
	}
}

// isNginxSSLPolicyPQCReady checks if an SSL policy supports PQC algorithms (nginx-specific)
func isNginxSSLPolicyPQCReady(policyName string) bool {
	// PQC-ready policies (TLS 1.3 support is essential for PQC)
	pqcReadyPolicies := []string{
		"ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
		"ELBSecurityPolicy-TLS13-1-3-2021-06",
		"ELBSecurityPolicy-TLS13-1-0-2021-06",
		"ELBSecurityPolicy-FS-1-2-Res-2020-10",
		"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	}

	for _, readyPolicy := range pqcReadyPolicies {
		if policyName == readyPolicy {
			return true
		}
	}
	return false
}

// analyzeNginxSSLPolicyDetails gets detailed information about an SSL policy for nginx context
func analyzeNginxSSLPolicyDetails(policyName string, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", policyName, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results["LB Policy Details"] = "Failed to retrieve policy details"
		return
	}

	var policyResp map[string]interface{}
	if json.Unmarshal(output, &policyResp) != nil {
		results["LB Policy Details"] = "Failed to parse policy details"
		return
	}

	policies, ok := policyResp["SslPolicies"].([]interface{})
	if !ok || len(policies) == 0 {
		results["LB Policy Details"] = "No policy details found"
		return
	}

	policy := policies[0].(map[string]interface{})

	// Extract supported protocols
	if protocols, ok := policy["SupportedProtocols"].([]interface{}); ok {
		protocolList := make([]string, len(protocols))
		for i, p := range protocols {
			protocolList[i] = p.(string)
		}
		results["LB Protocols"] = strings.Join(protocolList, ", ")

		// Check for TLS 1.3 support (essential for PQC)
		hasTLS13 := false
		for _, protocol := range protocolList {
			if protocol == "TLSv1.3" {
				hasTLS13 = true
				break
			}
		}
		results["LB TLS 1.3 Support"] = fmt.Sprintf("%t", hasTLS13)
	}

	// Extract supported ciphers
	if ciphers, ok := policy["Ciphers"].([]interface{}); ok {
		results["LB Cipher Count"] = fmt.Sprintf("%d", len(ciphers))

		// Check for modern cipher suites
		modernCiphers := 0
		for _, cipher := range ciphers {
			if cipherMap, ok := cipher.(map[string]interface{}); ok {
				if name, ok := cipherMap["Name"].(string); ok {
					// Count ECDHE and modern ciphers
					if strings.Contains(name, "ECDHE") || strings.Contains(name, "TLS_AES") || strings.Contains(name, "TLS_CHACHA20") {
						modernCiphers++
					}
				}
			}
		}
		results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCiphers)
	}
}

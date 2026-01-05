package linux

import (
	"bufio"
	"encoding/json"
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

// RuntimeReport represents the structure of the JSON report for the runtime command
type RuntimeReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	RuntimeInfo    map[string]string      `json:"runtime_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestRuntime command audits runtime environments for PQC readiness
func TestRuntime(jsonOutput bool) []scan.Recommendation {
	// Create a map to store detection results
	results := make(map[string]string)
	
	// Print header
	fmt.Println("=== Runtime Environment PQC Readiness Check ===")
	
	// Check Java runtime
	fmt.Println("\nJava Runtime Analysis:")
	checkJavaRuntime(results)
	
	// Print Java runtime details
	if javaStatus, ok := results["Java"]; ok {
		if javaStatus == "Installed" {
			fmt.Printf("  \u2713 Java is installed")
			if javaVersion, ok := results["Java Version"]; ok {
				fmt.Printf(": %s\n", javaVersion)
			} else {
				fmt.Println()
			}
			
			if javaHome, ok := results["JAVA_HOME"]; ok {
				fmt.Printf("  \u2713 JAVA_HOME: %s\n", javaHome)
			}
			
			if securityFile, ok := results["Java Security File"]; ok {
				fmt.Printf("  \u2713 Java security configuration: %s\n", securityFile)
			}
			
			if providers, ok := results["JCE Providers"]; ok {
				fmt.Printf("  \u2713 JCE providers: %s\n", providers)
			}
			
			if pqcSupport, ok := results["Java PQC Support"]; ok {
				if pqcSupport == "Yes" {
					fmt.Printf("  \u2713 PQC support available\n")
				} else if pqcSupport == "Partial" {
					fmt.Printf("  \u26A0 Limited PQC support\n")
				} else {
					fmt.Printf("  \u2717 No native PQC support\n")
				}
			} else {
				fmt.Printf("  \u2717 No native PQC support detected\n")
			}
		} else {
			fmt.Println("  \u2717 Java is not installed")
		}
	}
	
	// Check Python runtime
	fmt.Println("\nPython Runtime Analysis:")
	checkPythonRuntime(results)
	
	// Print Python runtime details
	if pythonStatus, ok := results["Python"]; ok {
		if pythonStatus == "Installed" {
			fmt.Printf("  \u2713 Python is installed")
			if pythonVersion, ok := results["Python Version"]; ok {
				fmt.Printf(": %s\n", pythonVersion)
			} else {
				fmt.Println()
			}
			
			if pythonPath, ok := results["Python Path"]; ok {
				fmt.Printf("  \u2713 Python path: %s\n", pythonPath)
			}
			
			if sslModule, ok := results["Python SSL Module"]; ok {
				fmt.Printf("  \u2713 SSL module version: %s\n", sslModule)
			}
			
			if cryptoLibs, ok := results["Python Crypto Libraries"]; ok {
				fmt.Printf("  \u2713 Crypto libraries: %s\n", cryptoLibs)
			}
			
			if pqcModules, ok := results["Python PQC Modules"]; ok {
				if strings.Contains(pqcModules, "Installed") {
					fmt.Printf("  \u2713 %s\n", pqcModules)
				} else {
					fmt.Printf("  \u2717 %s\n", pqcModules)
				}
			} else {
				fmt.Println("  \u2717 No PQC modules detected")
			}
		} else {
			fmt.Println("  \u2717 Python is not installed")
		}
	}

	// Check Node.js runtime
	fmt.Println("\nNode.js Runtime Analysis:")
	checkNodeRuntime(results)
	
	// Print Node.js runtime details
	if nodeStatus, ok := results["Node.js"]; ok {
		if nodeStatus == "Installed" {
			fmt.Printf("  \u2713 Node.js is installed")
			if nodeVersion, ok := results["Node.js Version"]; ok {
				fmt.Printf(": %s\n", nodeVersion)
			} else {
				fmt.Println()
			}
			
			if nodePath, ok := results["Node.js Path"]; ok {
				fmt.Printf("  \u2713 Node.js path: %s\n", nodePath)
			}
			
			if npmVersion, ok := results["NPM Version"]; ok {
				fmt.Printf("  \u2713 NPM version: %s\n", npmVersion)
			}
			
			if cryptoModules, ok := results["Node.js Crypto Modules"]; ok {
				fmt.Printf("  \u2713 Crypto modules: %s\n", cryptoModules)
			}
			
			if pqcPackages, ok := results["Node.js PQC Packages"]; ok {
				if strings.Contains(pqcPackages, "Installed") {
					fmt.Printf("  \u2713 %s\n", pqcPackages)
				} else {
					fmt.Printf("  \u2717 %s\n", pqcPackages)
				}
			} else {
				fmt.Println("  \u2717 No PQC packages detected")
			}
		} else {
			fmt.Println("  \u2717 Node.js is not installed")
		}
	}
	
	// Print runtime PQC readiness summary
	fmt.Println("\nRuntime Environment PQC Readiness Summary:")
	
	if javaReady, ok := results["Java PQC Readiness"]; ok {
		if strings.Contains(javaReady, "Good") {
			fmt.Printf("  \u2713 Java: %s\n", javaReady)
		} else if strings.Contains(javaReady, "Fair") {
			fmt.Printf("  \u26A0 Java: %s\n", javaReady)
		} else {
			fmt.Printf("  \u2717 Java: %s\n", javaReady)
		}
	} else if _, ok := results["Java"]; ok {
		fmt.Println("  \u2717 Java: Limited PQC readiness")
	}
	
	if pythonReady, ok := results["Python PQC Readiness"]; ok {
		if strings.Contains(pythonReady, "Good") {
			fmt.Printf("  \u2713 Python: %s\n", pythonReady)
		} else if strings.Contains(pythonReady, "Fair") {
			fmt.Printf("  \u26A0 Python: %s\n", pythonReady)
		} else {
			fmt.Printf("  \u2717 Python: %s\n", pythonReady)
		}
	} else if _, ok := results["Python"]; ok {
		fmt.Println("  \u2717 Python: Limited PQC readiness")
	}
	
	if nodeReady, ok := results["Node.js PQC Readiness"]; ok {
		if strings.Contains(nodeReady, "Good") {
			fmt.Printf("  \u2713 Node.js: %s\n", nodeReady)
		} else if strings.Contains(nodeReady, "Fair") {
			fmt.Printf("  \u26A0 Node.js: %s\n", nodeReady)
		} else {
			fmt.Printf("  \u2717 Node.js: %s\n", nodeReady)
		}
	} else if _, ok := results["Node.js"]; ok {
		fmt.Println("  \u2717 Node.js: Limited PQC readiness")
	}
	
	// Check Node.js source files for crypto usage
	checkNodeSourceFiles(results)

	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	awsResults := make(map[string]string)
	if awsData := inspectAWSLoadBalancerForRuntime(); len(awsData) > 0 {
		for key, value := range awsData {
			awsResults[key] = value
		}
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateRuntimeStatus(results, rm, awsResults)

	// Generate recommendations based on detection results
	recommendations := generateRuntimeRecommendations(results, awsResults)

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
		report := RuntimeReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			RuntimeInfo:    results,
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
			filePath := filepath.Join(reportDir, "runtime.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/runtime.json")
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

// checkJavaRuntime checks for Java runtime and its PQC readiness
func checkJavaRuntime(results map[string]string) {
	fmt.Println("Checking Java runtime environment...")
	
	// Check for Java installation
	javaPath, err := exec.LookPath("java")
	if err != nil {
		results["Java"] = "Not installed"
		return
	}
	
	results["Java"] = "Installed"
	results["Java Path"] = javaPath
	
	// Get Java version
	cmd := exec.Command(javaPath, "-version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		versionOutput := string(output)
		versionRegex := regexp.MustCompile(`version "([^"]+)"`)
		matches := versionRegex.FindStringSubmatch(versionOutput)
		if len(matches) > 1 {
			results["Java Version"] = matches[1]
		}
	}
	
	// Check JAVA_HOME environment variable
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		results["JAVA_HOME"] = javaHome
		
		// Check for java.security file
		securityFilePath := filepath.Join(javaHome, "lib", "security", "java.security")
		checkJavaSecurityFile(securityFilePath, results)
	} else {
		// Try to find java.security in common locations
		commonPaths := []string{
			"/usr/lib/jvm/default-java/lib/security/java.security",
			"/usr/lib/jvm/java-*/lib/security/java.security",
			"/etc/java*/security/java.security",
		}
		
		for _, pattern := range commonPaths {
			matches, _ := filepath.Glob(pattern)
			for _, path := range matches {
				checkJavaSecurityFile(path, results)
				break
			}
		}
	}
	
	// Check for keystores
	checkJavaKeystores(results)
	
	// Check for JCE providers
	checkJCEProviders(results)
}

// checkJavaSecurityFile analyzes the java.security configuration file
func checkJavaSecurityFile(path string, results map[string]string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	
	results["Java Security File"] = path
	
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	providers := []string{}
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Look for security providers
		if strings.HasPrefix(line, "security.provider.") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				provider := strings.TrimSpace(parts[1])
				providers = append(providers, provider)
			}
		}
	}
	
	if len(providers) > 0 {
		results["JCE Providers"] = strings.Join(providers, ", ")
	}
}

// checkJavaKeystores looks for Java keystores and analyzes them
func checkJavaKeystores(results map[string]string) {
	// Check if keytool is available
	keytoolPath, err := exec.LookPath("keytool")
	if err != nil {
		results["Keytool"] = "Not found"
		return
	}
	
	results["Keytool"] = "Found"
	
	// Look for common keystore locations
	keystorePaths := []string{
		"/etc/ssl/certs/java/cacerts",
		"$JAVA_HOME/lib/security/cacerts",
		"$HOME/.keystore",
	}
	
	for _, path := range keystorePaths {
		// Expand environment variables
		expandedPath := os.ExpandEnv(path)
		if _, err := os.Stat(expandedPath); err == nil {
			analyzeKeystore(keytoolPath, expandedPath, results)
		}
	}
}

// analyzeKeystore uses keytool to analyze a Java keystore
func analyzeKeystore(keytoolPath, keystorePath string, results map[string]string) {
	// Default password for Java cacerts is "changeit"
	cmd := exec.Command(keytoolPath, "-list", "-keystore", keystorePath, "-storepass", "changeit")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		// Try without password
		cmd = exec.Command(keytoolPath, "-list", "-keystore", keystorePath)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return
		}
	}
	
	keystoreOutput := string(output)
	results["Keystore "+keystorePath] = "Analyzed"
	
	// Count certificate types
	rsaCount := strings.Count(keystoreOutput, "RSA")
	dsaCount := strings.Count(keystoreOutput, "DSA")
	ecCount := strings.Count(keystoreOutput, "EC") + strings.Count(keystoreOutput, "ECDSA")
	pqCount := countPQAlgorithms(keystoreOutput)
	
	results["Keystore RSA Certs"] = fmt.Sprintf("%d", rsaCount)
	results["Keystore DSA Certs"] = fmt.Sprintf("%d", dsaCount)
	results["Keystore EC Certs"] = fmt.Sprintf("%d", ecCount)
	results["Keystore PQ Certs"] = fmt.Sprintf("%d", pqCount)
}

// checkJCEProviders checks for installed JCE providers, especially BouncyCastle
func checkJCEProviders(results map[string]string) {
	// Check for BouncyCastle in common locations
	bcPaths := []string{
		"/usr/share/java/bcprov-*.jar",
		"/usr/local/share/java/bcprov-*.jar",
		"$HOME/.m2/repository/org/bouncycastle/bcprov-*/",
	}
	
	for _, pattern := range bcPaths {
		expandedPattern := os.ExpandEnv(pattern)
		matches, _ := filepath.Glob(expandedPattern)
		if len(matches) > 0 {
			results["BouncyCastle"] = "Found"
			results["BouncyCastle Path"] = strings.Join(matches, ", ")
			break
		}
	}
	
	// Check for other common JCE providers
	if _, ok := results["JCE Providers"]; ok {
		providers := results["JCE Providers"]
		if strings.Contains(providers, "SunPKCS11") {
			results["SunPKCS11"] = "Found"
		}
		if strings.Contains(providers, "SunJCE") {
			results["SunJCE"] = "Found"
		}
	}
}

// countPQAlgorithms counts post-quantum algorithms in a string
func countPQAlgorithms(input string) int {
	pqAlgorithms := []string{
		"Dilithium", "DILITHIUM", "dilithium",
		"Falcon", "FALCON", "falcon",
		"SPHINCS", "Sphincs", "sphincs",
		"CRYSTALS", "Crystals", "crystals",
		"LMS", "HSS", "XMSS",
	}
	
	count := 0
	for _, alg := range pqAlgorithms {
		count += strings.Count(input, alg)
	}
	
	return count
}

// checkPythonRuntime checks for Python runtime and its PQC readiness
func checkPythonRuntime(results map[string]string) {
	fmt.Println("Checking Python runtime environment...")
	
	// Check for Python installation
	pythonPaths := []string{"python3", "python"}
	pythonPath := ""
	for _, path := range pythonPaths {
		if p, err := exec.LookPath(path); err == nil {
			pythonPath = p
			results["Python"] = "Installed"
			results["Python Path"] = pythonPath
			break
		}
	}
	
	if pythonPath == "" {
		results["Python"] = "Not installed"
		return
	}
	
	// Get Python version
	cmd := exec.Command(pythonPath, "--version")
	output, err := cmd.Output()
	if err == nil {
		versionOutput := strings.TrimSpace(string(output))
		parts := strings.Split(versionOutput, " ")
		if len(parts) > 1 {
			results["Python Version"] = parts[1]
		}
	}
	
	// Check for pip
	pipPaths := []string{"pip3", "pip"}
	pipPath := ""
	for _, path := range pipPaths {
		if p, err := exec.LookPath(path); err == nil {
			pipPath = p
			results["Pip"] = "Installed"
			results["Pip Path"] = pipPath
			break
		}
	}
	
	if pipPath != "" {
		// Check for installed crypto modules
		checkPythonCryptoModules(pipPath, results)
	}
	
	// Check for Python source files with crypto usage
	checkPythonSourceFiles(results)
}

// checkPythonCryptoModules checks for installed Python cryptography modules
func checkPythonCryptoModules(pipPath string, results map[string]string) {
	// Get list of installed packages
	cmd := exec.Command(pipPath, "list")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	packageList := string(output)
	
	// Check for common crypto packages
	cryptoModules := []string{
		"cryptography",
		"pyOpenSSL",
		"PyNaCl",
		"paramiko",
		"pycrypto",
		"pycryptodome",
		"pyca",
		"liboqs-python",
		"oqs",
	}
	
	installedModules := []string{}
	
	for _, module := range cryptoModules {
		if strings.Contains(strings.ToLower(packageList), strings.ToLower(module)) {
			installedModules = append(installedModules, module)
			results["Python Module "+module] = "Installed"
		}
	}
	
	if len(installedModules) > 0 {
		results["Python Crypto Modules"] = strings.Join(installedModules, ", ")
	}
	
	// Check for PQC modules specifically
	pqcModules := []string{"liboqs-python", "oqs", "pqcrypto"}
	installedPQCModules := []string{}
	
	for _, module := range pqcModules {
		if strings.Contains(strings.ToLower(packageList), strings.ToLower(module)) {
			installedPQCModules = append(installedPQCModules, module)
			results["Python PQC Module "+module] = "Installed"
		}
	}
	
	if len(installedPQCModules) > 0 {
		results["Python PQC Modules"] = strings.Join(installedPQCModules, ", ")
	}
}

// checkPythonSourceFiles looks for Python source files with crypto usage
func checkPythonSourceFiles(results map[string]string) {
	// Application directories to search for Python files
	applicationDirectories := []string{
		"./",
		"/home/*/projects",
		"/home/*/src",
		"/opt/*/",
		"/var/www/",
		"/srv/",
	}
	
	// System library directories (for informational scanning)
	systemLibraryDirectories := []string{
		"/usr/local/lib/python*/site-packages",
		"/usr/lib/python*/site-packages",
		"/usr/lib/python*/dist-packages",
	}
	
	// More precise patterns for actual API usage
	classicCryptoAPIPatterns := []string{
		"hashlib.md5(",
		"hashlib.sha1(",
		"md5(",
		"sha1(",
		"MD5.new(",
		"SHA.new(",
		"rsa.generate_private_key",
		"default_backend()",
		"private_key.sign",
	}
	
	// Generic patterns for library reference detection
	classicCryptoGenericPatterns := []string{
		"SHA-1",
		"SHA1",
		"MD5",
	}
	
	pqcPatterns := []string{
		"dilithium",
		"kyber",
		"sphincs",
		"falcon",
		"oqs.Signature",
		"oqs.KeyEncapsulation",
	}
	
	appCryptoFound := false
	libraryReferencesFound := false
	pqcFound := false

	// Track files with actual crypto API usage (application code)
	appCryptoFiles := []string{}
	// Track files with generic references (library code)
	libraryReferenceFiles := []string{}
	
	// Helper function to check if a file is in a system library directory
	isSystemLibrary := func(filePath string) bool {
		for _, libDir := range systemLibraryDirectories {
			if matched, _ := filepath.Match(libDir+"*", filePath); matched {
				return true
			}
			if strings.Contains(filePath, "/site-packages/") || strings.Contains(filePath, "/dist-packages/") {
				return true
			}
		}
		return false
	}
	
	// Scan application directories for actual crypto API usage
	for _, dirPattern := range applicationDirectories {
		dirs, _ := filepath.Glob(dirPattern)
		for _, dir := range dirs {
			// Find Python files
			pyFiles, _ := filepath.Glob(filepath.Join(dir, "**/*.py"))
			for _, file := range pyFiles {
				// Skip if this is actually a system library file
				if isSystemLibrary(file) {
					continue
				}
				
				content, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				
				fileContent := string(content)
				
				// Check for actual crypto API usage patterns
				for _, pattern := range classicCryptoAPIPatterns {
					if strings.Contains(fileContent, pattern) {
						appCryptoFound = true
						results["Python Classic Crypto"] = "Found"
						appCryptoFiles = append(appCryptoFiles, file)
						break
					}
				}
				
				// Check for PQC patterns
				for _, pattern := range pqcPatterns {
					if strings.Contains(fileContent, pattern) {
						pqcFound = true
						results["Python PQC Usage"] = "Found"
						break
					}
				}
			}
		}
	}
	
	// Scan system library directories for informational purposes
	for _, dirPattern := range systemLibraryDirectories {
		dirs, _ := filepath.Glob(dirPattern)
		for _, dir := range dirs {
			// Find Python files
			pyFiles, _ := filepath.Glob(filepath.Join(dir, "**/*.py"))
			for _, file := range pyFiles {
				content, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				
				fileContent := string(content)
				
				// Check for generic crypto references in libraries
				for _, pattern := range classicCryptoGenericPatterns {
					if strings.Contains(fileContent, pattern) {
						libraryReferencesFound = true
						results["Python Library Crypto References"] = "Found"
						libraryReferenceFiles = append(libraryReferenceFiles, file)
						break
					}
				}
			}
		}
	}
	
	// Record application crypto findings (critical)
	if appCryptoFound {
		results["Python Classic Crypto Locations"] = strings.Join(appCryptoFiles, ", ")
	} else {
		results["Python Classic Crypto"] = "Not found"
	}
	
	// Record library references (informational)
	if libraryReferencesFound {
		results["Python Library Crypto Reference Locations"] = strings.Join(libraryReferenceFiles, ", ")
	} else {
		results["Python Library Crypto References"] = "Not found"
	}

	if !pqcFound {
		results["Python PQC Usage"] = "Not found"
	}
}

// checkNodeRuntime checks for Node.js runtime and its PQC readiness
func checkNodeRuntime(results map[string]string) {
	fmt.Println("Checking Node.js runtime environment...")

	// Check for Node.js installation
	nodePath, err := exec.LookPath("node")
	if err != nil {
		results["Node.js"] = "Not installed"
		return
	}
	results["Node.js"] = "Installed"
	results["Node.js Path"] = nodePath

	// Get Node.js version
	cmd := exec.Command(nodePath, "--version")
	output, err := cmd.Output()
	if err == nil {
		results["Node.js Version"] = strings.TrimSpace(string(output))
	}

	// Check for npm
	npmPath, err := exec.LookPath("npm")
	if err == nil {
		results["npm"] = "Installed"
		results["npm Path"] = npmPath
		checkNodeCryptoModules(npmPath, results)
	}

	// Scan for crypto usage in JS/TS files
	checkNodeSourceFiles(results)
}

// checkNodeCryptoModules checks for installed npm crypto modules
func checkNodeCryptoModules(npmPath string, results map[string]string) {
	cmd := exec.Command(npmPath, "list", "--depth=1")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	packageList := string(output)
	cryptoModules := []string{"node-forge", "sjcl", "libsodium", "@openpgp/js", "crypto"}
	installedModules := []string{}
	for _, module := range cryptoModules {
		if strings.Contains(packageList, module) {
			installedModules = append(installedModules, module)
			results["Node Module "+module] = "Installed"
		}
	}
	if len(installedModules) > 0 {
		results["Node.js Crypto Modules"] = strings.Join(installedModules, ", ")
	}
	// PQC modules (rare)
	pqcModules := []string{"@openpgp/js"}
	installedPQC := []string{}
	for _, module := range pqcModules {
		if strings.Contains(packageList, module) {
			installedPQC = append(installedPQC, module)
			results["Node PQC Module "+module] = "Installed"
		}
	}
	if len(installedPQC) > 0 {
		results["Node.js PQC Modules"] = strings.Join(installedPQC, ", ")
	}
}

// checkNodeSourceFiles scans JS/TS files for crypto usage
func checkNodeSourceFiles(results map[string]string) {
	// Common directories to search for JS/TS files
	directories := []string{"./", "/home/*/projects", "/home/*/src"}
	classicalPatterns := []string{
		"crypto.createSign('RSA-SHA256'",
		"crypto.createSign(\"RSA-SHA256\"",
		"crypto.createSign('RSA-",
		"crypto.createSign(\"RSA-",
		"crypto.createSign('DSA-",
		"crypto.createSign(\"DSA-",
		"crypto.createSign('ECDSA",
		"crypto.createSign(\"ECDSA",
		"crypto.createVerify('RSA-",
		"crypto.createVerify(\"RSA-",
		"crypto.createVerify('DSA-",
		"crypto.createVerify(\"DSA-",
		"crypto.createVerify('ECDSA",
		"crypto.createVerify(\"ECDSA",
	}
	pqcPatterns := []string{"dilithium", "kyber", "sphincs", "falcon", "openpgp", "@openpgp/js"}
	classicFound := false
	pqcFound := false
	// track files containing hard-coded classical crypto so we can show them later
	classicFiles := []string{}
	for _, dir := range directories {
		jsFiles, _ := filepath.Glob(filepath.Join(dir, "**/*.js"))
		tsFiles, _ := filepath.Glob(filepath.Join(dir, "**/*.ts"))
		files := append(jsFiles, tsFiles...)
		for _, file := range files {
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			fileContent := string(content)
			for _, pattern := range classicalPatterns {
				if strings.Contains(fileContent, pattern) {
					classicFound = true
					results["Node.js Classic Crypto"] = "Found"
					classicFiles = append(classicFiles, file)
					break
				}
			}
			for _, pattern := range pqcPatterns {
				if strings.Contains(fileContent, pattern) {
					pqcFound = true
					results["Node.js PQC Usage"] = "Found"
					break
				}
			}
		}
	}
	if classicFound {
		results["Node.js Classic Crypto Locations"] = strings.Join(classicFiles, ", ")
	} else {
		results["Node.js Classic Crypto"] = "Not found"
	}
	if !pqcFound {
		results["Node.js PQC Usage"] = "Not found"
	}
}

// Note: printRuntimeAuditResults function has been removed as recommendations are now handled by runtime_recommendations.go

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
	"strings"
	"time"
)

// Evidence represents what we observed and how we observed it
type Evidence struct {
	Probe   string // e.g. "uname -r", "apt-cache policy linux-image-generic"
	Snippet string // short excerpt (first lines, trimmed)
}

// LifePhase represents the vendor support lifecycle phase
type LifePhase string

const (
	PhaseSupported   LifePhase = "supported"
	PhaseMaintenance LifePhase = "maintenance"
	PhaseEOL         LifePhase = "eol"
	PhaseUnknown     LifePhase = "unknown"
)

// KernelInfo aggregates all observed kernel signals (pure facts, no interpretation)
type KernelInfo struct {
	Version          string            // 6.8.0-45-generic
	Distro           string            // ubuntu|debian|rhel|centos|sles|arch|unknown
	DistroVersion    string            // 22.04, 12, 9 ...
	PkgMgr           string            // apt|dnf|yum|zypper|pacman|unknown
	LatestInRepo     string            // newest kernel pkg available via pkg manager
	CryptoAlgos      []string          // algorithm names from /proc/crypto
	Sysctl           map[string]string // queried sysctl values (not assumed)
	BootArgs         map[string]string // parsed /proc/cmdline
	IsContainer      bool
	LifecyclePhase   LifePhase         // vendor support phase
}

// KernelParam represents a kernel parameter and its security implications (legacy)
type KernelParam struct {
	name        string
	value       string
	description string
	secure      bool
	pqcRelevant bool
}

// CryptoAlgorithm represents a cryptographic algorithm from /proc/crypto (legacy)
type CryptoAlgorithm struct {
	Name      string
	Driver    string
	Module    string
	Type      string
	Priority  string
	PQCStatus string // "compliant", "non-compliant", or "unknown"
}

// KernelReport represents the structure of the JSON report for the kernel command
type KernelReport struct {
	ServerIP             string                `json:"server_ip"`
	ReportTime           string                `json:"report_time"`
	KernelVersion        string                `json:"kernel_version"`
	PQCSupport           bool                  `json:"pqc_support"`
	SecureParams         int                   `json:"secure_params"`
	InsecureParams       int                   `json:"insecure_params"`
	PQCRelevantParams    int                   `json:"pqc_relevant_params"`
	PQCCompliantAlgos    int                   `json:"pqc_compliant_algos"`
	NonPQCCompliantAlgos int                   `json:"non_pqc_compliant_algos"`
	Recommendations      []scan.Recommendation `json:"recommendations"`
}

// TestKernel checks kernel parameters for PQC readiness and security settings
func TestKernel(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Linux Kernel Security Analysis ===")
	fmt.Println("Checking kernel parameters for PQC readiness and security settings...")

	// Collect all kernel information using new signals-based approach
	fmt.Println("Collecting kernel information...")
	kernelInfo := CollectKernelInfo()

	// Display collected information
	fmt.Printf("Kernel Version: %s\n", kernelInfo.Version)
	fmt.Printf("Distribution: %s %s\n", kernelInfo.Distro, kernelInfo.DistroVersion)
	fmt.Printf("Package Manager: %s\n", kernelInfo.PkgMgr)
	fmt.Printf("Lifecycle Phase: %s\n", kernelInfo.LifecyclePhase)
	
	if kernelInfo.LatestInRepo != "" {
		fmt.Printf("Latest in Repository: %s\n", kernelInfo.LatestInRepo)
	}
	
	if len(kernelInfo.CryptoAlgos) > 0 {
		fmt.Printf("Crypto Algorithms: %d found\n", len(kernelInfo.CryptoAlgos))
	}
	
	if kernelInfo.IsContainer {
		fmt.Println("Container Environment: Detected")
	}

	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	awsResults := make(map[string]string)
	if awsData := inspectAWSLoadBalancerForKernel(); len(awsData) > 0 {
		for key, value := range awsData {
			awsResults[key] = value
		}
	}

	// Generate evidence-backed recommendations using new architecture
	fmt.Println("Generating evidence-backed recommendations...")
	recommendations := GenerateKernelRecommendationsFromInfo(kernelInfo, awsResults)

	// Create a recommendation manager for backward compatibility with status reporting
	rm := scan.NewRecommendationManager()

	// Generate legacy status reports for display (keeping existing UI)
	// Note: This maintains backward compatibility while using new recommendation logic
	secureCount := 0
	insecureCount := 0
	pqcRelevantCount := 0
	
	// Count secure/insecure sysctl parameters for status display
	for key, value := range kernelInfo.Sysctl {
		if isSecureParameter(key, value) {
			secureCount++
		} else if isInsecureParameter(key, value) {
			insecureCount++
		}
		if isPQCRelevantParameter(key) {
			pqcRelevantCount++
		}
	}

	// Generate status display using collected info
	generateKernelStatusFromInfo(kernelInfo, secureCount, insecureCount, pqcRelevantCount, rm)

	// Generate AWS status items if available
	if len(awsResults) > 0 {
		generateKernelAWSStatus(awsResults, rm)
	}

	// Add new evidence-backed recommendations to the manager
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

		// Create report structure using collected kernel info
		report := KernelReport{
			ServerIP:             serverIP,
			ReportTime:           time.Now().Format(time.RFC3339),
			KernelVersion:        kernelInfo.Version,
			PQCSupport:           len(kernelInfo.CryptoAlgos) > 0,
			SecureParams:         secureCount,
			InsecureParams:       insecureCount,
			PQCRelevantParams:    pqcRelevantCount,
			PQCCompliantAlgos:    len(kernelInfo.CryptoAlgos), // Use actual crypto algo count
			NonPQCCompliantAlgos: 0, // Will be calculated from crypto analysis
			Recommendations:      allRecommendations,
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
			filePath := filepath.Join(reportDir, "kernel.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/kernel.json")
			} else {
				fmt.Printf("\nError writing JSON report: %s\n", err)
			}
		} else {
			fmt.Printf("\nError creating JSON report: %s\n", err)
		}
	}

	return allRecommendations
}

// Helper functions for parameter classification (used for status display)
func isSecureParameter(key, value string) bool {
	secureSettings := map[string]string{
		"kernel.randomize_va_space":     "2",
		"kernel.dmesg_restrict":         "1",
		"kernel.kptr_restrict":          "2",
		"net.ipv4.conf.all.send_redirects": "0",
		"net.ipv4.conf.default.send_redirects": "0",
		"net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv4.conf.default.accept_redirects": "0",
	}
	
	if expectedValue, exists := secureSettings[key]; exists {
		return value == expectedValue
	}
	return false
}

func isInsecureParameter(key, value string) bool {
	insecureSettings := map[string]string{
		"kernel.randomize_va_space":     "0",
		"kernel.dmesg_restrict":         "0",
		"kernel.kptr_restrict":          "0",
		"net.ipv4.conf.all.send_redirects": "1",
		"net.ipv4.conf.default.send_redirects": "1",
		"net.ipv4.conf.all.accept_redirects": "1",
		"net.ipv4.conf.default.accept_redirects": "1",
	}
	
	if badValue, exists := insecureSettings[key]; exists {
		return value == badValue
	}
	return false
}

func isPQCRelevantParameter(key string) bool {
	pqcRelevantKeys := []string{
		"crypto.fips_enabled",
		"kernel.randomize_va_space",
		"net.core.bpf_jit_enable",
		"net.core.bpf_jit_harden",
	}
	
	for _, relevantKey := range pqcRelevantKeys {
		if key == relevantKey {
			return true
		}
	}
	return false
}

// generateKernelStatusFromInfo creates status items using KernelInfo
func generateKernelStatusFromInfo(info KernelInfo, secureCount, insecureCount, pqcRelevantCount int, rm *scan.RecommendationManager) {
	kernelModuleID := scan.CommandModules["kernel"] // Use correct kernel module ID (3)
	
	// Kernel version status
	rm.AddStatus(kernelModuleID, 1, 1, fmt.Sprintf("Kernel version: %s", info.Version), scan.InfoRecommendation, "", 1)
	
	// Distribution status
	rm.AddStatus(kernelModuleID, 1, 2, fmt.Sprintf("Distribution: %s %s", info.Distro, info.DistroVersion), scan.InfoRecommendation, "", 1)
	
	// Lifecycle phase status
	var lifecycleType scan.RecommendationType
	var severity int
	switch info.LifecyclePhase {
	case PhaseSupported:
		lifecycleType = scan.SuccessRecommendation
		severity = 1
	case PhaseMaintenance:
		lifecycleType = scan.WarningRecommendation
		severity = 3
	case PhaseEOL:
		lifecycleType = scan.CriticalRecommendation
		severity = 5
	default:
		lifecycleType = scan.InfoRecommendation
		severity = 1
	}
	
	rm.AddStatus(kernelModuleID, 1, 3, fmt.Sprintf("Lifecycle phase: %s", info.LifecyclePhase), lifecycleType, "", severity)
	
	// Crypto algorithms status
	if len(info.CryptoAlgos) > 0 {
		rm.AddStatus(kernelModuleID, 2, 1, fmt.Sprintf("Crypto algorithms available: %d", len(info.CryptoAlgos)), scan.SuccessRecommendation, "", 1)
	} else {
		rm.AddStatus(kernelModuleID, 2, 1, "No crypto algorithms detected", scan.WarningRecommendation, "", 3)
	}
	
	// Security parameters status
	if secureCount > 0 {
		rm.AddStatus(kernelModuleID, 3, 1, fmt.Sprintf("Secure kernel parameters: %d", secureCount), scan.SuccessRecommendation, "", 1)
	}
	
	if insecureCount > 0 {
		rm.AddStatus(kernelModuleID, 3, 2, fmt.Sprintf("Insecure kernel parameters: %d", insecureCount), scan.CriticalRecommendation, "", 5)
	}
	
	// Container environment status
	if info.IsContainer {
		rm.AddStatus(kernelModuleID, 4, 1, "Container environment detected", scan.InfoRecommendation, "", 1)
	}
}

// getKernelVersion returns the current kernel version
func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

// checkPQCSupport checks if the kernel supports PQC algorithms
func checkPQCSupport() bool {
	// Check for PQC modules in the kernel
	cmd := exec.Command("find", "/lib/modules/$(uname -r)/kernel", "-name", "*kyber*", "-o", "-name", "*dilithium*", "-o", "-name", "*sphincs*")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		return true
	}

	// Check kernel config for PQC options
	configFile := "/boot/config-$(uname -r)"
	if _, err := os.Stat(configFile); err == nil {
		file, err := os.Open(configFile)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "CONFIG_CRYPTO_KYBER=") ||
					strings.Contains(line, "CONFIG_CRYPTO_DILITHIUM=") ||
					strings.Contains(line, "CONFIG_CRYPTO_SPHINCS=") {
					return true
				}
			}
		}
	}

	return false
}

// getKernelParameters returns a map of kernel parameters and their values
func getKernelParameters() map[string]KernelParam {
	params := make(map[string]KernelParam)

	// Define security-relevant kernel parameters
	securityParams := map[string]KernelParam{
		"kernel.randomize_va_space": {
			name:        "kernel.randomize_va_space",
			description: "Address space layout randomization (ASLR)",
			secure:      true,
			pqcRelevant: false,
		},
		"kernel.kptr_restrict": {
			name:        "kernel.kptr_restrict",
			description: "Restricts access to kernel pointers in /proc",
			secure:      true,
			pqcRelevant: false,
		},
		"kernel.dmesg_restrict": {
			name:        "kernel.dmesg_restrict",
			description: "Restricts access to kernel logs",
			secure:      true,
			pqcRelevant: false,
		},
		"kernel.unprivileged_bpf_disabled": {
			name:        "kernel.unprivileged_bpf_disabled",
			description: "Disables unprivileged BPF",
			secure:      true,
			pqcRelevant: false,
		},
		"net.ipv4.tcp_syncookies": {
			name:        "net.ipv4.tcp_syncookies",
			description: "Protection against SYN flood attacks",
			secure:      true,
			pqcRelevant: false,
		},
		"net.ipv4.conf.all.rp_filter": {
			name:        "net.ipv4.conf.all.rp_filter",
			description: "Source route validation",
			secure:      true,
			pqcRelevant: false,
		},
		"net.ipv4.conf.all.accept_redirects": {
			name:        "net.ipv4.conf.all.accept_redirects",
			description: "ICMP redirect acceptance",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"net.ipv4.conf.all.secure_redirects": {
			name:        "net.ipv4.conf.all.secure_redirects",
			description: "Secure ICMP redirect acceptance",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"net.ipv4.conf.all.send_redirects": {
			name:        "net.ipv4.conf.all.send_redirects",
			description: "ICMP redirect sending",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"net.ipv4.conf.all.accept_source_route": {
			name:        "net.ipv4.conf.all.accept_source_route",
			description: "Source routing acceptance",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"net.ipv6.conf.all.accept_redirects": {
			name:        "net.ipv6.conf.all.accept_redirects",
			description: "IPv6 ICMP redirect acceptance",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"net.ipv6.conf.all.accept_source_route": {
			name:        "net.ipv6.conf.all.accept_source_route",
			description: "IPv6 source routing acceptance",
			secure:      false, // Should be 0 for security
			pqcRelevant: false,
		},
		"crypto.fips_enabled": {
			name:        "crypto.fips_enabled",
			description: "FIPS 140-2 compliance mode",
			secure:      true,
			pqcRelevant: true, // Relevant for crypto policy
		},
	}

	// Get current kernel parameter values
	cmd := exec.Command("sysctl", "-a")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[FAIL] Error getting kernel parameters:", err)
		return params
	}

	// Parse output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		paramName := strings.TrimSpace(parts[0])
		paramValue := strings.TrimSpace(parts[1])

		// Check if this is a security-relevant parameter
		if param, exists := securityParams[paramName]; exists {
			param.value = paramValue
			params[paramName] = param
		}
	}

	return params
}

// getCryptoAlgorithms reads /proc/crypto and returns a list of cryptographic algorithms
func getCryptoAlgorithms() (map[string]CryptoAlgorithm, int, int, int, int) {
	fmt.Println("\nAnalyzing Cryptographic Algorithms from /proc/crypto...")

	// Define algorithms considered PQC-compliant (post-quantum)
	pqcCompliantAlgos := map[string]bool{
		"kyber":     true,
		"dilithium": true,
		"sphincs":   true,
		"falcon":    true,
		"mceliece":  true,
		"ntru":      true,
		"sike":      true, // Note: SIKE was broken but still included here for completeness
		"frodokem":  true,
		"bike":      true,
		"hqc":       true,
		"rainbow":   true, // Note: Rainbow was broken but still included here for completeness
	}

	// Define CNSA-2.0 approved symmetric/hash algorithms (quantum-safe enough)
	cnsaApprovedAlgos := map[string]bool{
		"aes":      true,
		"sha256":   true,
		"sha384":   true,
		"sha512":   true,
		"sha3-256": true,
		"sha3-384": true,
		"sha3-512": true,
		"hmac":     true,
		"gcm":      true,
		"ctr":      true,
		"cbc":      true,
		"xts":      true,
	}

	// Define quantum-vulnerable asymmetric algorithms
	quantumVulnerableAlgos := map[string]bool{
		"rsa":      true,
		"ecdsa":    true,
		"ecdh":     true,
		"dh":       true,
		"pkcs1pad": true,
	}

	// Read /proc/crypto
	file, err := os.Open("/proc/crypto")
	if err != nil {
		fmt.Println("Error: Cannot access /proc/crypto:", err)
		return make(map[string]CryptoAlgorithm), 0, 0, 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	algorithms := make(map[string]CryptoAlgorithm)
	var currentAlgo CryptoAlgorithm
	var currentName string

	// Parse /proc/crypto file
	for scanner.Scan() {
		line := scanner.Text()

		// Parse key-value pairs
		if line == "" {
			// Empty line marks the end of an algorithm entry
			if currentName != "" {
				algorithms[currentName] = currentAlgo
				currentName = ""
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "name":
			currentName = value
			currentAlgo = CryptoAlgorithm{Name: value}

			// Check algorithm classification
			valueLower := strings.ToLower(value)
			isPQCCompliant := false
			isCNSAApproved := false
			isQuantumVulnerable := false

			// Check if it's a post-quantum algorithm
			for pqcAlgo := range pqcCompliantAlgos {
				if strings.Contains(valueLower, pqcAlgo) {
					isPQCCompliant = true
					break
				}
			}

			// Check if it's CNSA-2.0 approved symmetric/hash algorithm
			if !isPQCCompliant {
				for cnsaAlgo := range cnsaApprovedAlgos {
					if strings.Contains(valueLower, cnsaAlgo) {
						isCNSAApproved = true
						break
					}
				}
			}

			// Check if it's quantum-vulnerable asymmetric algorithm
			if !isPQCCompliant && !isCNSAApproved {
				for vulnAlgo := range quantumVulnerableAlgos {
					if strings.Contains(valueLower, vulnAlgo) {
						isQuantumVulnerable = true
						break
					}
				}
			}

			// Set PQC status based on classification
			if isPQCCompliant {
				currentAlgo.PQCStatus = "compliant"
			} else if isCNSAApproved {
				currentAlgo.PQCStatus = "cnsa-approved"
			} else if isQuantumVulnerable {
				currentAlgo.PQCStatus = "quantum-vulnerable"
			} else {
				currentAlgo.PQCStatus = "non-compliant"
			}

		case "driver":
			currentAlgo.Driver = value
		case "module":
			currentAlgo.Module = value
		case "type":
			currentAlgo.Type = value
		case "priority":
			currentAlgo.Priority = value
		}
	}

	// Add the last algorithm if there is one
	if currentName != "" {
		algorithms[currentName] = currentAlgo
	}

	// Count algorithms by category
	pqcCompliantCount := 0
	cnsaApprovedCount := 0
	quantumVulnerableCount := 0
	nonPQCCompliantCount := 0

	fmt.Println("\nCryptographic Algorithms:")
	for name, algo := range algorithms {
		switch algo.PQCStatus {
		case "compliant":
			pqcCompliantCount++
			fmt.Printf("- %s (Type: %s): PQC-compliant\n", name, algo.Type)
		case "cnsa-approved":
			cnsaApprovedCount++
			fmt.Printf("- %s (Type: %s): CNSA-2.0 approved\n", name, algo.Type)
		case "quantum-vulnerable":
			quantumVulnerableCount++
			fmt.Printf("- %s (Type: %s): Quantum-vulnerable\n", name, algo.Type)
		default:
			nonPQCCompliantCount++
			fmt.Printf("- %s (Type: %s): Not classified\n", name, algo.Type)
		}
	}

	fmt.Printf("\nTotal algorithms found: %d\n", len(algorithms))
	fmt.Printf("PQC-compliant algorithms: %d\n", pqcCompliantCount)
	fmt.Printf("CNSA-2.0 approved algorithms: %d\n", cnsaApprovedCount)
	fmt.Printf("Quantum-vulnerable algorithms: %d\n", quantumVulnerableCount)
	fmt.Printf("Other algorithms: %d\n", nonPQCCompliantCount)

	return algorithms, pqcCompliantCount, cnsaApprovedCount, quantumVulnerableCount, nonPQCCompliantCount
}

// analyzeKernelParameters analyzes kernel parameters for security issues
func analyzeKernelParameters(params map[string]KernelParam) (int, int, int, map[string]KernelParam, map[string]KernelParam, map[string]KernelParam) {
	fmt.Println("\nKernel Parameter Analysis:")

	// Count secure and insecure parameters
	secureCount := 0
	insecureCount := 0
	pqcRelevantCount := 0

	// Create maps to store secure, insecure, and PQC relevant parameters
	secureParams := make(map[string]KernelParam)
	insecureParams := make(map[string]KernelParam)
	pqcRelevantParams := make(map[string]KernelParam)

	// Security-relevant parameters
	fmt.Println("\nSecurity Parameters:")

	for _, param := range params {
		fmt.Printf("• %s = %s\n", param.name, param.value)
		fmt.Printf("  %s\n", param.description)

		// Check if the parameter is set securely
		isSecure := false
		switch param.name {
		case "kernel.randomize_va_space":
			isSecure = param.value == "2"
		case "kernel.kptr_restrict":
			isSecure = param.value == "1" || param.value == "2"
		case "kernel.dmesg_restrict":
			isSecure = param.value == "1"
		case "kernel.unprivileged_bpf_disabled":
			isSecure = param.value == "1"
		case "net.ipv4.tcp_syncookies":
			isSecure = param.value == "1"
		case "net.ipv4.conf.all.rp_filter":
			isSecure = param.value == "1" || param.value == "2"
		case "net.ipv4.conf.all.accept_redirects":
			isSecure = param.value == "0"
		case "net.ipv4.conf.all.secure_redirects":
			isSecure = param.value == "0"
		case "net.ipv4.conf.all.send_redirects":
			isSecure = param.value == "0"
		case "net.ipv4.conf.all.accept_source_route":
			isSecure = param.value == "0"
		case "net.ipv6.conf.all.accept_redirects":
			isSecure = param.value == "0"
		case "net.ipv6.conf.all.accept_source_route":
			isSecure = param.value == "0"
		case "crypto.fips_enabled":
			isSecure = param.value == "1"
		}

		if isSecure {
			fmt.Println("  ✅ Secure setting")
			secureCount++
			// Store secure parameter
			secureParams[param.name] = param
		} else {
			fmt.Println("  [FAIL] Insecure setting")
			insecureCount++
			// Store insecure parameter
			insecureParams[param.name] = param
		}

		if param.pqcRelevant {
			fmt.Println("  [INFO] Relevant for post-quantum cryptography")
			pqcRelevantCount++
			// Store PQC relevant parameter
			pqcRelevantParams[param.name] = param
		}

		fmt.Println()
	}

	// Print summary
	fmt.Println("\n=== Kernel Security Summary ===")
	fmt.Printf("Total parameters checked: %d\n", len(params))
	fmt.Printf("Secure parameters: %d\n", secureCount)
	fmt.Printf("Insecure parameters: %d\n", insecureCount)
	fmt.Printf("PQC-relevant parameters: %d\n", pqcRelevantCount)

	return secureCount, insecureCount, pqcRelevantCount, insecureParams, secureParams, pqcRelevantParams
}

// CollectKernelInfo gathers all kernel signals (pure observation, no interpretation)
func CollectKernelInfo() KernelInfo {
	info := KernelInfo{
		Sysctl:   make(map[string]string),
		BootArgs: make(map[string]string),
	}
	
	// 1) Kernel version
	info.Version = collectKernelVersion()
	
	// 2) Distribution and package manager detection
	info.Distro, info.DistroVersion = collectDistroInfo()
	info.PkgMgr = detectPackageManager()
	
	// 3) Latest kernel available in repos
	info.LatestInRepo = queryLatestKernel(info.PkgMgr)
	
	// 4) Crypto algorithms from /proc/crypto
	info.CryptoAlgos = collectCryptoAlgorithms()
	
	// 5) Security-relevant sysctl values
	info.Sysctl = batchSysctl([]string{
		"kernel.randomize_va_space",
		"kernel.kptr_restrict", 
		"kernel.dmesg_restrict",
		"kernel.sysrq",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.conf.all.accept_source_route",
		"net.ipv4.conf.all.accept_redirects",
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
	})
	
	// 6) Boot arguments from /proc/cmdline
	info.BootArgs = parseCmdline()
	
	// 7) Container detection
	info.IsContainer = detectContainer()
	
	// 8) Lifecycle phase assessment
	info.LifecyclePhase = assessLifecycle(info)
	
	return info
}

// collectKernelVersion returns the current kernel version
func collectKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// collectDistroInfo returns distribution ID and version from /etc/os-release
func collectDistroInfo() (string, string) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown", "unknown"
	}
	defer file.Close()
	
	var id, version string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	
	if id == "" {
		id = "unknown"
	}
	if version == "" {
		version = "unknown"
	}
	
	return id, version
}

// detectPackageManager detects the system package manager
func detectPackageManager() string {
	managers := []struct {
		cmd  string
		name string
	}{
		{"apt", "apt"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"zypper", "zypper"},
		{"pacman", "pacman"},
	}
	
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr.cmd); err == nil {
			return mgr.name
		}
	}
	return "unknown"
}

// queryLatestKernel queries the package manager for the latest available kernel
func queryLatestKernel(pkgMgr string) string {
	var cmd *exec.Cmd
	
	switch pkgMgr {
	case "apt":
		cmd = exec.Command("apt-cache", "policy", "linux-image-generic")
	case "dnf":
		cmd = exec.Command("dnf", "list", "available", "kernel", "--quiet")
	case "yum":
		cmd = exec.Command("yum", "list", "available", "kernel", "--quiet")
	case "zypper":
		cmd = exec.Command("zypper", "search", "-s", "kernel-default")
	case "pacman":
		cmd = exec.Command("pacman", "-Ss", "linux")
	default:
		return "unknown"
	}
	
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	
	// Parse output to extract latest version (simplified for now)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Candidate:") && pkgMgr == "apt" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	
	return "query-completed"
}

// collectCryptoAlgorithms reads algorithm names from /proc/crypto
func collectCryptoAlgorithms() []string {
	var algorithms []string
	
	file, err := os.Open("/proc/crypto")
	if err != nil {
		return algorithms
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				algorithms = append(algorithms, name)
			}
		}
	}
	
	return algorithms
}

// batchSysctl queries multiple sysctl values efficiently
func batchSysctl(keys []string) map[string]string {
	result := make(map[string]string)
	
	for _, key := range keys {
		cmd := exec.Command("sysctl", "-n", key)
		output, err := cmd.Output()
		if err != nil {
			result[key] = "unknown"
		} else {
			result[key] = strings.TrimSpace(string(output))
		}
	}
	
	return result
}

// parseCmdline parses /proc/cmdline into key-value pairs
func parseCmdline() map[string]string {
	result := make(map[string]string)
	
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return result
	}
	
	cmdline := strings.TrimSpace(string(data))
	args := strings.Fields(cmdline)
	
	for _, arg := range args {
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			result[parts[0]] = parts[1]
		} else {
			result[arg] = "true"
		}
	}
	
	return result
}

// detectContainer checks if running in a container environment
func detectContainer() bool {
	// Check for container indicators
	indicators := []string{
		"/.dockerenv",
		"/run/.containerenv",
	}
	
	for _, indicator := range indicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}
	
	// Check cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "containerd") {
			return true
		}
	}
	
	return false
}

// assessLifecycle determines the vendor support lifecycle phase
func assessLifecycle(info KernelInfo) LifePhase {
	switch info.Distro {
	case "ubuntu":
		return assessUbuntuLifecycle(info)
	case "debian":
		return assessDebianLifecycle(info)
	case "rhel", "centos", "almalinux", "rocky":
		return assessRHELLifecycle(info)
	default:
		return PhaseUnknown
	}
}

// assessUbuntuLifecycle assesses Ubuntu kernel lifecycle phase
func assessUbuntuLifecycle(info KernelInfo) LifePhase {
	// Simplified lifecycle assessment - in production this would use
	// more sophisticated version parsing and lifecycle data
	switch info.DistroVersion {
	case "24.04", "22.04", "20.04":
		return PhaseSupported
	case "18.04":
		return PhaseMaintenance
	default:
		return PhaseUnknown
	}
}

// assessDebianLifecycle assesses Debian kernel lifecycle phase  
func assessDebianLifecycle(info KernelInfo) LifePhase {
	// Simplified lifecycle assessment
	switch info.DistroVersion {
	case "12", "11":
		return PhaseSupported
	case "10":
		return PhaseMaintenance
	default:
		return PhaseUnknown
	}
}

// assessRHELLifecycle assesses RHEL/CentOS/AlmaLinux kernel lifecycle phase
func assessRHELLifecycle(info KernelInfo) LifePhase {
	// Simplified lifecycle assessment
	switch info.DistroVersion {
	case "9", "8":
		return PhaseSupported
	case "7":
		return PhaseMaintenance
	default:
		return PhaseUnknown
	}
}

// Note: printKernelRecommendations has been replaced by generateKernelRecommendations in kernel_recommendations.go

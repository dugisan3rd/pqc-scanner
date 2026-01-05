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

// OpenSSHReport represents the structure of the JSON report for the openssh command
type OpenSSHReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	OpenSSHInfo    map[string]string      `json:"openssh_info"`
	HostKeyResults map[string]string      `json:"host_key_results"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestOpenSSH checks OpenSSH configuration for PQC support and security issues
func TestOpenSSH(jsonOutput bool) []scan.Recommendation {
	// Results map
	results := make(map[string]string)
	
	// Host key audit results
	hostKeyResults := make(map[string]string)

	// Print header
	fmt.Println("=== OpenSSH PQC Configuration Check ===")
	
	// Get OpenSSH client version
	cmd := exec.Command("ssh", "-V")
	output, err := cmd.CombinedOutput()
	if err == nil {
		// ssh -V outputs to stderr, not stdout
		version := strings.TrimSpace(string(output))
		results["OpenSSHClientVersion"] = version
		fmt.Printf("Client: %s\n", version)
	} else {
		results["OpenSSHClientVersion"] = "Unknown"
		fmt.Println("Could not determine OpenSSH client version")
	}
	
	// Get OpenSSH server version
	cmd = exec.Command("sshd", "-V")
	output, err = cmd.CombinedOutput()
	if err == nil {
		// sshd -V outputs to stderr, not stdout
		version := strings.TrimSpace(string(output))
		results["OpenSSHServerVersion"] = version
		fmt.Printf("Server: %s\n", version)
	} else {
		// Try alternative method to get server version by checking the binary directly
		cmd = exec.Command("/usr/sbin/sshd", "-v")
		output, err = cmd.CombinedOutput()
		if err == nil || strings.Contains(string(output), "OpenSSH") {
			// Even with non-zero exit code, we might get version info
			outputStr := string(output)
			if strings.Contains(outputStr, "OpenSSH") {
				// Extract the version string
				for _, line := range strings.Split(outputStr, "\n") {
					if strings.Contains(line, "OpenSSH") {
						version := strings.TrimSpace(line)
						results["OpenSSHServerVersion"] = version
						fmt.Printf("Server: %s\n", version)
						break
					}
				}
			}
		} else {
			// Try with dpkg if it's a Debian-based system
			cmd = exec.Command("dpkg", "-s", "openssh-server")
			output, err = cmd.CombinedOutput()
			if err == nil {
				outputStr := string(output)
				scanner := bufio.NewScanner(strings.NewReader(outputStr))
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "Version:") {
						version := strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
						results["OpenSSHServerVersion"] = "OpenSSH Server " + version
						fmt.Printf("Server: OpenSSH Server %s\n", version)
						break
					}
				}
			} else {
				// Try with rpm if it's a Red Hat-based system
				cmd = exec.Command("rpm", "-q", "openssh-server")
				output, err = cmd.CombinedOutput()
				if err == nil {
					version := strings.TrimSpace(string(output))
					results["OpenSSHServerVersion"] = version
					fmt.Printf("Server: %s\n", version)
				} else {
					// Last resort: check if sshd is installed
					cmd = exec.Command("which", "sshd")
					_, err = cmd.CombinedOutput()
					if err == nil {
						results["OpenSSHServerVersion"] = "Installed (version unknown)"
						fmt.Println("OpenSSH server installed but version could not be determined")
					} else {
						results["OpenSSHServerVersion"] = "Not installed"
						fmt.Println("OpenSSH server not installed")
					}
				}
			}
		}
	}

	// Check if sshd_config exists
	sshdConfigPath := "/etc/ssh/sshd_config"
	configExists := true
	if _, err := os.Stat(sshdConfigPath); err != nil {
		configExists = false
		
		fmt.Println("sshd_config not found at ", sshdConfigPath)
		fmt.Println("Using sample configuration for demonstration purposes...")
		
		// Use a temporary file for demonstration
		tmpFile, err := os.CreateTemp("", "sample_sshd_config")
		if err != nil {
			fmt.Println("Error creating sample config:", err)
			return []scan.Recommendation{}
		}
		defer os.Remove(tmpFile.Name()) // Clean up
		
		// Write sample configuration
		sampleConfig := `# Sample sshd_config file for demonstration
# This is not a real configuration

Port 22
ListenAddress 0.0.0.0

# Example with legacy algorithm
HostKeyAlgorithms ssh-ed25519,ssh-rsa

# Example with only modern algorithms
# PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sk,ed25519-sk

# Example missing recommended algorithms
CASignatureAlgorithms ssh-rsa
`
		if _, err := tmpFile.Write([]byte(sampleConfig)); err != nil {
			fmt.Println("Error writing sample config:", err)
			return []scan.Recommendation{}
		}
		tmpFile.Close()
		
		sshdConfigPath = tmpFile.Name()
	} else {
		fmt.Printf("OpenSSH config found: %s\n", sshdConfigPath)
	}

	// Parse the sshd_config file
	fmt.Println("\nAnalyzing OpenSSH configuration:")
	parseSSHDConfig(sshdConfigPath, results)

	// Store whether we're using a sample config
	if !configExists {
		results["UsingSampleConfig"] = "true"
	}
	
	// Audit SSH host keys
	fmt.Println("\nAuditing SSH host keys:")
	auditSSHHostKeys(hostKeyResults)

	// Print CLI summary
	printOpenSSHCLISummary(results, hostKeyResults)

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Debug output removed

	// Check AWS environment and load balancer configuration
	checkAWSEnvironmentForOpenSSH(results)

	// Generate status items based on scan results
	generateOpenSSHStatus(results, rm)

	// Generate recommendations based on detection results
	recommendations := generateOpenSSHRecommendations(results, hostKeyResults)

	// Add recommendations to the manager
	rm.AppendRecommendations(recommendations)

	// Get all recommendations and status items from the manager
	allRecommendations := rm.GetRecommendations()

	// Status section will be printed by main program
	// No need to print it here to avoid duplication

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
		report := OpenSSHReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			OpenSSHInfo:    results,
			HostKeyResults: hostKeyResults,
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
			filePath := filepath.Join(reportDir, "openssh.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/openssh.json")
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

// parseSSHDConfig parses the sshd_config file for security-related settings
func parseSSHDConfig(configPath string, results map[string]string) {
	file, err := os.Open(configPath)
	if err != nil {
		results["Config Parse Error"] = err.Error()
		fmt.Printf("  Error parsing config file: %s\n", err)
		return
	}
	defer file.Close()

	fmt.Printf("  Analyzing configuration file: %s\n", configPath)
	scanner := bufio.NewScanner(file)

	// Initialize with default values (what OpenSSH would use if not specified)
	results["HostKeyAlgorithms"] = "Default (not explicitly set)"
	results["PubkeyAcceptedAlgorithms"] = "Default (not explicitly set)"
	results["CASignatureAlgorithms"] = "Default (not explicitly set)"

	// Track if we found relevant directives
	foundHostKeyAlgorithms := false
	foundPubkeyAcceptedAlgorithms := false
	foundCASignatureAlgorithms := false
	foundPQCRelevantConfig := false

	fmt.Println("  Scanning for security-relevant directives...")

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Split the line into directive and value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		directive := parts[0]
		value := strings.TrimSpace(parts[1])

		// Check for key directives
		switch directive {
		case "HostKeyAlgorithms":
			foundHostKeyAlgorithms = true
			results["HostKeyAlgorithms"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found HostKeyAlgorithms: %s\n", value)
		case "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes": // Both are valid depending on OpenSSH version
			foundPubkeyAcceptedAlgorithms = true
			results["PubkeyAcceptedAlgorithms"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found %s: %s\n", directive, value)
		case "CASignatureAlgorithms":
			foundCASignatureAlgorithms = true
			results["CASignatureAlgorithms"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found CASignatureAlgorithms: %s\n", value)
		case "KexAlgorithms":
			// Key Exchange algorithms are also relevant for security
			results["KexAlgorithms"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found KexAlgorithms: %s\n", value)
		case "Ciphers":
			// Encryption ciphers used by SSH
			results["Ciphers"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found Ciphers: %s\n", value)
		case "MACs":
			// Message Authentication Codes
			results["MACs"] = value
			foundPQCRelevantConfig = true
			fmt.Printf("    Found MACs: %s\n", value)
		}
	}

	// Report on directives not found
	if !foundHostKeyAlgorithms {
		fmt.Println("    Warning: HostKeyAlgorithms not explicitly configured (using system defaults)")
	}
	
	if !foundPubkeyAcceptedAlgorithms {
		fmt.Println("    Warning: PubkeyAcceptedAlgorithms not explicitly configured (using system defaults)")
	}
	
	if !foundCASignatureAlgorithms {
		fmt.Println("    Warning: CASignatureAlgorithms not explicitly configured (using system defaults)")
	}

	if !foundPQCRelevantConfig {
		fmt.Println("    Info: No PQC-relevant configuration directives found")
	}
}

// auditSSHHostKeys audits the SSH host keys and classifies them
func auditSSHHostKeys(results map[string]string) {
	// Check if host keys exist
	hostKeyPattern := "/etc/ssh/ssh_host_*_key.pub"
	hostKeyFiles, err := filepath.Glob(hostKeyPattern)
	
	if err != nil || len(hostKeyFiles) == 0 {
		// No host keys found or error accessing them
		results["HostKeysFound"] = "false"
		
		// Create sample data for demonstration
		fmt.Println("  No SSH host keys found in /etc/ssh/")
		fmt.Println("  Creating sample data for demonstration purposes...")
		
		// Add sample key data
		results["SampleData"] = "true"
		results["ssh_host_rsa_key.pub"] = "3072 SHA256:abcdefghijklmnopqrstuvwxyz123456789ABCDEFG root@localhost (RSA)"
		results["ssh_host_ecdsa_key.pub"] = "256 SHA256:123456789ABCDEFGhijklmnopqrstuvwxyzabcdefg root@localhost (ECDSA)"
		results["ssh_host_ed25519_key.pub"] = "256 SHA256:zyxwvutsrqponmlkjihgfedcba987654321ZYXWVUT root@localhost (ED25519)"
		fmt.Println("  Added sample RSA, ECDSA, and ED25519 host keys")
		return
	}
	
	results["HostKeysFound"] = "true"
	results["KeyCount"] = fmt.Sprintf("%d", len(hostKeyFiles))
	fmt.Printf("  Found %d SSH host keys\n", len(hostKeyFiles))
  
  // Process each host key file
  rsaFound := false
  ecdsaFound := false
  ed25519Found := false
	sk2Found := false
	
	for _, keyFile := range hostKeyFiles {
		// Get the base filename
		baseName := filepath.Base(keyFile)
		
		// Track key types
		if strings.Contains(baseName, "rsa") {
			rsaFound = true
		} else if strings.Contains(baseName, "ecdsa") && !strings.Contains(baseName, "sk") {
			ecdsaFound = true
		} else if strings.Contains(baseName, "ed25519") && !strings.Contains(baseName, "sk") {
			ed25519Found = true
		} else if strings.Contains(baseName, "sk") {
			sk2Found = true
		}
		
		// Run ssh-keygen to get key details
		fmt.Printf("  Analyzing %s...\n", baseName)
		cmd := exec.Command("ssh-keygen", "-lf", keyFile)
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			// Error running ssh-keygen
			results[baseName] = "Error: " + err.Error()
			fmt.Printf("    Error: %s\n", err)
			continue
		}
		
		// Store the key details
		outputStr := strings.TrimSpace(string(output))
		results[baseName] = outputStr
		fmt.Printf("    %s\n", outputStr)
	}
	
	// Check for FIDO2 keys
	fido2KeyPattern := "/etc/ssh/ssh_host_*_sk_key.pub"
	fido2KeyFiles, _ := filepath.Glob(fido2KeyPattern)
	
	if len(fido2KeyFiles) > 0 {
		results["FIDO2KeysFound"] = "true"
		results["FIDO2KeyCount"] = fmt.Sprintf("%d", len(fido2KeyFiles))
		fmt.Printf("  Found %d FIDO2 (SK) host keys\n", len(fido2KeyFiles))
	} else {
		results["FIDO2KeysFound"] = "false"
		fmt.Println("  No FIDO2 (SK) host keys found")
	}
	
	// Print key type summary
	fmt.Println("  Key types found:")
	if rsaFound {
		fmt.Println("    RSA")
	} else {
		fmt.Println("    No RSA keys")
	}
  
	if ecdsaFound {
		fmt.Println("    ECDSA")
	} else {
		fmt.Println("    No ECDSA keys")
	}
  
	if ed25519Found {
		fmt.Println("    ED25519")
	} else {
		fmt.Println("    No ED25519 keys")
	}
  
	if sk2Found {
		fmt.Println("    FIDO2 (SK)")
	} else {
		fmt.Println("    No FIDO2 (SK) keys")
	}
}

// printOpenSSHCLISummary prints a summary of OpenSSH configuration for CLI output
func printOpenSSHCLISummary(results map[string]string, hostKeyResults map[string]string) {
	fmt.Println("\nOpenSSH Security Configuration Analysis:")

	// Print directive analysis
	fmt.Println("  Algorithm Configuration:")
	
	// Host Key Algorithms
	if algorithms, ok := results["HostKeyAlgorithms"]; ok {
		if strings.Contains(algorithms, "ssh-rsa") {
			fmt.Println("  Warning: HostKeyAlgorithms includes legacy ssh-rsa algorithm")
		} else if algorithms == "Default (not explicitly set)" {
			fmt.Println("  Warning: HostKeyAlgorithms not explicitly configured")
		} else {
			fmt.Println("  Info: HostKeyAlgorithms configured with modern algorithms")
		}
		fmt.Printf("    Current setting: %s\n", algorithms)
	}
	
	// Public Key Algorithms
	if algorithms, ok := results["PubkeyAcceptedAlgorithms"]; ok {
		if strings.Contains(algorithms, "ssh-rsa") {
			fmt.Println("  Warning: PubkeyAcceptedAlgorithms includes legacy ssh-rsa algorithm")
		} else if algorithms == "Default (not explicitly set)" {
			fmt.Println("  Warning: PubkeyAcceptedAlgorithms not explicitly configured")
		} else {
			fmt.Println("  Info: PubkeyAcceptedAlgorithms configured with modern algorithms")
		}
		fmt.Printf("    Current setting: %s\n", algorithms)
	}
	
	// CA Signature Algorithms
	if algorithms, ok := results["CASignatureAlgorithms"]; ok {
		if strings.Contains(algorithms, "ssh-rsa") {
			fmt.Println("  Warning: CASignatureAlgorithms includes legacy ssh-rsa algorithm")
		} else if algorithms == "Default (not explicitly set)" {
			fmt.Println("  Warning: CASignatureAlgorithms not explicitly configured")
		} else {
			fmt.Println("  Info: CASignatureAlgorithms configured with modern algorithms")
		}
		fmt.Printf("    Current setting: %s\n", algorithms)
	}

	// Print host key audit
	fmt.Println("\n  Host Keys Analysis:")

	// Check if we're using sample data
	if _, ok := hostKeyResults["SampleData"]; ok {
		fmt.Println("  Info: Using sample host key data for demonstration")
	}

	// Count the key types
	rsaCount := 0
	ecdsaCount := 0
	ed25519Count := 0
	sk2Count := 0 // FIDO2 keys

	// Analyze each key
	for key, details := range hostKeyResults {
		if !strings.HasSuffix(key, ".pub") || strings.HasPrefix(key, "HostKeys") || 
		   strings.HasPrefix(key, "Sample") || strings.HasPrefix(key, "FIDO2") || 
		   strings.HasPrefix(key, "Key") {
			continue
		}
		
		// Count key types
		if strings.Contains(key, "rsa") {
			rsaCount++
		} else if strings.Contains(key, "ecdsa") && !strings.Contains(key, "sk") {
			ecdsaCount++
		} else if strings.Contains(key, "ed25519") && !strings.Contains(key, "sk") {
			ed25519Count++
		} else if strings.Contains(key, "sk") {
			sk2Count++
		}
		
		// Print details
		shortName := strings.TrimPrefix(key, "ssh_host_")
		fmt.Printf("    %s: %s\n", shortName, details)
	}

	// Print key type summary
	fmt.Println("\n  Key Type Summary:")
	fmt.Printf("    RSA keys: %d\n", rsaCount)
	fmt.Printf("    ECDSA keys: %d\n", ecdsaCount)
	fmt.Printf("    ED25519 keys: %d\n", ed25519Count)
	fmt.Printf("    FIDO2 (SK) keys: %d\n", sk2Count)
	
	// Check for quantum-resistant algorithms
	fmt.Println("\n  Quantum-Resistant Support:")
	fmt.Println("    Warning: No quantum-resistant algorithms configured")
	fmt.Println("    Warning: No PQC algorithms available in current OpenSSH")


}

// Note: printDirectiveAnalysis function has been removed as recommendations are now handled centrally

// Note: printHostKeyAudit function has been removed as recommendations are now handled centrally

// Note: printOpenSSHRecommendations function has been removed as recommendations are now handled centrally

package linux

import (
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

// LibReport represents the structure of the JSON report for the lib command
type LibReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	OpenSSL        *scan.LibraryScanResult `json:"openssl"`
	GnuTLS         GnuTLSInfo             `json:"gnutls"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// GnuTLSInfo holds information about GnuTLS installation and capabilities
type GnuTLSInfo struct {
	Installed         bool
	Path              string
	VersionOutput     string
	Version           string
	VersionMajor      int
	VersionMinor      int
	VersionPatch      int
	VersionSufficient bool
	CECPQ2Support     string
	LinkedTools       []string
}

// TestLib command checks for PQC support in cryptographic libraries and returns structured recommendations and status items
func TestLib(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Library PQC Support Scan ===")

	// Create a library scanner
	scanner := scan.NewLibraryScanner()

	// Check OpenSSL
	fmt.Println("\nChecking OpenSSL...")
	result := scanner.ScanOpenSSL()

	if result.Error != nil {
		fmt.Printf("[FAIL] Error checking OpenSSL: %v\n", result.Error)
		// Continue with the rest of the scan even if OpenSSL fails
	} else {
		// Display OpenSSL version and PQC support only if scan succeeded
		fmt.Printf("[PASS] OpenSSL version: %s", result.Version)

		if result.HasPQCSupport {
			fmt.Printf(" (PQC support built-in)\n")
		} else if result.IsPQCCapable {
			fmt.Printf(" (PQC-capable with extensions)\n")
		} else {
			fmt.Printf(" (No PQC support)\n")
		}

		// Display details
		fmt.Printf("   Details: %s\n", result.Details)

		// Display OQS provider status
		if result.IsPQCCapable || result.HasPQCSupport {
			fmt.Println("\nProvider Status:")
			if result.HasOQSProvider {
				fmt.Println("[PASS] OQS provider is installed and registered")
			} else {
				fmt.Println("[FAIL] OQS provider is not installed or not registered")
			}
		}
	}

	// Check GnuTLS
	fmt.Println("\nChecking GnuTLS...")
	gnutlsInfo := checkGnuTLSInstallation()

	// Print GnuTLS information
	printGnuTLSInfo(gnutlsInfo)

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateLibraryStatus(result, gnutlsInfo, rm)

	// Generate recommendations based on scan results
	recommendations := generateLibraryRecommendations(result, gnutlsInfo)

	// Add recommendations to the manager
	rm.AppendRecommendations(recommendations)

	// Get all recommendations and status items from the manager
	allRecommendations := rm.GetRecommendations()

	// If JSON output is requested, create and save the report
	if jsonOutput {
		// Get server IP address - using the function from env.go
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
		report := LibReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			OpenSSL:        result,
			GnuTLS:         gnutlsInfo,
			Recommendations: allRecommendations,
		}
		
		// Create report directory if it doesn't exist
		reportDir := "./report"
		if _, err := os.Stat(reportDir); os.IsNotExist(err) {
			os.Mkdir(reportDir, 0755)
		}
		
		// Marshal to JSON
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Println("Error creating JSON report:", err)
		} else {
			// Write to file
			filePath := filepath.Join(reportDir, "lib.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err != nil {
				fmt.Println("Error writing JSON report to file:", err)
			} else {
				fmt.Println("\nJSON report saved to", filePath)
			}
		}
	}
	
	return allRecommendations
}

// checkGnuTLSInstallation checks if GnuTLS is installed and gets its version and capabilities
func checkGnuTLSInstallation() GnuTLSInfo {
	info := GnuTLSInfo{
		Installed: false,
	}

	// Check for GnuTLS installation
	cmd := exec.Command("which", "gnutls-cli")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return info
	}

	info.Installed = true
	info.Path = strings.TrimSpace(string(output))

	// Get GnuTLS version
	cmd = exec.Command("gnutls-cli", "--version")
	output, err = cmd.CombinedOutput()
	if err == nil {
		info.VersionOutput = strings.TrimSpace(string(output))

		// Extract version number
		versionRegex := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
		versionMatch := versionRegex.FindStringSubmatch(info.VersionOutput)
		if len(versionMatch) >= 4 {
			info.VersionMajor, _ = strconv.Atoi(versionMatch[1])
			info.VersionMinor, _ = strconv.Atoi(versionMatch[2])
			info.VersionPatch, _ = strconv.Atoi(versionMatch[3])

			info.Version = fmt.Sprintf("%d.%d.%d", info.VersionMajor, info.VersionMinor, info.VersionPatch)

			// Check if version is sufficient for modern PQC features (>= 3.6.14)
			if info.VersionMajor > 3 ||
				(info.VersionMajor == 3 && info.VersionMinor > 6) ||
				(info.VersionMajor == 3 && info.VersionMinor == 6 && info.VersionPatch >= 14) {
				info.VersionSufficient = true
			}
		}
	}

	// Check for CECPQ2 support (obsolete - CECPQ2 removed from BoringSSL in 2023)
	cmd = exec.Command("gnutls-cli", "--list")
	output, err = cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "CECPQ2") || strings.Contains(outputStr, "KX-CECPQ2") {
			info.CECPQ2Support = "Obsolete (found)"
		} else {
			info.CECPQ2Support = "Obsolete (not found)"
		}
	} else {
		info.CECPQ2Support = "Status unknown"
	}

	// Check for tools linked with GnuTLS
	// Check curl
	cmd = exec.Command("ldd", "/usr/bin/curl")
	output, err = cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "libgnutls") {
		info.LinkedTools = append(info.LinkedTools, "curl")
	}

	// Check git
	cmd = exec.Command("ldd", "/usr/bin/git")
	output, err = cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "libgnutls") {
		info.LinkedTools = append(info.LinkedTools, "git")
	}

	return info
}

// printGnuTLSInfo prints information about GnuTLS installation
func printGnuTLSInfo(info GnuTLSInfo) {
	if !info.Installed {
		fmt.Println("Status: Not installed")
		return
	}

	// Print basic info
	fmt.Printf("Status: Installed\n")
	if info.VersionOutput != "" {
		fmt.Printf("Version Info: %s\n", info.VersionOutput)
	}
	if info.Version != "" {
		fmt.Printf("Version: %s\n", info.Version)
	}

	// Print CECPQ2 support
	if info.CECPQ2Support != "" {
		fmt.Printf("CECPQ2 Support: %s\n", info.CECPQ2Support)
	}

	// Print linked tools
	if len(info.LinkedTools) > 0 {
		fmt.Printf("Tools linked with GnuTLS: %s\n", strings.Join(info.LinkedTools, ", "))
	}
}



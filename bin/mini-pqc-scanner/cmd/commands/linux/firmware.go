package linux

import (
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

// FirmwareReport represents the structure of the JSON report for the firmware command
type FirmwareReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	FirmwareInfo   map[string]string      `json:"firmware_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// Firmware command checks firmware security and PQC support
func Firmware(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== Firmware Security and PQC Support Check ===")
	
	// Create a map to store detection results
	results := make(map[string]string)
	
	// First, determine if we're running on bare metal
	environment := determineEnvironment()
	results["Environment"] = environment
	
	// Check UEFI status
	checkUEFI(results)
	
	// Check Secure Boot status
	checkSecureBoot(results)
	
	// Check TPM status
	checkTPM(results)
	
	// Check BMC/IPMI firmware (especially for on-prem/edge servers)
	checkBMCFirmware(results)
	
	// Check for PQC support in firmware
	checkPQCFirmwareSupport(results)
	
	// Validate firmware signing algorithms
	validateSigningAlgorithms(results)
	
	// Print firmware summary to CLI
	printFirmwareSummary(results)
	
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateFirmwareStatus(results, rm)

	// Generate recommendations based on detection results
	recommendations := generateFirmwareRecommendations(results)

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
		report := FirmwareReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			FirmwareInfo:   results,
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
			filePath := filepath.Join(reportDir, "firmware.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/firmware.json")
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

// determineEnvironment reuses logic from cloudenv to determine if we're on bare metal
func determineEnvironment() string {
	// Check for virtualization indicators
	if isVirtualized() {
		return "Virtual Machine (not bare metal)"
	}
	
	// Check for cloud-specific hardware indicators
	if isCloudMetal() {
		return "Bare Metal Cloud Server"
	}
	
	// Check for on-prem or edge server indicators
	if isOnPremOrEdge() {
		return "On-Premises or Edge Server"
	}
	
	return "Dedicated/Physical Server"
}

// isOnPremOrEdge checks for indicators of on-premises or edge server environments
func isOnPremOrEdge() bool {
	// Check for common edge computing platforms
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(string(data))
		
		// Check for common edge/IoT hardware vendors
		if strings.Contains(vendor, "raspberry") || // Raspberry Pi
		   strings.Contains(vendor, "intel nuc") || // Intel NUC
		   strings.Contains(vendor, "nvidia") || // NVIDIA Jetson
		   strings.Contains(vendor, "dell edge") || // Dell Edge
		   strings.Contains(vendor, "lenovo edge") { // Lenovo Edge
			return true
		}
	}
	
	// Check for industrial automation or robotics indicators
	if _, err := os.Stat("/opt/ros"); err == nil { // ROS (Robot Operating System)
		return true
	}
	
	// Check for common edge software platforms
	if _, err := exec.LookPath("k3s"); err == nil { // Lightweight Kubernetes
		return true
	}
	
	if _, err := exec.LookPath("balena"); err == nil { // Balena IoT
		return true
	}
	
	// Check for industrial control systems
	if _, err := os.Stat("/etc/inductive"); err == nil { // Inductive Automation
		return true
	}
	
	return false
}

// isVirtualized checks if we're running in a virtualized environment
func isVirtualized() bool {
	// Check for WSL
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil {
		return true
	}
	
	// Check for hypervisor flag in /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "hypervisor") {
			return true
		}
	}
	
	// Check for /sys/hypervisor directory
	if _, err := os.Stat("/sys/hypervisor"); err == nil {
		return true
	}
	
	// Check for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		cgroups := strings.ToLower(string(data))
		if strings.Contains(cgroups, "docker") || strings.Contains(cgroups, "lxc") {
			return true
		}
	}
	
	return false
}

// isCloudMetal checks for bare metal cloud server indicators
func isCloudMetal() bool {
	// Check for AWS Metal
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(string(data))
		if strings.Contains(vendor, "amazon") {
			// Check for metal instance type
			if product, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name"); err == nil {
				if strings.Contains(strings.ToLower(string(product)), "metal") {
					return true
				}
			}
		}
	}
	
	// Check for Equinix Metal (formerly Packet)
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(string(data))
		if strings.Contains(vendor, "equinix") || strings.Contains(vendor, "packet") {
			return true
		}
	}
	
	// Check for Hetzner Dedicated
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(string(data))
		if strings.Contains(vendor, "hetzner") {
			return true
		}
	}
	
	return false
}

// checkUEFI checks if the system is using UEFI
func checkUEFI(results map[string]string) {
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		results["UEFI"] = "Present"
		
		// Check UEFI version if available
		if data, err := os.ReadFile("/sys/firmware/efi/fw_platform_size"); err == nil {
			if strings.TrimSpace(string(data)) == "64" {
				results["UEFI"] = "Present (64-bit)"
			} else if strings.TrimSpace(string(data)) == "32" {
				results["UEFI"] = "Present (32-bit)"
			}
		}
	} else {
		results["UEFI"] = "Not detected (likely using Legacy BIOS)"
	}
}

// checkSecureBoot checks if Secure Boot is enabled
func checkSecureBoot(results map[string]string) {
	// Check for EFI variables to determine secure boot status
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		// EFI system detected
		if _, err := os.Stat("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
			// Try to read the SecureBoot variable value if possible
			if data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil && len(data) >= 5 {
				// The 5th byte indicates if Secure Boot is enabled (1) or disabled (0)
				if data[4] == 1 {
					results["Secure Boot"] = "Enabled"
				} else {
					results["Secure Boot"] = "Disabled"
				}
			} else {
				results["Secure Boot"] = "Status unknown (variable exists but cannot be read)"
			}
		} else {
			results["Secure Boot"] = "Not configured"
		}
	} else {
		results["Secure Boot"] = "Not available (no UEFI detected)"
	}
	
	// Check if mokutil is available
	if _, err := exec.LookPath("mokutil"); err == nil {
		results["Secure Boot Tools"] = "mokutil available"
	}
}

// checkTPM checks for TPM presence and version
func checkTPM(results map[string]string) {
	// Check for TPM 2.0 device
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		results["TPM"] = "Present (/dev/tpm0 exists)"
		
		// Try to determine TPM version
		if _, err := os.Stat("/sys/class/tpm/tpm0/tpm_version_major"); err == nil {
			if data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major"); err == nil {
				version := strings.TrimSpace(string(data))
				results["TPM"] = "TPM " + version + ".0 detected"
			}
		}
	} else {
		results["TPM"] = "Not detected"
	}
}

// checkBMCFirmware checks BMC/IPMI firmware details
func checkBMCFirmware(results map[string]string) {
	// Check for BMC/IPMI device presence
	bmcPresent := false
	
	// Check for BMC/IPMI device files
	if _, err := os.Stat("/dev/ipmi0"); err == nil {
		bmcPresent = true
		results["BMC Present"] = "Yes (/dev/ipmi0)"
		results["BMC Type"] = "IPMI"
	} else if _, err := os.Stat("/dev/bmc"); err == nil {
		bmcPresent = true
		results["BMC Present"] = "Yes (/dev/bmc)"
		results["BMC Type"] = "BMC"
	} else {
		results["BMC Present"] = "No"
	}
	
	// If BMC is present, try to get more information without using sudo
	if bmcPresent {
		// Check if ipmitool is available
		if _, err := exec.LookPath("ipmitool"); err == nil {
			results["BMC Tools"] = "ipmitool available"
			
			// We won't run ipmitool directly as it requires sudo
			// Instead, provide guidance on how to check
			results["BMC Firmware Check"] = "Run 'sudo ipmitool mc info' to check firmware version"
			results["BMC Security Check"] = "Run 'sudo ipmitool lan print' to check network security settings"
		}
		
		// Check for common BMC web interfaces
		if _, err := exec.LookPath("curl"); err == nil {
			results["BMC Web Interface"] = "Check for web interface on port 443, 80, 8443, or 8080"
		}
		
		// For on-prem/edge servers, BMC security is critical
		if results["Environment"] == "On-Premises or Edge Server" {
			results["BMC Security"] = "⚠️ Critical: Verify BMC firmware is up-to-date with latest security patches"
		}
	}
}

// validateSigningAlgorithms performs mandatory validation of firmware signing algorithms
func validateSigningAlgorithms(results map[string]string) {
	// This is especially important for on-prem/edge servers
	isOnPremOrEdge := results["Environment"] == "On-Premises or Edge Server"
	
	// Check if we already have PQC firmware support info
	pqcSupport, hasPQCInfo := results["PQC Firmware Support"]
	
	// If we're on an on-prem/edge server, validation is mandatory
	if isOnPremOrEdge {
		if hasPQCInfo && strings.Contains(pqcSupport, "Not detected") {
			// No PQC support detected, this is critical for on-prem/edge
			results["Signing Algorithm Validation"] = "❗ CRITICAL: No quantum-safe signing algorithms detected"
			results["Security Risk"] = "High - On-premises/edge servers require quantum-safe boot chains"
			results["Recommended Action"] = "Immediate firmware upgrade to support LMS (SHA-256/192) or hybrid signatures"
		} else if hasPQCInfo && (strings.Contains(pqcSupport, "LMS") || strings.Contains(pqcSupport, "XMSS")) {
			// Has PQC support, check if it's the recommended type
			if strings.Contains(pqcSupport, "LMS") {
				results["Signing Algorithm Validation"] = "✅ LMS signatures detected (recommended)"
				results["Security Status"] = "Good - Using recommended quantum-safe signatures"
			} else {
				results["Signing Algorithm Validation"] = "✅ XMSS signatures detected"
				results["Security Status"] = "Good - Using quantum-safe signatures"
				results["Recommendation"] = "Consider LMS (SHA-256/192) for broader compatibility"
			}
		} else if hasPQCInfo && strings.Contains(pqcSupport, "Hybrid") {
			// Has hybrid signatures
			results["Signing Algorithm Validation"] = "✅ Hybrid signatures detected (recommended)"
			results["Security Status"] = "Good - Using recommended quantum-safe hybrid signatures"
		} else {
			// No information available
			results["Signing Algorithm Validation"] = "⚠️ Unable to validate signing algorithms"
			results["Recommendation"] = "Manually verify firmware supports LMS (SHA-256/192) or hybrid signatures"
		}
	} else {
		// For non-edge servers, still important but less critical
		if hasPQCInfo && strings.Contains(pqcSupport, "Not detected") {
			results["Signing Algorithm Validation"] = "⚠️ No quantum-safe signing algorithms detected"
			results["Recommendation"] = "Consider firmware with LMS (SHA-256/192) or hybrid signatures"
		} else if hasPQCInfo {
			results["Signing Algorithm Validation"] = "✅ Quantum-safe signing algorithms detected"
		}
	}
}

// checkPQCFirmwareSupport checks for PQC support in firmware
func checkPQCFirmwareSupport(results map[string]string) {
	// Check for UEFI Secure Boot signature algorithms
	hasLMS := false
	hasXMSS := false
	hasHybrid := false
	hasRSAOnly := true
	
	// Check if efitools is available
	if _, err := exec.LookPath("efi-readvar"); err == nil {
		// Try to read signature database
		cmd := exec.Command("efi-readvar", "-v", "db")
		output, err := cmd.CombinedOutput()
		if err == nil {
			outputStr := strings.ToLower(string(output))
			
			// Check for LMS signatures
			if strings.Contains(outputStr, "lms") || strings.Contains(outputStr, "hash-based") {
				hasLMS = true
				hasRSAOnly = false
			}
			
			// Check for XMSS signatures
			if strings.Contains(outputStr, "xmss") {
				hasXMSS = true
				hasRSAOnly = false
			}
			
			// Check for hybrid signatures
			if strings.Contains(outputStr, "hybrid") || 
			   strings.Contains(outputStr, "rsa+lms") || 
			   strings.Contains(outputStr, "ecdsa+lms") {
				hasHybrid = true
				hasRSAOnly = false
			}
		}
	}
	
	// Set results based on findings
	if hasLMS {
		results["PQC Firmware Support"] = "LMS signatures detected"
	}
	
	if hasXMSS {
		results["PQC Firmware Support"] = "XMSS signatures detected"
	}
	
	if hasHybrid {
		results["PQC Firmware Support"] = "Hybrid PQC signatures detected"
	}
	
	if hasRSAOnly {
		results["PQC Firmware Support"] = "Not detected (RSA-only boot chain)"
		results["Boot Chain Security"] = "⚠️ RSA-only boot chain is vulnerable to quantum attacks"
	} else {
		results["Boot Chain Security"] = "✅ PQC-protected boot chain"
	}
}

// printFirmwareSummary prints a summary of the firmware security analysis to CLI
func printFirmwareSummary(results map[string]string) {
	fmt.Println("\nFirmware Security Summary:")
	fmt.Println("-------------------------")
	
	// Print environment first
	if env, ok := results["Environment"]; ok {
		fmt.Printf("Environment: %s\n", env)
	}
	
	// Print UEFI status
	if uefi, ok := results["UEFI"]; ok {
		fmt.Printf("UEFI: %s\n", uefi)
	}
	
	// Print Secure Boot status
	if sb, ok := results["Secure Boot"]; ok {
		fmt.Printf("Secure Boot: %s\n", sb)
	}
	
	// Print TPM status
	if tpm, ok := results["TPM"]; ok {
		fmt.Printf("TPM: %s\n", tpm)
	}
	
	// Print BMC status if available
	if bmc, ok := results["BMC Present"]; ok {
		fmt.Printf("BMC: %s\n", bmc)
		if bmcType, ok := results["BMC Type"]; ok {
			fmt.Printf("BMC Type: %s\n", bmcType)
		}
	}
	
	// Print PQC support
	if pqc, ok := results["PQC Firmware Support"]; ok {
		fmt.Printf("PQC Support: %s\n", pqc)
	}
	
	// Print security status if available
	if status, ok := results["Security Status"]; ok {
		fmt.Printf("Security Status: %s\n", status)
	}
	

}

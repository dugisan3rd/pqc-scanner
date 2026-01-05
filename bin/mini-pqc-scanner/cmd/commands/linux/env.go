package linux

import (
	"context"
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

// EnvReport represents the structure of the JSON report
type EnvReport struct {
	ServerIP      string                 `json:"server_ip"`
	ReportTime    string                 `json:"report_time"`
	Environment   map[string]string      `json:"environment"`
	Recommendations []scan.Recommendation `json:"recommendations"`
}

// Env command identifies the environment and installed components and returns recommendations and status items
func Env(jsonOutput bool) []scan.Recommendation {

	// Create a map to store detection results
	results := make(map[string]string)

	// Create a context with timeout for the entire operation
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create a channel to collect results
	done := make(chan bool)

	// Run all checks in a goroutine to respect the timeout
	go func() {
		// Check local environment components
		checkLocalEnvironment(results)

		// Check for basic virtualization
		checkBasicVirtualization(results)

		// Check for cloud environment
		checkCloudEnvironment(results)

		done <- true
	}()

	// Wait for either completion or timeout
	select {
	case <-done:
		// All checks completed successfully
	case <-ctx.Done():
		// Timeout occurred
		results["Status"] = "Warning: Some checks timed out after 3 seconds"
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Add status items based on the results
	generateEnvStatus(results, rm)

	// Print environment summary to CLI using the structured status items
	printEnvSummary(results)

	// Generate recommendations based on the results
	recommendations := generateEnvRecommendations(results)
	
	// Add recommendations to the manager
	rm.AppendRecommendations(recommendations)

	// Get all recommendations and status items from the manager
	allRecommendations := rm.GetRecommendations()

	// If JSON output is requested, create and save the report
	if jsonOutput {
		// Get server IP address
		serverIP := getServerIP()
		
		// Create report structure
		report := EnvReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			Environment:    results,
			Recommendations: recommendations,
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
			filePath := filepath.Join(reportDir, "env.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err != nil {
				fmt.Println("Error writing JSON report to file:", err)
			} else {
				fmt.Println("\nJSON report saved to", filePath)
			}
		}
	}

	// Return all recommendations and status items
	return allRecommendations
}

// checkLocalEnvironment checks for installed components like Nginx, Apache, OpenSSL, WireGuard, and OpenVPN
func checkLocalEnvironment(results map[string]string) {
	// Check for Nginx installation
	checkNginxInstallation(results)

	// Check for Apache installation
	checkApacheInstallation(results)

	// Check for OpenSSL installation
	checkOpenSSLInstallation(results)

	// Check for WireGuard installation
	checkWireGuardInstallation(results)

	// Check for OpenVPN installation
	checkOpenVPNInstallation(results)

	// Check for IPsec installation
	CheckIPsecInstallation(results)

	// Check for tcpdump installation
	checkTcpdumpInstallation(results)
	
	// Check for tshark installation
	checkTsharkInstallation(results)

	// Check Linux distribution information
	checkLinuxDistribution(results)
}

// checkNginxInstallation has been moved to testnginx.go
// checkOpenSSLInstallation has been moved to openssl.go

// checkApacheInstallation has been moved to testapache.go

// printCloudEnvironmentSummary prints a summary of the cloud environment detection results
// Note: printCloudEnvironmentSummary function has been removed as recommendations are now handled centrally

// printEnvSummary prints a summary of the environment detection results to CLI
func printEnvSummary(results map[string]string) {
	fmt.Println("\nEnvironment Summary:")
	fmt.Println("------------------")

	// Print a simplified cloud environment summary
	hasCloudIndicators := false
	cloudKeys := []string{"DMI", "Hypervisor", "MAC OUI", "Cloud-Init", "EC2 Metadata", "EC2 Instance ID"}
	for _, key := range cloudKeys {
		if _, exists := results[key]; exists {
			hasCloudIndicators = true
			break
		}
	}

	if hasCloudIndicators {
		fmt.Println("Cloud Environment: Detected")
	} else {
		fmt.Println("Cloud Environment: Not detected")
	}

	// Print a simplified local environment summary
	fmt.Println("\nDetected Components:")

	// OpenSSL
	if openssl, ok := results["OpenSSL"]; ok {
		fmt.Printf("- OpenSSL: %s\n", openssl)
		if oqsProvider, ok := results["OQS Provider"]; ok {
			fmt.Printf("  OQS Provider: %s\n", oqsProvider)
		}
	}

	// Web servers
	if nginx, ok := results["Nginx"]; ok && nginx != "Not installed" {
		fmt.Printf("- Nginx: %s\n", nginx)
	}

	if apache, ok := results["Apache"]; ok && apache != "Not installed" {
		fmt.Printf("- Apache: %s\n", apache)
	}

	// VPN solutions
	if wireguard, ok := results["WireGuard"]; ok && wireguard != "Not installed" {
		fmt.Printf("- WireGuard: %s\n", wireguard)
	}

	if openvpn, ok := results["OpenVPN"]; ok && openvpn != "Not installed" {
		fmt.Printf("- OpenVPN: %s\n", openvpn)
	}

	if ipsec, ok := results["IPsec"]; ok && ipsec != "Not installed" {
		fmt.Printf("- IPsec: %s\n", ipsec)
	}

	if tcpdump, ok := results["tcpdump"]; ok {
		if tcpdump != "Not installed" {
			fmt.Printf("- tcpdump: %s\n", tcpdump)
			if tcpdumpVersion, ok := results["tcpdump Version"]; ok {
				fmt.Printf("  Version: %s\n", tcpdumpVersion)
			}
		} else {
			fmt.Printf("- tcpdump: Not installed\n")
		}
	}
	
	if tshark, ok := results["tshark"]; ok {
		if tshark != "Not installed" {
			fmt.Printf("- tshark: %s\n", tshark)
			if tsharkVersion, ok := results["tshark Version"]; ok {
				fmt.Printf("  Version: %s\n", tsharkVersion)
			}
		} else {
			fmt.Printf("- tshark: Not installed\n")
		}
	}

	// TPM
	if tpmVersion, ok := results["TPM Version"]; ok && tpmVersion != "Not detected" {
		fmt.Printf("- TPM Version: %s\n", tpmVersion)
	}


}

// checkWireGuardInstallation has been moved to testwireguard.go

// checkOpenVPNInstallation has been moved to openvpn.go

// checkBasicVirtualization checks for basic virtualization indicators
func checkBasicVirtualization(results map[string]string) {
	// Check for common virtualization indicators
	virtType := "Physical (likely)"

	// Check /proc/cpuinfo for virtualization flags
	cmd := exec.Command("grep", "-E", "svm|vmx", "/proc/cpuinfo")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		results["CPU Virtualization"] = "Supported"
	} else {
		results["CPU Virtualization"] = "Not detected"
	}

	// Check for hypervisor using systemd-detect-virt if available
	cmd = exec.Command("which", "systemd-detect-virt")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		cmd = exec.Command("systemd-detect-virt")
		output, err = cmd.CombinedOutput()
		if err == nil {
			virtType = strings.TrimSpace(string(output))
			if virtType != "none" {
				results["Virtualization"] = virtType
				return
			}
		}
	}

	// Check for Docker container
	cmd = exec.Command("grep", "docker", "/proc/1/cgroup")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		results["Virtualization"] = "Docker container"
		return
	}

	// Check for other container technologies
	cmd = exec.Command("grep", "-E", "lxc|kubepods", "/proc/1/cgroup")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		if strings.Contains(string(output), "lxc") {
			results["Virtualization"] = "LXC container"
		} else if strings.Contains(string(output), "kubepods") {
			results["Virtualization"] = "Kubernetes pod"
		} else {
			results["Virtualization"] = "Container (unknown type)"
		}
		return
	}

	// Default if no virtualization detected
	results["Virtualization"] = virtType
}

// getServerIP retrieves the server's IP address
func getServerIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}

	return "unknown"
}

// checkCloudEnvironment checks for cloud environment indicators
func checkCloudEnvironment(results map[string]string) {
	// Check DMI data (fast, filesystem operations)
	checkDMIData(results)

	// Check for hypervisor (fast, filesystem operations)
	checkHypervisor(results)

	// Check MAC address OUI (fast, no network)
	checkMACAddressOUIData(results)

	// Check for cloud-init (fast, filesystem operations)
	checkCloudInit(results)

	// Check for EC2 metadata (already has internal timeout)
	checkEC2Metadata(results)

	// Check hardware vendor (fast, filesystem operations)
	checkHardwareVendor(results)

	// Check for BMC/IPMI (fast, filesystem operations)
	checkBMC(results)

	// Check TPM and Secure Boot (fast, filesystem operations)
	checkTPMAndSecureBoot(results)

	// Check AWS load balancers if in AWS environment
	checkAWSLoadBalancers(results)

	// Note: We don't call checkVirtualization here as it's similar to checkBasicVirtualization
	// which is already called in the main Env function
}

// checkDMIData checks DMI data for cloud provider indicators
func checkDMIData(results map[string]string) {
	// Try to read DMI data from sysfs instead of using dmidecode (no sudo required)
	// Check system manufacturer
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/sys_vendor"); err == nil {
		manufacturer := strings.TrimSpace(string(data))
		if strings.Contains(strings.ToLower(manufacturer), "amazon") {
			results["DMI"] = "AWS"
		} else if strings.Contains(strings.ToLower(manufacturer), "google") {
			results["DMI"] = "Google Cloud"
		} else if strings.Contains(strings.ToLower(manufacturer), "microsoft") {
			results["DMI"] = "Azure"
		} else {
			results["DMI"] = manufacturer
		}
	} else {
		// Try to check for cloud-specific files
		if _, err := os.Stat("/sys/hypervisor/uuid"); err == nil {
			results["DMI"] = "Virtualized environment (hypervisor detected)"
		} else {
			results["DMI"] = "Unknown (cannot access DMI data)"
		}
	}

	// Check system product name
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name"); err == nil {
		productName := strings.TrimSpace(string(data))
		if productName != "" {
			results["System Product"] = productName
		}
	}
}

// checkHypervisor checks for hypervisor presence
func checkHypervisor(results map[string]string) {
	// Check for /sys/hypervisor/uuid
	if _, err := os.Stat("/sys/hypervisor/uuid"); err == nil {
		results["Hypervisor"] = "Present (/sys/hypervisor/uuid exists)"
	}

	// Check for Xen in /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "xen") {
			results["Hypervisor"] = "Xen (found in /proc/cpuinfo)"
		}
	}

	// Check dmesg for hypervisor info
	cmd := exec.Command("dmesg")
	output, err := cmd.CombinedOutput()
	if err == nil {
		dmesgOutput := strings.ToLower(string(output))
		if strings.Contains(dmesgOutput, "xen") {
			results["Hypervisor"] = "Xen (found in dmesg)"
		} else if strings.Contains(dmesgOutput, "kvm") {
			results["Hypervisor"] = "KVM (found in dmesg)"
		} else if strings.Contains(dmesgOutput, "vmware") {
			results["Hypervisor"] = "VMware (found in dmesg)"
		} else if strings.Contains(dmesgOutput, "hyperv") {
			results["Hypervisor"] = "Hyper-V (found in dmesg)"
		}
	}
}

// checkMACAddressOUIData checks MAC address OUI for cloud provider indicators
func checkMACAddressOUIData(results map[string]string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		results["MAC OUI"] = "Unknown (failed to get interfaces)"
		return
	}

	for _, iface := range interfaces {
		if len(iface.HardwareAddr) >= 3 {
			mac := iface.HardwareAddr.String()
			oui := strings.ToUpper(strings.Replace(mac[0:8], ":", "", -1))

			// Check for known cloud provider OUIs
			if strings.HasPrefix(oui, "0A") || strings.HasPrefix(oui, "0C") {
				results["MAC OUI"] = "Possible AWS (OUI: " + oui + ")"
				break
			} else if strings.HasPrefix(oui, "42") {
				results["MAC OUI"] = "Possible Google Cloud (OUI: " + oui + ")"
				break
			} else if strings.HasPrefix(oui, "00155D") {
				results["MAC OUI"] = "Possible Azure (OUI: " + oui + ")"
				break
			}
		}
	}

	if _, exists := results["MAC OUI"]; !exists {
		results["MAC OUI"] = "No cloud provider MAC OUI detected"
	}
}

// checkCloudInit checks for cloud-init indicators
func checkCloudInit(results map[string]string) {
	if _, err := os.Stat("/var/lib/cloud/instances"); err == nil {
		results["Cloud-Init"] = "Present (/var/lib/cloud/instances exists)"
	} else {
		results["Cloud-Init"] = "Not detected"
	}
}

// checkEC2Metadata checks for EC2 environment indicators without network calls
func checkEC2Metadata(results map[string]string) {
	// Check if ec2metadata tool is available
	_, err := exec.LookPath("ec2metadata")
	if err == nil {
		results["EC2 Metadata"] = "Tool available"
	}

	// Check for EC2-specific files and directories (no network calls)
	ec2Indicators := []string{
		"/sys/devices/virtual/dmi/id/bios_vendor",
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/devices/virtual/dmi/id/sys_vendor",
	}

	for _, path := range ec2Indicators {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.TrimSpace(strings.ToLower(string(data)))
			if strings.Contains(content, "amazon") || strings.Contains(content, "ec2") {
				results["EC2 Environment"] = "Detected via DMI data"
				break
			}
		}
	}

	// Check for EC2-specific kernel modules or drivers
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		modules := strings.ToLower(string(data))
		if strings.Contains(modules, "xen_netfront") || strings.Contains(modules, "xen_blkfront") {
			results["EC2 Environment"] = "Detected via Xen modules"
		}
	}

	// If no EC2 indicators found, mark as not detected
	if results["EC2 Environment"] == "" && results["EC2 Metadata"] == "" {
		results["EC2 Environment"] = "Not detected"
	}
}

// checkHardwareVendor checks for physical hardware indicators
func checkHardwareVendor(results map[string]string) {
	// Try reading CPU info directly from /proc/cpuinfo instead of using lshw
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuinfo := strings.ToLower(string(data))

		// Check for CPU vendor
		if strings.Contains(cpuinfo, "vendor_id") && strings.Contains(cpuinfo, "intel") {
			results["CPU Vendor"] = "Intel"
		} else if strings.Contains(cpuinfo, "vendor_id") && strings.Contains(cpuinfo, "amd") {
			results["CPU Vendor"] = "AMD"
		}

		// Try to infer hardware vendor from model name or other indicators
		if strings.Contains(cpuinfo, "model name") {
			results["CPU Model"] = extractValue(cpuinfo, "model name")
		}
	}

	// Try to read hardware vendor from DMI data
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/board_vendor"); err == nil {
		vendor := strings.TrimSpace(string(data))
		if vendor != "" {
			results["Hardware Vendor"] = vendor
		}
	}

	// Try to read hardware model from DMI data
	if data, err := os.ReadFile("/sys/devices/virtual/dmi/id/board_name"); err == nil {
		model := strings.TrimSpace(string(data))
		if model != "" {
			results["Hardware Model"] = model
		}
	}
}

// extractValue extracts a value from a key in a string like "key : value"
func extractValue(data, key string) string {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.Contains(line, key) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// checkBMC checks for BMC/IPMI device
func checkBMC(results map[string]string) {
	// Check for BMC/IPMI device files (no sudo required)
	if _, err := os.Stat("/dev/ipmi0"); err == nil {
		results["BMC/IPMI"] = "Present (/dev/ipmi0 exists)"
	} else if _, err := os.Stat("/dev/bmc"); err == nil {
		results["BMC/IPMI"] = "Present (/dev/bmc exists)"
	} else {
		// Check if ipmitool is available without running it
		_, err := exec.LookPath("ipmitool")
		if err == nil {
			results["BMC/IPMI"] = "ipmitool available (not checked)"
		} else {
			results["BMC/IPMI"] = "Not detected"
		}
	}
}

// checkTPMAndSecureBoot checks for TPM and Secure Boot
func checkTPMAndSecureBoot(results map[string]string) {
	// Check for TPM device file (no sudo required)
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		results["TPM"] = "Present (/dev/tpm0 exists)"
	} else {
		// Check if tpm2_getcap is available without running it
		_, err := exec.LookPath("tpm2_getcap")
		if err == nil {
			results["TPM"] = "TPM tools available (not checked)"
		} else {
			results["TPM"] = "Not detected"
		}
	}

	// Check for EFI variables to determine secure boot status without using mokutil
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		// EFI system detected
		if _, err := os.Stat("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
			// SecureBoot variable exists, but we can't read its value without root
			results["Secure Boot"] = "EFI SecureBoot variable exists (status unknown)"
		} else {
			results["Secure Boot"] = "EFI system, SecureBoot status unknown"
		}
	} else {
		// Not an EFI system
		results["Secure Boot"] = "Not an EFI system (no Secure Boot)"
	}

	// Check if mokutil is available without running it
	_, err := exec.LookPath("mokutil")
	if err == nil {
		results["Secure Boot Tools"] = "mokutil available (not checked)"
	}
}

// checkTcpdumpInstallation checks if tcpdump is installed
func checkTcpdumpInstallation(results map[string]string) {
	cmd := exec.Command("which", "tcpdump")
	output, err := cmd.Output()

	if err == nil && len(output) > 0 {
		results["tcpdump"] = "Installed: " + strings.TrimSpace(string(output))

		// Get version information
		versionCmd := exec.Command("tcpdump", "--version")
		versionOutput, versionErr := versionCmd.CombinedOutput()
		if versionErr == nil {
			versionLines := strings.Split(string(versionOutput), "\n")
			if len(versionLines) > 0 {
				results["tcpdump Version"] = strings.TrimSpace(versionLines[0])
			}
		}
	} else {
		results["tcpdump"] = "Not installed"
	}
}

// checkTsharkInstallation checks if tshark is installed
func checkTsharkInstallation(results map[string]string) {
	cmd := exec.Command("tshark", "-v")
	output, err := cmd.Output()
	if err != nil {
		results["tshark"] = "Not installed"
		return
	}

	// Parse tshark version from output
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		// First line typically contains version info
		versionLine := strings.TrimSpace(lines[0])
		if strings.Contains(versionLine, "TShark") {
			results["tshark"] = versionLine
		} else {
			results["tshark"] = "Installed (version unknown)"
		}
	} else {
		results["tshark"] = "Installed (version unknown)"
	}
}

// checkLinuxDistribution detects comprehensive Linux distribution information
func checkLinuxDistribution(results map[string]string) {
	// Primary method: /etc/os-release (systemd standard)
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		distroInfo := make(map[string]string)
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				distroInfo[key] = value
			}
		}
		
		// Build comprehensive distribution string
		var distroDetails []string
		
		if name, ok := distroInfo["PRETTY_NAME"]; ok {
			distroDetails = append(distroDetails, name)
		} else if name, ok := distroInfo["NAME"]; ok {
			if version, ok := distroInfo["VERSION"]; ok {
				distroDetails = append(distroDetails, name+" "+version)
			} else {
				distroDetails = append(distroDetails, name)
			}
		}
		
		// Add ID and version info for Docker base image reference
		if id, ok := distroInfo["ID"]; ok {
			if versionId, ok := distroInfo["VERSION_ID"]; ok {
				distroDetails = append(distroDetails, fmt.Sprintf("Docker Base: %s:%s", id, versionId))
			} else {
				distroDetails = append(distroDetails, fmt.Sprintf("Docker Base: %s:latest", id))
			}
		}
		
		// Add codename if available
		if codename, ok := distroInfo["VERSION_CODENAME"]; ok {
			distroDetails = append(distroDetails, "Codename: "+codename)
		}
		
		results["Linux Distribution"] = strings.Join(distroDetails, " | ")
		
		// Store individual components for automation scripts
		if id, ok := distroInfo["ID"]; ok {
			results["Distribution ID"] = id
		}
		if versionId, ok := distroInfo["VERSION_ID"]; ok {
			results["Distribution Version"] = versionId
		}
		if codename, ok := distroInfo["VERSION_CODENAME"]; ok {
			results["Distribution Codename"] = codename
		}
		
		return
	}
	
	// Fallback method: /etc/lsb-release
	if data, err := os.ReadFile("/etc/lsb-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		lsbInfo := make(map[string]string)
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				lsbInfo[key] = value
			}
		}
		
		if description, ok := lsbInfo["DISTRIB_DESCRIPTION"]; ok {
			results["Linux Distribution"] = description
		} else if id, ok := lsbInfo["DISTRIB_ID"]; ok {
			if release, ok := lsbInfo["DISTRIB_RELEASE"]; ok {
				results["Linux Distribution"] = id + " " + release
			} else {
				results["Linux Distribution"] = id
			}
		}
		
		return
	}
	
	// Final fallback: uname and /proc/version
	if cmd := exec.Command("uname", "-a"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			unameInfo := strings.TrimSpace(string(output))
			results["Linux Distribution"] = "Linux (" + unameInfo + ")"
			return
		}
	}
	
	// Last resort
	results["Linux Distribution"] = "Linux (distribution unknown)"
}

// checkAWSLoadBalancers checks for AWS load balancers associated with this instance
func checkAWSLoadBalancers(results map[string]string) {
	// Only check if we're in AWS environment
	if results["Cloud Environment"] != "AWS" && results["EC2 Instance"] == "" {
		return
	}

	// Check if AWS CLI is available
	cmd := exec.Command("which", "aws")
	if err := cmd.Run(); err != nil {
		results["AWS CLI"] = "Not Available"
		return
	}
	results["AWS CLI"] = "Available"

	// Get instance ID from metadata service
	cmd = exec.Command("curl", "-s", "--connect-timeout", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	instanceID := strings.TrimSpace(string(output))
	if instanceID == "" {
		return
	}
	results["EC2 Instance ID"] = instanceID

	// Discover Classic Load Balancers
	cmd = exec.Command("aws", "elb", "describe-load-balancers", "--query", "LoadBalancerDescriptions[?contains(Instances[].InstanceId, '" + instanceID + "')].{Name:LoadBalancerName,Scheme:Scheme,Listeners:ListenerDescriptions}", "--output", "json")
	output, err = cmd.Output()
	if err == nil {
		var clbs []map[string]interface{}
		if json.Unmarshal(output, &clbs) == nil && len(clbs) > 0 {
			for _, clb := range clbs {
				if name, ok := clb["Name"].(string); ok {
					results["Classic Load Balancer"] = name
					break
				}
			}
		}
	}

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
																		analyzeLoadBalancerSSLPolicies(arnStr, results)
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

// analyzeLoadBalancerSSLPolicies analyzes SSL policies for a given load balancer ARN
func analyzeLoadBalancerSSLPolicies(lbArn string, results map[string]string) {
	// Get load balancer listeners
	cmd := exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", lbArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results["SSL Policy Analysis"] = "Failed to retrieve listeners"
		return
	}

	var listenersResp map[string]interface{}
	if json.Unmarshal(output, &listenersResp) != nil {
		results["SSL Policy Analysis"] = "Failed to parse listeners response"
		return
	}

	listeners, ok := listenersResp["Listeners"].([]interface{})
	if !ok {
		results["SSL Policy Analysis"] = "No listeners found"
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
		results["SSL Policy Analysis"] = "No HTTPS/TLS listeners found"
		return
	}

	results["HTTPS Listeners"] = fmt.Sprintf("%d", len(httpsListeners))

	// Analyze each HTTPS listener's SSL policy
	for i, listener := range httpsListeners {
		port := "unknown"
		if portNum, ok := listener["Port"].(float64); ok {
			port = fmt.Sprintf("%.0f", portNum)
		}

		sslPolicy := "default"
		if policy, ok := listener["SslPolicy"].(string); ok {
			sslPolicy = policy
		}

		results[fmt.Sprintf("Listener %d Port", i+1)] = port
		results[fmt.Sprintf("Listener %d SSL Policy", i+1)] = sslPolicy

		// Analyze SSL policy for PQC readiness
		pqcReady := isSSLPolicyPQCReady(sslPolicy)
		results[fmt.Sprintf("Listener %d PQC Ready", i+1)] = fmt.Sprintf("%t", pqcReady)

		if !pqcReady {
			recommendedPolicy := getRecommendedSSLPolicy(sslPolicy)
			results[fmt.Sprintf("Listener %d Recommended Policy", i+1)] = recommendedPolicy
		}

		// Get detailed SSL policy information
		analyzeSSLPolicyDetails(sslPolicy, i+1, results)
	}
}

// isSSLPolicyPQCReady checks if an SSL policy supports PQC algorithms
func isSSLPolicyPQCReady(policyName string) bool {
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

// getRecommendedSSLPolicy returns a recommended PQC-ready SSL policy
func getRecommendedSSLPolicy(currentPolicy string) string {
	// Always recommend the latest TLS 1.3 policy for best PQC support
	return "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

// analyzeSSLPolicyDetails gets detailed information about an SSL policy
func analyzeSSLPolicyDetails(policyName string, listenerNum int, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", policyName, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results[fmt.Sprintf("Listener %d Policy Details", listenerNum)] = "Failed to retrieve policy details"
		return
	}

	var policyResp map[string]interface{}
	if json.Unmarshal(output, &policyResp) != nil {
		results[fmt.Sprintf("Listener %d Policy Details", listenerNum)] = "Failed to parse policy details"
		return
	}

	policies, ok := policyResp["SslPolicies"].([]interface{})
	if !ok || len(policies) == 0 {
		results[fmt.Sprintf("Listener %d Policy Details", listenerNum)] = "No policy details found"
		return
	}

	policy := policies[0].(map[string]interface{})

	// Extract supported protocols
	if protocols, ok := policy["SupportedProtocols"].([]interface{}); ok {
		protocolList := make([]string, len(protocols))
		for i, p := range protocols {
			protocolList[i] = p.(string)
		}
		results[fmt.Sprintf("Listener %d Protocols", listenerNum)] = strings.Join(protocolList, ", ")
		
		// Check for TLS 1.3 support (essential for PQC)
		hasTLS13 := false
		for _, protocol := range protocolList {
			if protocol == "TLSv1.3" {
				hasTLS13 = true
				break
			}
		}
		results[fmt.Sprintf("Listener %d TLS 1.3 Support", listenerNum)] = fmt.Sprintf("%t", hasTLS13)
	}

	// Extract supported ciphers
	if ciphers, ok := policy["Ciphers"].([]interface{}); ok {
		results[fmt.Sprintf("Listener %d Cipher Count", listenerNum)] = fmt.Sprintf("%d", len(ciphers))
		
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
		results[fmt.Sprintf("Listener %d Modern Ciphers", listenerNum)] = fmt.Sprintf("%d", modernCiphers)
	}
}

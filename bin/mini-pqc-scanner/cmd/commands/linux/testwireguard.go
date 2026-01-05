package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mini-pqc/scan"
)

// WireguardReport represents the structure of the JSON report for the wireguard command
type WireguardReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	WireguardInfo  map[string]string      `json:"wireguard_info"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// TestWireguard checks WireGuard configuration for PQC readiness
func TestWireguard(jsonOutput bool) []scan.Recommendation {
	fmt.Println("\n=== WireGuard PQC Test ===")

	// Initialize results map
	results := make(map[string]string)

	// Check if WireGuard is installed
	if !isWireGuardInstalled() {
		fmt.Println("[FAIL] WireGuard is not installed")
		results["WireGuard Installed"] = "No"
		return generateWireguardRecommendations(results)
	}

	fmt.Println("[PASS] WireGuard is installed")
	results["WireGuard Installed"] = "Yes"
	
	// Check WireGuard version
	cmd := exec.Command("wg", "version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		version := strings.TrimSpace(string(output))
		fmt.Printf("[PASS] %s\n", version)
		results["WireGuard Version"] = version
	} else {
		results["WireGuard Version"] = "Unknown"
	}

	// Get active WireGuard interfaces
	interfaces := getWireGuardInterfaces()
	if len(interfaces) == 0 {
		fmt.Println("[FAIL] No active WireGuard interfaces found")
		results["Interfaces"] = "None"
	} else {
		fmt.Printf("[PASS] Found %d WireGuard interface(s): %s\n", len(interfaces), strings.Join(interfaces, ", "))
		results["Interfaces"] = strings.Join(interfaces, ", ")
	}

	// Check kernel module status
	lsmodCmd := exec.Command("lsmod")
	lsmodOutput, lsmodErr := lsmodCmd.CombinedOutput()
	if lsmodErr == nil && len(lsmodOutput) > 0 {
		lsmodOutputStr := string(lsmodOutput)
		if strings.Contains(lsmodOutputStr, "wireguard") {
			results["Kernel Module"] = "Loaded"
		} else {
			results["Kernel Module"] = "Not loaded"
		}
	}

	// Check for Rosenpass installation
	hasRosenpass := checkRosenpassInstallation()
	if hasRosenpass {
		fmt.Println("[PASS] Rosenpass is installed (PQC-enabled WireGuard)")
		results["Rosenpass"] = "Installed"
	} else {
		fmt.Println("[INFO] Rosenpass is not installed (consider installing for PQC support)")
		results["Rosenpass"] = "Not installed"
	}

	// Check for tools
	cmd = exec.Command("which", "wg")
	if err := cmd.Run(); err != nil {
		results["Tools"] = "Missing"
	} else {
		results["Tools"] = "Installed"
	}

	// Check each interface configuration
	for _, iface := range interfaces {
		fmt.Printf("\n--- Interface: %s ---\n", iface)
		checkInterfaceConfig(iface, hasRosenpass)
	}

	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	generateWireGuardStatus(results, rm)

	// Check AWS environment and load balancer configuration
	checkAWSEnvironmentForWireguard(results)

	// Generate recommendations based on results
	recommendations := generateWireguardRecommendations(results)

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
		report := WireguardReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			WireguardInfo:  results,
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
			filePath := filepath.Join(reportDir, "wireguard.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/wireguard.json")
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

// isWireGuardInstalled checks if WireGuard is installed
func isWireGuardInstalled() bool {
	cmd := exec.Command("which", "wg")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}



// checkWireGuardInstallation checks if WireGuard is installed and gets its status
func checkWireGuardInstallation(results map[string]string) {
	// Check for WireGuard kernel module
	cmd := exec.Command("lsmod")
	output, err := cmd.CombinedOutput()
	wireguardKernelModule := false
	if err == nil && len(output) > 0 {
		outputStr := string(output)
		if strings.Contains(outputStr, "wireguard") {
			wireguardKernelModule = true
			results["WireGuard"] = "Kernel module loaded"
		}
	}

	// Check for WireGuard tools
	cmd = exec.Command("which", "wg")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		results["WireGuard"] = "Installed"

		// Check WireGuard version
		cmd = exec.Command("wg", "version")
		output, err = cmd.CombinedOutput()
		if err == nil {
			version := strings.TrimSpace(string(output))
			results["WireGuard"] = version
		}

		// Check if WireGuard is running (interfaces exist)
		cmd = exec.Command("wg", "show", "interfaces")
		output, err = cmd.CombinedOutput()
		if err == nil {
			interfaces := strings.TrimSpace(string(output))
			if interfaces != "" {
				results["WireGuard Status"] = "Active"
				results["WireGuard Interfaces"] = interfaces
			} else {
				results["WireGuard Status"] = "Installed but no active interfaces"
			}
		} else {
			// Try with sudo if available
			cmd = exec.Command("sudo", "-n", "wg", "show", "interfaces")
			output, err = cmd.CombinedOutput()
			if err == nil {
				interfaces := strings.TrimSpace(string(output))
				if interfaces != "" {
					results["WireGuard Status"] = "Active"
					results["WireGuard Interfaces"] = interfaces
				} else {
					results["WireGuard Status"] = "Installed but no active interfaces"
				}
			} else {
				// Check via ip link as a fallback
				cmd = exec.Command("ip", "-o", "link", "show")
				output, err = cmd.CombinedOutput()
				if err == nil {
					outputStr := string(output)
					wgInterfaces := []string{}
					for _, line := range strings.Split(outputStr, "\n") {
						if strings.Contains(line, "wg") {
							parts := strings.Fields(line)
							if len(parts) > 1 {
								interface_name := strings.TrimSuffix(parts[1], ":")
								if strings.HasPrefix(interface_name, "wg") {
									wgInterfaces = append(wgInterfaces, interface_name)
								}
							}
						}
					}
					if len(wgInterfaces) > 0 {
						results["WireGuard Status"] = "Active"
						results["WireGuard Interfaces"] = strings.Join(wgInterfaces, ", ")
					} else if wireguardKernelModule {
						results["WireGuard Status"] = "Kernel module loaded but no active interfaces"
					} else {
						results["WireGuard Status"] = "Installed but status unknown"
					}
				}
			}
		}
	} else if wireguardKernelModule {
		results["WireGuard Status"] = "Kernel module loaded but tools not found"
	} else {
		// Check for WireGuard package
		cmd = exec.Command("dpkg", "-l", "wireguard")
		output, err = cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "wireguard") {
			results["WireGuard"] = "Package installed but not configured"
			results["WireGuard Status"] = "Not active"
		} else {
			// Try rpm-based systems
			cmd = exec.Command("rpm", "-q", "wireguard-tools")
			output, err = cmd.CombinedOutput()
			if err == nil && strings.Contains(string(output), "wireguard") {
				results["WireGuard"] = "Package installed but not configured"
				results["WireGuard Status"] = "Not active"
			} else {
				results["WireGuard"] = "Not installed"
			}
		}
	}
}

// getWireGuardInterfaces returns a list of active WireGuard interfaces
func getWireGuardInterfaces() []string {
	var interfaces []string

	// Try direct wg command first
	cmd := exec.Command("wg", "show", "interfaces")
	output, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if line != "" {
				interfaces = append(interfaces, line)
			}
		}
		return interfaces
	}

	// Try with sudo if available
	cmd = exec.Command("sudo", "-n", "wg", "show", "interfaces")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if line != "" {
				interfaces = append(interfaces, line)
			}
		}
		return interfaces
	}

	// Fallback to ip link
	cmd = exec.Command("ip", "-o", "link", "show")
	output, err = cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "wg") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ifaceName := strings.TrimSuffix(parts[1], ":")
					if strings.HasPrefix(ifaceName, "wg") {
						interfaces = append(interfaces, ifaceName)
					}
				}
			}
		}
	}

	return interfaces
}

// checkRosenpassInstallation checks if Rosenpass is installed
func checkRosenpassInstallation() bool {
	// Check for rosenpass binary
	cmd := exec.Command("which", "rosenpass")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Check for rp binary (alternative name)
	cmd = exec.Command("which", "rp")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Check for Rosenpass service
	cmd = exec.Command("systemctl", "is-active", "rosenpass")
	output, _ := cmd.CombinedOutput()
	if strings.TrimSpace(string(output)) == "active" {
		return true
	}

	return false
}

// checkInterfaceConfig checks the configuration of a WireGuard interface
func checkInterfaceConfig(iface string, hasRosenpass bool) {
	// Check config file
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", iface)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("[FAIL] Configuration file not found: %s\n", configPath)

		// Try to get info from wg show command
		showInterfaceInfo(iface)
		return
	}

	fmt.Printf("[PASS] Found configuration file: %s\n", configPath)

	// Parse config file
	file, err := os.Open(configPath)
	if err != nil {
		fmt.Printf("[FAIL] Error opening config file: %s\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var publicKey, presharedKey string
	var hasPostQuantumKey bool

	for scanner.Scan() {
		line := scanner.Text()

		// Look for public keys
		if strings.Contains(line, "PublicKey") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				publicKey = strings.TrimSpace(parts[1])
				fmt.Printf("[PASS] Found PublicKey: %s\n", publicKey)
			}
		}

		// Look for preshared keys
		if strings.Contains(line, "PresharedKey") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				presharedKey = strings.TrimSpace(parts[1])
				fmt.Printf("[PASS] Found PresharedKey: %s\n", presharedKey)
			}
		}

		// Check for Rosenpass configuration
		if strings.Contains(line, "PostQuantum") ||
			strings.Contains(line, "Rosenpass") ||
			strings.Contains(line, "RosenpassKey") {
			hasPostQuantumKey = true
			fmt.Printf("[PASS] Found Post-Quantum configuration: %s\n", line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[FAIL] Error reading config file: %s\n", err)
	}

	// Check for Rosenpass configuration files
	rosenpassConfigPath := fmt.Sprintf("/etc/rosenpass/%s.conf", iface)
	if _, err := os.Stat(rosenpassConfigPath); err == nil {
		fmt.Printf("[PASS] Found Rosenpass configuration file: %s\n", rosenpassConfigPath)
		hasPostQuantumKey = true
	}

	// Check for Rosenpass key files
	rosenpassKeyPath := fmt.Sprintf("/etc/rosenpass/keys/%s", iface)
	if _, err := os.Stat(rosenpassKeyPath); err == nil {
		fmt.Printf("[PASS] Found Rosenpass key directory: %s\n", rosenpassKeyPath)
		hasPostQuantumKey = true
	}

	// If we have Rosenpass but no PQ config detected, check for integration
	if hasRosenpass && !hasPostQuantumKey {
		checkRosenpassIntegration(iface)
	}

	// Show interface info from wg command
	showInterfaceInfo(iface)
}

// showInterfaceInfo shows information about a WireGuard interface using wg command
func showInterfaceInfo(iface string) {
	cmd := exec.Command("wg", "show", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try with sudo
		cmd = exec.Command("sudo", "-n", "wg", "show", iface)
		output, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("[FAIL] Error getting interface info: %s\n", err)
			return
		}
	}

	fmt.Println("\nInterface Details:")
	fmt.Println(strings.TrimSpace(string(output)))
}

// checkRosenpassIntegration checks if Rosenpass is integrated with this WireGuard interface
func checkRosenpassIntegration(iface string) {
	// Check systemd service
	cmd := exec.Command("systemctl", "status", fmt.Sprintf("rosenpass@%s", iface))
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "Active: active") {
		fmt.Printf("[PASS] Found active Rosenpass service for %s\n", iface)
		return
	}

	// Check for Rosenpass hooks
	hooksDir := "/etc/wireguard/hooks"
	if _, err := os.Stat(hooksDir); err == nil {
		files, err := filepath.Glob(filepath.Join(hooksDir, "*"))
		if err == nil {
			for _, file := range files {
				// Read file content to check for Rosenpass and this interface
				content, err := os.ReadFile(file)
				if err == nil && strings.Contains(string(content), "rosenpass") &&
					strings.Contains(string(content), iface) {
					fmt.Printf("[PASS] Found Rosenpass hook for %s: %s\n", iface, file)
					return
				}
			}
		}
	}

	fmt.Println("[INFO] No Rosenpass integration detected for this interface")
}



package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateWireGuardStatus creates structured status items from WireGuard scan results
func generateWireGuardStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for WireGuard command
	moduleID := scan.CommandModules["testwireguard"] // Should be 16

	// Section 1: WireGuard Installation Status
	if installed, ok := results["WireGuard Installed"]; ok {
		if installed != "No" {
			rm.AddStatus(moduleID, 1, 1, "WireGuard: Installed", scan.InfoRecommendation, "", 1)
		}
		// Don't show anything if not installed
	}

	// Section 2: WireGuard Version
	if version, ok := results["Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("WireGuard version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 3: Kernel Module Information
	if kernelModule, ok := results["Kernel Module"]; ok && kernelModule != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Kernel module: %s", kernelModule), scan.InfoRecommendation, "", 2)
	}

	// Section 4: Configuration Information
	if confPath, ok := results["Config Path"]; ok && confPath != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("Configuration file: %s", confPath), scan.InfoRecommendation, "", 1)
	}

	// Section 5: Key Information
	if keyType, ok := results["Key Type"]; ok && keyType != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Key type: %s", keyType), scan.InfoRecommendation, "", 2)
	}

	// Section 6: Interface Status
	if ifaceStatus, ok := results["Interface Status"]; ok && ifaceStatus != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("Interface status: %s", ifaceStatus), scan.InfoRecommendation, "", 1)
	}

	// Section 8: Interfaces
	if interfaces, ok := results["Interfaces"]; ok {
		if interfaces != "None" && interfaces != "" {
			rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("WireGuard interfaces found: %s", interfaces), scan.InfoRecommendation, "", 2)
		} else {
			rm.AddStatus(moduleID, 8, 1, "No WireGuard interfaces found", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 7: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 9: AWS Load Balancer Configuration (if in AWS environment)
	awsItemID := 1
	if _, ok := results["AWS Environment"]; ok {
		// AWS Environment Detection
		if awsEnv, ok := results["AWS Environment"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS Environment: %s", awsEnv), scan.InfoRecommendation, "AWS environment detected for load balancer crypto inspection", 1)
			awsItemID++
		}
		
		// EC2 Instance ID
		if instanceID, ok := results["EC2 Instance ID"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "EC2 instance ID used for load balancer discovery", 1)
			awsItemID++
		}
		
		// Load Balancer Discovery
		if clb, ok := results["Classic Load Balancer"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Classic Load Balancer: %s", clb), scan.InfoRecommendation, "Classic Load Balancer discovered (internet-facing VPN access)", 1)
			awsItemID++
		}
		if alb, ok := results["Application Load Balancer"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Application Load Balancer: %s", alb), scan.InfoRecommendation, "Application/Network Load Balancer discovered (internet-facing VPN access)", 1)
			awsItemID++
		}
		
		// Load Balancer Type and Scheme
		if lbType, ok := results["LB Type"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Type: %s", lbType), scan.InfoRecommendation, "Load balancer type (Application/Network/Classic)", 1)
			awsItemID++
		}
		if lbScheme, ok := results["LB Scheme"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Scheme: %s", lbScheme), scan.InfoRecommendation, "Load balancer scheme (internet-facing or internal)", 1)
			awsItemID++
		}
		
		// VPN Protocol Analysis
		if vpnProtocol, ok := results["LB VPN Protocol"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Protocol: %s", vpnProtocol), scan.InfoRecommendation, "VPN protocol support on load balancer for WireGuard traffic", 1)
			awsItemID++
		}
		
		// Listener Information
		if udpListeners, ok := results["LB UDP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB UDP Listeners: %s", udpListeners), scan.InfoRecommendation, "UDP listeners for WireGuard VPN traffic", 1)
			awsItemID++
		}
		if tcpListeners, ok := results["LB TCP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TCP Listeners: %s", tcpListeners), scan.InfoRecommendation, "TCP listeners for alternative VPN configurations", 1)
			awsItemID++
		}
		if httpsListeners, ok := results["LB HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB HTTPS Listeners: %s", httpsListeners), scan.InfoRecommendation, "HTTPS listeners for WireGuard management interfaces", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis (for management interfaces)
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL policy for WireGuard management interfaces (not VPN tunnel crypto)", 1)
			awsItemID++
		}
		
		// SSL Context Note
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy applies to management interfaces only, VPN tunnel uses WireGuard's own cryptography", 1)
			awsItemID++
		}
		
		// PQC Readiness (for management interfaces)
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready (Management)", scan.InfoRecommendation, "Load balancer SSL policy supports PQC for management interfaces (VPN tunnel crypto is separate)", 1)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade (Management)", scan.WarningRecommendation, "Load balancer SSL policy for management interfaces needs PQC upgrade", 3)
			}
			awsItemID++
		}
		
		// Primary Port
		if primaryPort, ok := results["LB Primary Port"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary port for WireGuard VPN access through load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateOpenVPNStatus creates structured status items from OpenVPN scan results
func generateOpenVPNStatus(results map[string]string, rm *scan.RecommendationManager) {
    // Module ID for OpenVPN command
    moduleID := scan.CommandModules["testopenvpn"]

	// Section 1: OpenVPN Version / Installation
	if openvpnInfo, ok := results["OpenVPN"]; ok {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("OpenVPN: %s", openvpnInfo), scan.InfoRecommendation, "", 1)
	} else if installed, ok := results["OpenVPN Installed"]; ok {
		// Fallback to older key name if present
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("OpenVPN Installed: %s", installed), scan.InfoRecommendation, "", 1)
	}

	// Section 2: OpenVPN Version
	if version, ok := results["Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("OpenVPN version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 3: OpenSSL Information
	if version, ok := results["OpenSSL Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("OpenSSL version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 4: Configuration Information
	if confPath, ok := results["Config Path"]; ok && confPath != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("Configuration file: %s", confPath), scan.InfoRecommendation, "", 1)
	}

	// Section 5: Cipher Settings
	if ciphers, ok := results["Cipher"]; ok && ciphers != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Configured cipher: %s", ciphers), scan.InfoRecommendation, "", 2)
	}

	// Section 6: TLS Settings
	if tlsVersion, ok := results["TLS Version"]; ok && tlsVersion != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("TLS version: %s", tlsVersion), scan.InfoRecommendation, "", 2)
	}

	// Section 7: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 8: Certificate Information
	if certInfo, ok := results["Certificate Info"]; ok && certInfo != "" {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("Certificate information: %s", certInfo), scan.InfoRecommendation, "", 2)
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Protocol: %s", vpnProtocol), scan.InfoRecommendation, "VPN protocol support on load balancer for OpenVPN traffic", 1)
			awsItemID++
		}
		
		// VPN Ports
		if vpnPorts, ok := results["LB VPN Ports"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Ports: %s", vpnPorts), scan.InfoRecommendation, "VPN ports exposed through load balancer for OpenVPN access", 1)
			awsItemID++
		}
		
		// Listener Information
		if udpListeners, ok := results["LB UDP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB UDP Listeners: %s", udpListeners), scan.InfoRecommendation, "UDP listeners for OpenVPN traffic (preferred protocol)", 1)
			awsItemID++
		}
		if tcpListeners, ok := results["LB TCP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TCP Listeners: %s", tcpListeners), scan.InfoRecommendation, "TCP listeners for OpenVPN traffic (fallback protocol)", 1)
			awsItemID++
		}
		if httpsListeners, ok := results["LB HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB HTTPS Listeners: %s", httpsListeners), scan.InfoRecommendation, "HTTPS listeners for OpenVPN web interfaces", 1)
			awsItemID++
		}
		if tlsListeners, ok := results["LB TLS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TLS Listeners: %s", tlsListeners), scan.InfoRecommendation, "TLS listeners for OpenVPN traffic (uncommon setup)", 1)
			awsItemID++
		}
		
		// VPN Context Note
		if vpnContext, ok := results["LB VPN Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Context: %s", vpnContext), scan.InfoRecommendation, "How OpenVPN cryptography is handled in relation to load balancer", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis (for web interfaces)
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL policy for OpenVPN web interfaces (not tunnel crypto)", 1)
			awsItemID++
		}
		
		// PQC Readiness (context-dependent)
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready (Web Interface)", scan.InfoRecommendation, "Load balancer SSL policy supports PQC for web interfaces (VPN tunnel crypto is separate)", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade (Web Interface)", scan.WarningRecommendation, "Load balancer SSL policy for web interfaces needs PQC upgrade", 3)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: N/A (VPN Passthrough)", scan.InfoRecommendation, "OpenVPN uses own TLS cryptography - check OpenVPN PQC support separately", 1)
			}
			awsItemID++
		}
		
		// Primary Port
		if primaryPort, ok := results["LB Primary Port"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary port for OpenVPN access through load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateIPsecStatus creates structured status items from IPsec scan results
func generateIPsecStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for IPsec command
	moduleID := scan.CommandModules["testipsec"] // Should be 4

	// Section 1: IPsec Installation Status
	// Check for installation status under the correct key
	if installed, ok := results["IPsec"]; ok {
		// Get version information
		var version string
		
		// Check for strongSwan version
		if strongswanVer, ok := results["strongSwan Version"]; ok && strongswanVer != "" {
			version = strongswanVer
		} else if libreswanVer, ok := results["Libreswan Version"]; ok && libreswanVer != "" {
			version = libreswanVer
		} else if openswanVer, ok := results["Openswan Version"]; ok && openswanVer != "" {
			version = openswanVer
		} else if genericVer, ok := results["IPsec Version"]; ok && genericVer != "" {
			version = genericVer
		}
		
		// Display installation status with version if available
		if version != "" {
			// Extract implementation name from the installed status
			implementation := "Unknown"
			if strings.Contains(installed, "strongSwan") {
				implementation = "strongSwan"
			} else if strings.Contains(installed, "Libreswan") {
				implementation = "Libreswan"
			} else if strings.Contains(installed, "Openswan") {
				implementation = "Openswan"
			}
			
			// Create status message with implementation and version
			rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("IPsec: %s (Version: %s)", implementation, version), scan.InfoRecommendation, "", 1)
		} else {
			// Just show installation status if version is not available
			rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("IPsec: %s", installed), scan.InfoRecommendation, "", 1)
		}
		
		// Display if it's running
		if _, ok := results["Runtime Status"]; ok {
			runningStatus := "Unknown"
			if active, ok := results["Active Connections"]; ok {
				if active == "true" {
					runningStatus = "Running with active connections"
				} else {
					runningStatus = "Running with no active connections"
				}
			}
			rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("Status: %s", runningStatus), scan.InfoRecommendation, "", 0)
		}
	} else {
		rm.AddStatus(moduleID, 1, 1, "IPsec: Not installed", scan.InfoRecommendation, "", 1)
	}

	// Section 2: IPsec Implementation
	if impl, ok := results["Implementation"]; ok && impl != "" {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("Implementation: %s", impl), scan.InfoRecommendation, "", 1)
	}

	// Section 3: Version Information
	if version, ok := results["Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 4: Configuration Information
	if confPath, ok := results["Config Path"]; ok && confPath != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("Configuration file: %s", confPath), scan.InfoRecommendation, "", 0)
	}

	// Section 5: Crypto Settings
	if algorithms, ok := results["Algorithms"]; ok && algorithms != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Configured algorithms: %s", algorithms), scan.InfoRecommendation, "", 2)
	}

	// Section 6: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 7: Connection Status
	if status, ok := results["Connection Status"]; ok {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("Connection status: %s", status), scan.InfoRecommendation, "", 1)
	}

	// Section 9: AWS Load Balancer Context (if available)
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
		
		// VPN Protocol Context
		if vpnProtocol, ok := results["LB VPN Protocol"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Protocol: %s", vpnProtocol), scan.InfoRecommendation, "VPN protocol support on load balancer for IPsec traffic", 1)
			awsItemID++
		}
		
		// Listener Information
		if udpListeners, ok := results["LB UDP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB UDP Listeners: %s", udpListeners), scan.InfoRecommendation, "UDP listeners for IPsec VPN traffic", 1)
			awsItemID++
		}
		if tcpListeners, ok := results["LB TCP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TCP Listeners: %s", tcpListeners), scan.InfoRecommendation, "TCP listeners for IPsec VPN traffic", 1)
			awsItemID++
		}
		if httpsListeners, ok := results["LB HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB HTTPS Listeners: %s", httpsListeners), scan.InfoRecommendation, "HTTPS listeners for IPsec management interfaces", 1)
			awsItemID++
		}
		if tlsListeners, ok := results["LB TLS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TLS Listeners: %s", tlsListeners), scan.InfoRecommendation, "TLS listeners for IPsec traffic (uncommon setup)", 1)
			awsItemID++
		}
		
		// VPN Context
		if vpnContext, ok := results["LB VPN Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB VPN Context: %s", vpnContext), scan.InfoRecommendation, "How IPsec cryptography is handled in relation to load balancer", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis (for management interfaces)
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL policy for IPsec management interfaces (not tunnel crypto)", 1)
			awsItemID++
		}
		
		// SSL Context
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy applies to management interfaces only, IPsec tunnel uses own cryptography", 1)
			awsItemID++
		}
		
		// PQC Readiness (context-dependent)
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready (Management)", scan.InfoRecommendation, "Load balancer SSL policy supports PQC for management interfaces (VPN tunnel crypto is separate)", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade (Management)", scan.WarningRecommendation, "Load balancer SSL policy for management interfaces needs PQC upgrade", 3)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: N/A (VPN Passthrough)", scan.InfoRecommendation, "IPsec uses own cryptography - check IPsec PQC support separately", 1)
			}
			awsItemID++
		}
		
		// Cipher Information
		if cipherCount, ok := results["LB Cipher Count"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Cipher Count: %s", cipherCount), scan.InfoRecommendation, "Number of cipher suites supported by load balancer SSL policy", 1)
			awsItemID++
		}
		if modernCiphers, ok := results["LB Modern Ciphers"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Modern Ciphers: %s", modernCiphers), scan.InfoRecommendation, "Number of modern cipher suites in load balancer SSL policy", 1)
			awsItemID++
		}
		
		// Primary Port
		if primaryPort, ok := results["LB Primary Port"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary port for IPsec VPN access through load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

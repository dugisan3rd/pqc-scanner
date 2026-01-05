package linux

import (
	"fmt"
	"strings"
	"mini-pqc/scan"
)

// generateOpenSSHStatus creates structured status items from OpenSSH scan results
func generateOpenSSHStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for OpenSSH command
	moduleID := scan.CommandModules["testopenssh"] // Should be 6

	// Section 1: OpenSSH Installation Status
	// Always add a basic status item since we know OpenSSH is installed if we got this far
	
	// Report client version
	if clientVersion, ok := results["OpenSSHClientVersion"]; ok && clientVersion != "Unknown" {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("OpenSSH Client: %s", clientVersion), scan.InfoRecommendation, "", 1)
	} else {
		rm.AddStatus(moduleID, 1, 1, "OpenSSH Client: Installed", scan.InfoRecommendation, "", 1)
	}
	
	// Report server version
	if serverVersion, ok := results["OpenSSHServerVersion"]; ok {
		if serverVersion == "Not installed" {
			rm.AddStatus(moduleID, 1, 2, "OpenSSH Server: Not installed", scan.InfoRecommendation, "", 1)
		} else {
			rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("OpenSSH Server: %s", serverVersion), scan.InfoRecommendation, "", 1)
		}
	} else {
		rm.AddStatus(moduleID, 1, 2, "OpenSSH Server: Status unknown", scan.InfoRecommendation, "", 1)
	}

	// Section 2: Algorithm Configuration
	// Host Key Algorithms
	if hostKeyAlgs, ok := results["HostKeyAlgorithms"]; ok && hostKeyAlgs != "" {
		rm.AddStatus(moduleID, 2, 1, "Host Key Algorithms", scan.InfoRecommendation, hostKeyAlgs, 2)
	}

	// Pubkey Accepted Algorithms
	if pubkeyAlgs, ok := results["PubkeyAcceptedAlgorithms"]; ok && pubkeyAlgs != "" {
		rm.AddStatus(moduleID, 2, 2, "Public Key Accepted Algorithms", scan.InfoRecommendation, pubkeyAlgs, 2)
	}

	// CA Signature Algorithms
	if caSignAlgs, ok := results["CASignatureAlgorithms"]; ok && caSignAlgs != "" {
		rm.AddStatus(moduleID, 2, 3, "CA Signature Algorithms", scan.InfoRecommendation, caSignAlgs, 2)
	}

	// Section 3: Quantum Resistance Status
	// Determine availability and defaults based on version thresholds
	pqcDetails := "No PQC algorithms available in current OpenSSH version"
	pqcAvailable := false
	pqcDefault := false

	if clientVersion, ok := results["OpenSSHClientVersion"]; ok {
		if isOpenSSHAtLeast(clientVersion, 9, 9) {
			pqcAvailable = true
		}
		if isOpenSSHAtLeast(clientVersion, 10, 0) {
			pqcDefault = true
		}
	}
	if serverVersion, ok := results["OpenSSHServerVersion"]; ok {
		if isOpenSSHAtLeast(serverVersion, 9, 9) {
			pqcAvailable = true
		}
		if isOpenSSHAtLeast(serverVersion, 10, 0) {
			pqcDefault = true
		}
	}

	// Check if KexAlgorithms explicitly enables the hybrid KEX
	kexConfigured := false
	if kexAlgs, ok := results["KexAlgorithms"]; ok {
		if strings.Contains(kexAlgs, "mlkem768x25519-sha256") {
			kexConfigured = true
		}
	}

	if pqcDefault {
		pqcDetails = "OpenSSH 10.0+ defaults to hybrid post-quantum key exchange (mlkem768x25519-sha256)"
	} else if pqcAvailable {
		if kexConfigured {
			pqcDetails = "Hybrid PQC key exchange enabled (mlkem768x25519-sha256) on OpenSSH 9.9+"
		} else {
			pqcDetails = "Hybrid PQC key exchange available on OpenSSH 9.9+; configure KexAlgorithms to enable (mlkem768x25519-sha256)"
		}
	}

	rm.AddStatus(moduleID, 3, 1, "Quantum-Resistant Support", scan.InfoRecommendation, pqcDetails, 2)


	// Section 6: Host Key Algorithms
	if hostKeyAlgs, ok := results["Host Key Algorithms"]; ok && hostKeyAlgs != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("Host key algorithms: %s", hostKeyAlgs), scan.InfoRecommendation, "", 2)
	}

	// Section 7: Ciphers
	if ciphers, ok := results["Ciphers"]; ok && ciphers != "" {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("Ciphers: %s", ciphers), scan.InfoRecommendation, "", 2)
	}

	// Section 8: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Classic Load Balancer: %s", clb), scan.InfoRecommendation, "Classic Load Balancer discovered (internet-facing SSH access)", 1)
			awsItemID++
		}
		if alb, ok := results["Application Load Balancer"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Application Load Balancer: %s", alb), scan.InfoRecommendation, "Application/Network Load Balancer discovered (internet-facing SSH access)", 1)
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
		
		// SSH Protocol Analysis
		if sshProtocol, ok := results["LB SSH Protocol"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSH Protocol: %s", sshProtocol), scan.InfoRecommendation, "SSH protocol handling on load balancer", 1)
			awsItemID++
		}
		
		// SSH Ports
		if sshPorts, ok := results["LB SSH Ports"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSH Ports: %s", sshPorts), scan.InfoRecommendation, "SSH ports exposed through load balancer", 1)
			awsItemID++
		}
		
		// Listener Information
		if tcpListeners, ok := results["LB TCP Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TCP Listeners: %s", tcpListeners), scan.InfoRecommendation, "TCP listeners for SSH traffic (standard setup)", 1)
			awsItemID++
		}
		if tlsListeners, ok := results["LB TLS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB TLS Listeners: %s", tlsListeners), scan.InfoRecommendation, "TLS listeners for SSH traffic (uncommon setup)", 1)
			awsItemID++
		}
		
		// SSH Context Note
		if sshContext, ok := results["LB SSH Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSH Context: %s", sshContext), scan.InfoRecommendation, "How SSH cryptography is handled in relation to load balancer", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis (for rare TLS-terminated SSH)
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL policy for TLS-terminated SSH (uncommon setup)", 1)
			awsItemID++
		}
		
		// PQC Readiness (context-dependent)
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready (TLS)", scan.InfoRecommendation, "Load balancer SSL policy supports PQC for TLS-terminated SSH (rare setup)", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade (TLS)", scan.WarningRecommendation, "Load balancer SSL policy for TLS-terminated SSH needs PQC upgrade", 3)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: N/A (TCP passthrough)", scan.InfoRecommendation, "SSH uses own cryptography - check OpenSSH PQC support separately", 1)
			}
			awsItemID++
		}
		
		// Primary Port
		if primaryPort, ok := results["LB Primary Port"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary port for SSH access through load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

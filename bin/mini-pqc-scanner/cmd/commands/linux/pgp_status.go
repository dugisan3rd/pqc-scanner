package linux

import (
    "fmt"
    "os/exec"
    "mini-pqc/scan"
)

// generatePGPStatus adds status items for the PGP command (module 9)
// Section 1: Installation status and version, Section 2: Key counts
func generatePGPStatus(total, pqc, classic int, rm *scan.RecommendationManager) {
    moduleID := scan.CommandModules["testpgp"] // Should be 9

    // Section 1: Installation status and version
    _, err := exec.LookPath("gpg")
    if err != nil {
        // GnuPG (PGP implementation) is not installed
        rm.AddStatus(moduleID, 1, 1, "GnuPG (PGP): Not installed", scan.InfoRecommendation, "", 1)
    } else {
        // GnuPG (PGP implementation) is installed, get version
        version := getGPGVersion()
        rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("GnuPG (PGP): Installed (Version: %s)", version), scan.InfoRecommendation, "", 1)
    }

    // Section 2: Key count summary
    rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("GnuPG keys: %d total, %d quantum-safe, %d non-quantum-safe", total, pqc, classic), scan.InfoRecommendation, "", 1)
}

// generatePGPAWSStatus creates AWS load balancer status items for PGP command
func generatePGPAWSStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for PGP command
	moduleID := scan.CommandModules["testpgp"] // Should be 9

	// Section 10: AWS Load Balancer Status (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok {
		awsItemID := 1
		
		// AWS Environment
		rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS Environment: %s", awsEnv), scan.InfoRecommendation, "PGP key management running in AWS environment with potential web service crypto termination", 1)
		awsItemID++
		
		// EC2 Instance ID
		if instanceID, ok := results["EC2 Instance ID"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "EC2 instance identifier for load balancer association", 1)
			awsItemID++
		}
		
		// Load Balancer Type
		if lbType, ok := results["LB Type"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Type: %s", lbType), scan.InfoRecommendation, "Type of AWS load balancer handling web services that might use PGP", 1)
			awsItemID++
		}
		
		// Load Balancer Name
		if lbName, ok := results["LB Name"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Name: %s", lbName), scan.InfoRecommendation, "AWS load balancer name handling web services", 1)
			awsItemID++
		}
		
		// Web Ports
		if webPorts, ok := results["LB Web Ports"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Web Ports: %s", webPorts), scan.InfoRecommendation, "Web service ports on load balancer that might serve PGP-signed content", 1)
			awsItemID++
		}
		
		// SSL Policy
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL/TLS policy used by load balancer for web service encryption", 1)
			awsItemID++
		}
		
		// SSL Context
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy context for web services that might use PGP signatures", 1)
			awsItemID++
		}
		
		// PQC Readiness
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			} else {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: N/A", scan.InfoRecommendation, "No SSL termination at load balancer for web services", 1)
			}
			awsItemID++
		}
		
		// Cipher Information
		if cipherCount, ok := results["LB Cipher Count"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Cipher Count: %s", cipherCount), scan.InfoRecommendation, "Number of cipher suites supported by load balancer SSL policy", 1)
			awsItemID++
		}
		if modernCiphers, ok := results["LB Modern Ciphers"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Modern Ciphers: %s", modernCiphers), scan.InfoRecommendation, "Number of modern cipher suites in load balancer SSL policy", 1)
			awsItemID++
		}
		
		// Primary Port
		if primaryPort, ok := results["LB Primary Port"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary web service port on load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generatePostfixStatus creates structured status items from Postfix scan results
func generatePostfixStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for Postfix command
	moduleID := scan.CommandModules["testpostfix"] // Should be 8

	// Section 1: Postfix Installation Status and Version
	installed, hasInstalled := results["Postfix Installed"]
	version, hasVersion := results["Version"]
	
	if hasInstalled {
		if installed == "Yes" {
			if hasVersion && version != "" {
				// Merge installation status and version into one message
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Postfix: Installed (Version: %s)", version), scan.InfoRecommendation, "", 1)
			} else {
				// Just show installation status if version is not available
				rm.AddStatus(moduleID, 1, 1, "Postfix: Installed", scan.InfoRecommendation, "", 1)
			}
		} else {
			rm.AddStatus(moduleID, 1, 1, "Postfix: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 3: Configuration Status
	if configPath, ok := results["Config Path"]; ok && configPath != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Configuration file: %s", configPath), scan.InfoRecommendation, "", 1)
	}

	// Section 4: TLS Configuration
	if tlsEnabled, ok := results["TLS Enabled"]; ok {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("TLS enabled: %s", tlsEnabled), scan.InfoRecommendation, "", 2)
	}

	// Section 5: Certificate Information
	if certPath, ok := results["Certificate Path"]; ok && certPath != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Certificate path: %s", certPath), scan.InfoRecommendation, "", 2)
	}

	// Section 6: Key Information
	if keyPath, ok := results["Key Path"]; ok && keyPath != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("Key path: %s", keyPath), scan.InfoRecommendation, "", 2)
	}

	// Section 7: Protocol Information
	if protocols, ok := results["Protocols"]; ok && protocols != "" {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("Protocols: %s", protocols), scan.InfoRecommendation, "", 2)
	}

	// Section 8: Cipher Information
	if ciphers, ok := results["Ciphers"]; ok && ciphers != "" {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("Ciphers: %s", ciphers), scan.InfoRecommendation, "", 2)
	}

	// Section 9: PQC Support (only report if Postfix is installed)
	if installed == "Yes" {
		if pqcSupport, ok := results["PQC Support"]; ok {
			rm.AddStatus(moduleID, 9, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
		}
	}

	// Section 10: AWS Load Balancer Status (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok {
		awsItemID := 1
		
		// AWS Environment
		rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS Environment: %s", awsEnv), scan.InfoRecommendation, "Mail server running in AWS environment with potential load balancer crypto termination", 1)
		awsItemID++
		
		// EC2 Instance ID
		if instanceID, ok := results["EC2 Instance ID"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "EC2 instance identifier for load balancer association", 1)
			awsItemID++
		}
		
		// Load Balancer Type
		if lbType, ok := results["LB Type"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Type: %s", lbType), scan.InfoRecommendation, "Type of AWS load balancer handling mail traffic", 1)
			awsItemID++
		}
		
		// Load Balancer Name
		if lbName, ok := results["LB Name"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Name: %s", lbName), scan.InfoRecommendation, "AWS load balancer name handling mail services", 1)
			awsItemID++
		}
		
		// Mail Ports
		if mailPorts, ok := results["LB Mail Ports"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Mail Ports: %s", mailPorts), scan.InfoRecommendation, "Mail service ports configured on load balancer (SMTP: 25,587,465, IMAP: 993, POP3: 995)", 1)
			awsItemID++
		}
		
		// SSL Policy
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL/TLS policy used by load balancer for mail traffic encryption", 1)
			awsItemID++
		}
		
		// SSL Context
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy applies to mail service encryption and authentication", 1)
			awsItemID++
		}
		
		// PQC Readiness
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			} else {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: N/A", scan.InfoRecommendation, "No SSL termination at load balancer for mail services", 1)
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
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary mail service port on load balancer", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

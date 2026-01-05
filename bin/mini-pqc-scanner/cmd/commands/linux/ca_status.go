package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateCAStatus creates structured status items from CA scan results
func generateCAStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for CA command
	moduleID := scan.CommandModules["testca"] // Should be 11

	// Section 1: OpenSSL Status
	if openssl, ok := results["OpenSSL"]; ok {
		if openssl == "Installed" {
			if version, ok := results["OpenSSL Version"]; ok && version != "" {
				// Merge installation status and version into one message
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("OpenSSL: Installed (Version: %s)", version), scan.InfoRecommendation, "", 1)
			} else {
				// Just show installation status if version is not available
				rm.AddStatus(moduleID, 1, 1, "OpenSSL: Installed", scan.InfoRecommendation, "", 1)
			}
		} else {
			rm.AddStatus(moduleID, 1, 1, "OpenSSL: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 2: EasyRSA Status
	if easyrsa, ok := results["EasyRSA"]; ok {
		if easyrsa == "Installed" {
			if version, ok := results["EasyRSA Version"]; ok && version != "" {
				// Merge installation status and version into one message
				rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("EasyRSA: Installed (Version: %s)", version), scan.InfoRecommendation, "", 1)
			} else {
				// Just show installation status if version is not available
				rm.AddStatus(moduleID, 2, 1, "EasyRSA: Installed", scan.InfoRecommendation, "", 1)
			}
		} else {
			rm.AddStatus(moduleID, 2, 1, "EasyRSA: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 3: CFSSL Status
	if cfssl, ok := results["CFSSL"]; ok {
		if cfssl == "Installed" {
			if version, ok := results["CFSSL Version"]; ok && version != "" {
				// Merge installation status and version into one message
				rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("CFSSL: Installed (Version: %s)", version), scan.InfoRecommendation, "", 1)
			} else {
				// Just show installation status if version is not available
				rm.AddStatus(moduleID, 3, 1, "CFSSL: Installed", scan.InfoRecommendation, "", 1)
			}
		} else {
			rm.AddStatus(moduleID, 3, 1, "CFSSL: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 4: System CA Certificates
	if systemCerts, ok := results["System CA Certificates"]; ok && systemCerts != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("System CA certificates: %s", systemCerts), scan.InfoRecommendation, "", 1)
	}

	// Section 5: Custom CA Certificates
	if customCerts, ok := results["Custom CA Certificates"]; ok && customCerts != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Custom CA certificates: %s", customCerts), scan.InfoRecommendation, "", 1)
	}

	// Section 6: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok && pqcSupport != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 7: OQS Provider Status
	if oqsStatus, ok := results["OQS Provider"]; ok && oqsStatus != "" {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("OQS provider: %s", oqsStatus), scan.InfoRecommendation, "", 2)
	}

	// Section 8: Certificate Algorithm Types
	if certAlgos, ok := results["Certificate Algorithms"]; ok && certAlgos != "" {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("Certificate algorithms: %s", certAlgos), scan.InfoRecommendation, "", 2)
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Classic Load Balancer: %s", clb), scan.InfoRecommendation, "Classic Load Balancer discovered (internet-facing CA services)", 1)
			awsItemID++
		}
		if alb, ok := results["Application Load Balancer"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Application Load Balancer: %s", alb), scan.InfoRecommendation, "Application/Network Load Balancer discovered (internet-facing CA services)", 1)
			awsItemID++
		}
		
		// Load Balancer ARN
		if lbArn, ok := results["Load Balancer ARN"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Load Balancer ARN: %s", lbArn), scan.InfoRecommendation, "ARN used for querying actual internet-facing SSL/TLS configuration", 1)
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
		
		// CA Context
		if caContext, ok := results["LB CA Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB CA Context: %s", caContext), scan.InfoRecommendation, "How CA services are handled in relation to load balancer", 1)
			awsItemID++
		}
		
		// HTTPS Listeners
		if httpsListeners, ok := results["LB HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB HTTPS Listeners: %s", httpsListeners), scan.InfoRecommendation, "HTTPS listeners for CA web interfaces and certificate distribution", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "AWS-managed SSL policy determining cipher suites and protocols for CA services", 1)
			awsItemID++
		}
		
		// SSL Context
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy applies to CA web interfaces and certificate distribution", 1)
			awsItemID++
		}
		
		// PQC Readiness
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: N/A", scan.InfoRecommendation, "No SSL termination at load balancer for CA services", 1)
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary HTTPS port on load balancer for CA services", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

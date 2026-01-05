package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateTLSStatus creates structured status items from TLS scan results
func generateTLSStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for TLS command
	moduleID := scan.CommandModules["testtls"] // Should be 13

	// Section 1: TLS Library Status
	if tlsLib, ok := results["TLS Library"]; ok {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("TLS library: %s", tlsLib), scan.InfoRecommendation, "", 1)
	}

	// Section 2: OpenSSL Version
	if version, ok := results["OpenSSL Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("OpenSSL version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 3: LibreSSL Version
	if version, ok := results["LibreSSL Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("LibreSSL version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 4: BoringSSL Version
	if version, ok := results["BoringSSL Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("BoringSSL version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 5: GnuTLS Version
	if version, ok := results["GnuTLS Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("GnuTLS version: %s", version), scan.InfoRecommendation, "", 1)
	}

	// Section 6: OQS Provider Status
	if oqsStatus, ok := results["OQS Provider"]; ok && oqsStatus != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("OQS provider: %s", oqsStatus), scan.InfoRecommendation, "", 2)
	}

	// Section 7: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 8: Supported Algorithms
	if algorithms, ok := results["Supported Algorithms"]; ok && algorithms != "" {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("Supported algorithms: %s", algorithms), scan.InfoRecommendation, "", 2)
	}

	// Section 9: AWS Load Balancer Context (if in AWS environment)
	awsItemID := 1
	if _, ok := results["AWS Environment"]; ok {
		// Domain being tested
		if domain, ok := results["Domain"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Domain Tested: %s", domain), scan.InfoRecommendation, "Domain tested for TLS configuration from AWS environment", 1)
			awsItemID++
		}
		
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Classic Load Balancer: %s", clb), scan.InfoRecommendation, "Classic Load Balancer discovered (internet-facing crypto configuration)", 1)
			awsItemID++
		}
		if alb, ok := results["Application Load Balancer"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Application Load Balancer: %s", alb), scan.InfoRecommendation, "Application/Network Load Balancer discovered (internet-facing crypto configuration)", 1)
			awsItemID++
		}
		
		// Load Balancer ARN
		if lbArn, ok := results["Load Balancer ARN"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("Load Balancer ARN: %s", lbArn), scan.InfoRecommendation, "ARN used for querying actual internet-facing SSL/TLS configuration", 1)
			awsItemID++
		}
		
		// SSL Policy Analysis
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "AWS-managed SSL policy determining cipher suites and protocols for internet traffic", 1)
			awsItemID++
		}
		
		// PQC Readiness
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else {
				rm.AddStatus(moduleID, 9, awsItemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			}
			awsItemID++
		}
		
		// HTTPS Listeners
		if httpsListeners, ok := results["LB HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB HTTPS Listeners: %s", httpsListeners), scan.InfoRecommendation, "HTTPS listeners on load balancer (internet-facing SSL termination)", 1)
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
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary HTTPS port on load balancer for internet-facing connections", 1)
			awsItemID++
		}
		
		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 9, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
		
		// Context note
		rm.AddStatus(moduleID, 9, awsItemID, "Load Balancer Context: TLS results reflect internet-facing configuration", scan.InfoRecommendation, "If domain is served through AWS Load Balancer, results show load balancer SSL/TLS termination", 1)
		awsItemID++
	}
}

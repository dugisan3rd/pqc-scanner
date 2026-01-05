package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateApacheStatus creates structured status items from apache scan results
func generateApacheStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for apache command
	moduleID := scan.CommandModules["testapache"] // Should be 15

	// Section 1: Apache Installation Status
	if installed, ok := results["Apache Installed"]; ok {
		if installed != "No" {
			rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Apache: %s", installed), scan.InfoRecommendation, "", 3)
		} else {
			rm.AddStatus(moduleID, 1, 1, "Apache: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 2: Apache Version
	if version, ok := results["Apache"]; ok && version != "" && version != "Not installed" {
		// Extract just the version part if it contains full version output
		versionText := version
		if strings.Contains(version, "Server version:") {
			// Parse Apache version output like "Server version: Apache/2.4.62 (Debian)"
			lines := strings.Split(version, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Server version:") {
					versionText = strings.TrimSpace(strings.TrimPrefix(line, "Server version:"))
					break
				}
			}
		}
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("Apache version: %s", versionText), scan.InfoRecommendation, "", 1)
	}

	// Section 3: OpenSSL Information
	if version, ok := results["OpenSSL Version"]; ok && version != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("OpenSSL version: %s", version), scan.WarningRecommendation, "", 4)
	}

	// Section 4: Configuration Information
	if confPath, ok := results["Config Path"]; ok && confPath != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("Configuration file: %s", confPath), scan.InfoRecommendation, "", 1)
	}

	// Section 5: SSL Configuration
	if sslEnabled, ok := results["SSL Enabled"]; ok {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("SSL enabled: %s", sslEnabled), scan.InfoRecommendation, "", 2)

		if ciphers, ok := results["SSL Ciphers"]; ok && ciphers != "" {
			rm.AddStatus(moduleID, 5, 2, fmt.Sprintf("Configured ciphers: %s", ciphers), scan.InfoRecommendation, "", 2)
		}

		if protocols, ok := results["SSL Protocols"]; ok && protocols != "" {
			rm.AddStatus(moduleID, 5, 3, fmt.Sprintf("Configured protocols: %s", protocols), scan.InfoRecommendation, "", 2)
		}
	}

	// Section 6: PQC Support
	if pqcSupport, ok := results["PQC Support"]; ok {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("PQC support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Add Kyber KEM Support status
	if kyberSupport, ok := results["Kyber KEM Support"]; ok {
		rm.AddStatus(moduleID, 6, 2, fmt.Sprintf("Kyber KEM support: %s", kyberSupport), scan.InfoRecommendation, "", 2)
	}

	// Add Hybrid Groups Support status
	if hybridSupport, ok := results["Hybrid Groups Support"]; ok {
		rm.AddStatus(moduleID, 6, 3, fmt.Sprintf("Hybrid Groups support: %s", hybridSupport), scan.InfoRecommendation, "", 2)
	}

	// Add TLS 1.3 Support status
	if tls13Support, ok := results["TLS 1.3"]; ok {
		rm.AddStatus(moduleID, 6, 4, fmt.Sprintf("TLS 1.3 support: %s", tls13Support), scan.InfoRecommendation, "", 2)
	}

	// Section 7: OQS Provider
	if oqsProvider, ok := results["OQS Provider"]; ok {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("OQS provider: %s", oqsProvider), scan.CriticalRecommendation, "", 5)
	}

	// Section 8: Connection Test
	if connectionTest, ok := results["Connection Test"]; ok {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("PQC connection test: %s", connectionTest), scan.InfoRecommendation, "", 2)
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
	}
}

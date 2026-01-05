package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strconv"
	"strings"
)

// isNginxVersionPQCReady checks if an Nginx version supports native PQC integration
func isNginxVersionPQCReady(version string) bool {
	// Extract version number from strings like "1.20.1" or "nginx/1.20.1"
	versionStr := version
	if strings.Contains(version, "/") {
		parts := strings.Split(version, "/")
		if len(parts) > 1 {
			versionStr = parts[1]
		}
	}
	
	// Parse version components
	parts := strings.Split(versionStr, ".")
	if len(parts) < 2 {
		return false // Invalid version format
	}
	
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	
	if err1 != nil || err2 != nil {
		return false // Invalid version format
	}
	
	// Nginx 1.25+ has better PQC integration support
	// Versions before 1.25 make PQC integration "patchy/complex"
	if major > 1 {
		return true
	}
	if major == 1 && minor >= 25 {
		return true
	}
	
	return false
}

// isOpenSSLVersionPQCReady checks if an OpenSSL version supports native ML-KEM/ML-DSA
func isOpenSSLVersionPQCReady(version string) bool {
	// Extract version number from strings like "3.2.2" or "OpenSSL 3.2.2 4 Jun 2024"
	versionStr := version
	if strings.Contains(version, "OpenSSL") {
		parts := strings.Fields(version)
		if len(parts) >= 2 {
			versionStr = parts[1]
		}
	}
	
	// Parse version components
	parts := strings.Split(versionStr, ".")
	if len(parts) < 2 {
		return false // Invalid version format
	}
	
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	
	if err1 != nil || err2 != nil {
		return false // Invalid version format
	}
	
	// OpenSSL 3.5+ has native ML-KEM/ML-DSA support for clean CNSA 2.0 path
	// Versions below 3.5 block the "clean" CNSA 2.0 path
	if major > 3 {
		return true
	}
	if major == 3 && minor >= 5 {
		return true
	}
	
	return false
}

// generateNginxStatus creates structured status items from nginx scan results
func generateNginxStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for nginx command
	moduleID := scan.CommandModules["nginx"] // Should be 5

	// Section 1: Nginx Installation Status
	if version, ok := results["Nginx"]; ok {
		if version != "Not installed" {
			// Check if version supports PQC and set appropriate severity
			if isNginxVersionPQCReady(version) {
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Nginx: %s", version), scan.InfoRecommendation, "", 1)
			} else {
				// CRITICAL severity for older versions that lack native PQC support
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Nginx: %s", version), scan.CriticalRecommendation, "Version predates native ML-KEM/ML-DSA support, making PQC integration complex and patchy", 5)
			}
		} else {
			rm.AddStatus(moduleID, 1, 1, "Nginx: Not installed", scan.InfoRecommendation, "", 1)
		}
	} else if installed, ok := results["Nginx Installed"]; ok {
		if installed != "No" {
			// Check if version supports PQC and set appropriate severity
			if isNginxVersionPQCReady(installed) {
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Nginx: %s", installed), scan.InfoRecommendation, "", 1)
			} else {
				// CRITICAL severity for older versions that lack native PQC support
				rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Nginx: %s", installed), scan.CriticalRecommendation, "Version predates native ML-KEM/ML-DSA support, making PQC integration complex and patchy", 5)
			}
		} else {
			rm.AddStatus(moduleID, 1, 1, "Nginx: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 2: OpenSSL Information
	if version, ok := results["OpenSSL Version"]; ok {
		// Check if OpenSSL version supports native ML-KEM/ML-DSA and set appropriate severity
		if isOpenSSLVersionPQCReady(version) {
			rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("OpenSSL version: %s", version), scan.InfoRecommendation, "", 1)
		} else {
			// HIGH severity for versions below 3.5 that block clean CNSA 2.0 path
			rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("OpenSSL version: %s", version), scan.WarningRecommendation, "Version below 3.5+ blocks clean CNSA 2.0 path for native ML-KEM/ML-DSA support", 4)
		}
		
		if path, ok := results["OpenSSL Path"]; ok && path != "" {
			rm.AddStatus(moduleID, 2, 2, fmt.Sprintf("OpenSSL path: %s", path), scan.InfoRecommendation, "", 1)
		}
	}

	// Section 3: Configuration Information
	if confPath, ok := results["Nginx Config"]; ok {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Configuration file: %s", confPath), scan.InfoRecommendation, "", 0)
	}

	// Add Include Directory information
	if includeDir, ok := results["Include Directory"]; ok && includeDir != "" {
		rm.AddStatus(moduleID, 3, 2, fmt.Sprintf("Include directory: %s", includeDir), scan.InfoRecommendation, "", 1)
	}

	// Section 4: SSL Configuration
	if sslEnabled, ok := results["SSL Enabled"]; ok {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("SSL enabled: %s", sslEnabled), scan.InfoRecommendation, "", 2)
		
		if ciphers, ok := results["SSL Ciphers"]; ok && ciphers != "" {
			rm.AddStatus(moduleID, 4, 2, fmt.Sprintf("Configured ciphers: %s", ciphers), scan.InfoRecommendation, "", 2)
		}
		
		if protocols, ok := results["SSL Protocols"]; ok && protocols != "" {
			rm.AddStatus(moduleID, 4, 3, fmt.Sprintf("Configured protocols: %s", protocols), scan.InfoRecommendation, "", 2)
		}
	}
	
	// Add PQC Ciphers information
	if pqcCiphers, ok := results["PQC Ciphers"]; ok {
		rm.AddStatus(moduleID, 4, 4, fmt.Sprintf("PQC ciphers: %s", pqcCiphers), scan.InfoRecommendation, "", 2)
	}

	// Section 5: TLS Support
	itemID := 1
	
	// Show all configured SSL/TLS protocols
	if protocols, ok := results["SSL Protocols"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("SSL/TLS protocols: %s", protocols), scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	// Show specific TLS version status
	if tls13, ok := results["TLS 1.3"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("TLS 1.3: %s", tls13), scan.InfoRecommendation, "", 0)
		itemID++
	}
	
	if tls12, ok := results["TLS 1.2"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("TLS 1.2: %s", tls12), scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	if tls11, ok := results["TLS 1.1"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("TLS 1.1: %s", tls11), scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	if tls10, ok := results["TLS 1.0"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("TLS 1.0: %s", tls10), scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	if ssl30, ok := results["SSL 3.0"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("SSL 3.0: %s", ssl30), scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	if ssl20, ok := results["SSL 2.0"]; ok {
		rm.AddStatus(moduleID, 5, itemID, fmt.Sprintf("SSL 2.0: %s", ssl20), scan.InfoRecommendation, "", 1)
		itemID++
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

	// Add Kyber in Includes status
	if kyberIncludes, ok := results["Kyber in Includes"]; ok {
		rm.AddStatus(moduleID, 6, 4, fmt.Sprintf("Kyber in included files: %s", kyberIncludes), scan.InfoRecommendation, "", 2)
	}

	// Add Hybrid in Includes status
	if hybridIncludes, ok := results["Hybrid in Includes"]; ok {
		rm.AddStatus(moduleID, 6, 5, fmt.Sprintf("Hybrid in included files: %s", hybridIncludes), scan.InfoRecommendation, "", 2)
	}

	// Section 7: OQS Provider
	if oqsProvider, ok := results["OQS Provider"]; ok {
		if oqsProvider == "Not found" {
			// HIGH severity when OQS provider is not found - critical for PQC support
			rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("OQS provider: %s", oqsProvider), scan.WarningRecommendation, "OQS provider is required for PQC algorithm support in OpenSSL", 4)
		} else {
			rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("OQS provider: %s", oqsProvider), scan.InfoRecommendation, "", 2)
		}
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

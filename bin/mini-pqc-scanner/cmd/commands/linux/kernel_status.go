package linux

import (
	"fmt"
	"mini-pqc/scan"
	"sort"
	"strings"
)

// generateKernelStatus creates structured status items from kernel scan results
func generateKernelStatus(kernelVersion string, pqcSupport bool, secureCount, insecureCount, pqcRelevantCount int,
	secureParams, insecureParams, pqcRelevantParams map[string]KernelParam,
	cryptoAlgos map[string]CryptoAlgorithm, pqcCompliantCount, cnsaApprovedCount, quantumVulnerableCount, nonPQCCompliantCount int,
	rm *scan.RecommendationManager) {
	// Module ID for kernel command
	moduleID := scan.CommandModules["kernel"] // Should be 3

	// Section 1: Kernel Version
	if kernelVersion != "" {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Kernel Version: %s", kernelVersion), scan.InfoRecommendation, "", 1)
	}

	// Section 2: PQC Support
	if pqcSupport {
		rm.AddStatus(moduleID, 2, 1, "PQC Support: Available", scan.InfoRecommendation, "", 2)
	} else {
		rm.AddStatus(moduleID, 2, 1, "PQC Support: Not available", scan.InfoRecommendation, "", 2)
	}

	// Section 3: Security Parameters
	// Display secure parameter count and names
	secureParamNames := make([]string, 0, len(secureParams))
	for name := range secureParams {
		secureParamNames = append(secureParamNames, name)
	}

	// Sort parameter names for consistent output
	sort.Strings(secureParamNames)

	secureParamsInfo := fmt.Sprintf("Secure Parameters: %d", secureCount)

	// Create details with the parameter names
	detailsInfo := ""
	if len(secureParamNames) > 0 {
		detailsInfo = strings.Join(secureParamNames, ", ")
	}
	rm.AddStatus(moduleID, 3, 1, secureParamsInfo, scan.InfoRecommendation, detailsInfo, 2)

	// Display insecure parameter count and names
	insecureParamNames := make([]string, 0, len(insecureParams))
	for name := range insecureParams {
		insecureParamNames = append(insecureParamNames, name)
	}

	// Sort parameter names for consistent output
	sort.Strings(insecureParamNames)

	insecureParamsInfo := fmt.Sprintf("Insecure Parameters: %d", insecureCount)

	// Create details with the parameter names
	insecureDetailsInfo := ""
	if len(insecureParamNames) > 0 {
		insecureDetailsInfo = strings.Join(insecureParamNames, ", ")
	}
	rm.AddStatus(moduleID, 3, 2, insecureParamsInfo, scan.WarningRecommendation, insecureDetailsInfo, 3)

	// Section 4: PQC Relevant Parameters
	// Display PQC relevant parameter count and names
	pqcRelevantParamNames := make([]string, 0, len(pqcRelevantParams))
	for name := range pqcRelevantParams {
		pqcRelevantParamNames = append(pqcRelevantParamNames, name)
	}

	// Sort parameter names for consistent output
	sort.Strings(pqcRelevantParamNames)

	pqcParamsInfo := fmt.Sprintf("PQC Relevant Parameters: %d", pqcRelevantCount)

	// Create details with the parameter names
	pqcDetailsInfo := ""
	if len(pqcRelevantParamNames) > 0 {
		pqcDetailsInfo = strings.Join(pqcRelevantParamNames, ", ")
	}
	rm.AddStatus(moduleID, 4, 1, pqcParamsInfo, scan.InfoRecommendation, pqcDetailsInfo, 2)

	// Section 5: Crypto Algorithms
	// Display PQC-compliant algorithms (post-quantum)
	pqcAlgoInfo := fmt.Sprintf("PQC-Compliant Algorithms: %d", pqcCompliantCount)

	// Create details with PQC-compliant algorithm names
	pqcAlgoNames := make([]string, 0)
	for name, algo := range cryptoAlgos {
		if algo.PQCStatus == "compliant" {
			pqcAlgoNames = append(pqcAlgoNames, name)
		}
	}

	// Sort algorithm names for consistent output
	sort.Strings(pqcAlgoNames)

	pqcAlgoDetailsInfo := ""
	if len(pqcAlgoNames) > 0 {
		pqcAlgoDetailsInfo = strings.Join(pqcAlgoNames, ", ")
	}
	rm.AddStatus(moduleID, 5, 1, pqcAlgoInfo, scan.InfoRecommendation, pqcAlgoDetailsInfo, 2)

	// Display CNSA-2.0 approved symmetric/hash algorithms (quantum-safe enough)
	cnsaAlgoInfo := fmt.Sprintf("CNSA-2.0 Approved Algorithms: %d", cnsaApprovedCount)

	// Create details with CNSA-approved algorithm names
	cnsaAlgoNames := make([]string, 0)
	for name, algo := range cryptoAlgos {
		if algo.PQCStatus == "cnsa-approved" {
			cnsaAlgoNames = append(cnsaAlgoNames, name)
		}
	}

	// Sort algorithm names for consistent output
	sort.Strings(cnsaAlgoNames)

	cnsaAlgoDetailsInfo := ""
	if len(cnsaAlgoNames) > 0 {
		cnsaAlgoDetailsInfo = strings.Join(cnsaAlgoNames, ", ")
	}
	rm.AddStatus(moduleID, 5, 2, cnsaAlgoInfo, scan.InfoRecommendation, cnsaAlgoDetailsInfo, 2)

	// Display quantum-vulnerable asymmetric algorithms (need migration)
	vulnAlgoInfo := fmt.Sprintf("Quantum-Vulnerable Algorithms: %d", quantumVulnerableCount)

	// Create details with quantum-vulnerable algorithm names
	vulnAlgoNames := make([]string, 0)
	for name, algo := range cryptoAlgos {
		if algo.PQCStatus == "quantum-vulnerable" {
			vulnAlgoNames = append(vulnAlgoNames, name)
		}
	}

	// Sort algorithm names for consistent output
	sort.Strings(vulnAlgoNames)

	vulnAlgoDetailsInfo := ""
	if len(vulnAlgoNames) > 0 {
		vulnAlgoDetailsInfo = strings.Join(vulnAlgoNames, ", ")
	}
	rm.AddStatus(moduleID, 5, 3, vulnAlgoInfo, scan.WarningRecommendation, vulnAlgoDetailsInfo, 3)

	// Display other unclassified algorithms
	if nonPQCCompliantCount > 0 {
		otherAlgoInfo := fmt.Sprintf("Other Algorithms: %d", nonPQCCompliantCount)

		// Create details with other algorithm names
		otherAlgoNames := make([]string, 0)
		for name, algo := range cryptoAlgos {
			if algo.PQCStatus == "non-compliant" {
				otherAlgoNames = append(otherAlgoNames, name)
			}
		}

		// Sort algorithm names for consistent output
		sort.Strings(otherAlgoNames)

		otherAlgoDetailsInfo := ""
		if len(otherAlgoNames) > 0 {
			otherAlgoDetailsInfo = strings.Join(otherAlgoNames, ", ")
		}
		rm.AddStatus(moduleID, 5, 4, otherAlgoInfo, scan.InfoRecommendation, otherAlgoDetailsInfo, 2)
	}
}

// generateKernelAWSStatus creates AWS load balancer status items for kernel command
func generateKernelAWSStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for kernel command
	moduleID := scan.CommandModules["kernel"] // Should be 3

	// Section 10: AWS Load Balancer Status (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok {
		awsItemID := 1

		// AWS Environment
		rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS Environment: %s", awsEnv), scan.InfoRecommendation, "Kernel crypto analysis running in AWS environment with potential load balancer crypto termination", 1)
		awsItemID++

		// EC2 Instance ID
		if instanceID, ok := results["EC2 Instance ID"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "EC2 instance identifier for load balancer association", 1)
			awsItemID++
		}

		// Load Balancer Type
		if lbType, ok := results["LB Type"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Type: %s", lbType), scan.InfoRecommendation, "Type of AWS load balancer handling internet-facing crypto operations", 1)
			awsItemID++
		}

		// Load Balancer Name
		if lbName, ok := results["LB Name"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Name: %s", lbName), scan.InfoRecommendation, "AWS load balancer name handling crypto operations", 1)
			awsItemID++
		}

		// All Ports
		if allPorts, ok := results["LB All Ports"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB All Ports: %s", allPorts), scan.InfoRecommendation, "All service ports configured on load balancer", 1)
			awsItemID++
		}

		// SSL Port Count
		if sslPortCount, ok := results["LB SSL Port Count"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Port Count: %s", sslPortCount), scan.InfoRecommendation, "Number of SSL/TLS encrypted ports on load balancer", 1)
			awsItemID++
		}

		// SSL Policy
		if sslPolicy, ok := results["LB SSL Policy"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "SSL/TLS policy used by load balancer for crypto operations", 1)
			awsItemID++
		}

		// SSL Context
		if sslContext, ok := results["LB SSL Context"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB SSL Context: %s", sslContext), scan.InfoRecommendation, "SSL policy context for internet-facing crypto operations", 1)
			awsItemID++
		}

		// PQC Readiness
		if pqcReady, ok := results["LB PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else if pqcReady == "false" {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			} else {
				rm.AddStatus(moduleID, 10, awsItemID, "LB PQC Readiness: N/A", scan.InfoRecommendation, "No SSL termination at load balancer", 1)
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
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("LB Primary Port: %s", primaryPort), scan.InfoRecommendation, "Primary service port on load balancer", 1)
			awsItemID++
		}

		// AWS CLI Availability
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, 10, awsItemID, fmt.Sprintf("AWS CLI: %s", awsCli), scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			awsItemID++
		}
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateRuntimeStatus creates structured status items from runtime scan results
func generateRuntimeStatus(results map[string]string, rm *scan.RecommendationManager, awsResults map[string]string) {
	// Module ID for runtime command
	moduleID := scan.CommandModules["testruntime"] // Should be 10

	// Section 1: Java Runtime Status
	if javaStatus, ok := results["Java"]; ok {
		if javaStatus == "Installed" {
			// Merge Java installation and version information into a single message
			javaInfo := "Java: Installed"
			if javaVersion, ok := results["Java Version"]; ok && javaVersion != "" {
				javaInfo = fmt.Sprintf("Java: Installed, version: %s", javaVersion)
			}
			rm.AddStatus(moduleID, 1, 1, javaInfo, scan.InfoRecommendation, "", 3)
			if javaHome, ok := results["JAVA_HOME"]; ok && javaHome != "" {
				rm.AddStatus(moduleID, 1, 3, fmt.Sprintf("JAVA_HOME: %s", javaHome), scan.InfoRecommendation, "", 1)
			}
		} else {
			rm.AddStatus(moduleID, 1, 1, "Java: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 2: Java Security Configuration
	if securityFile, ok := results["Java Security File"]; ok && securityFile != "" {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("Java security file: %s", securityFile), scan.InfoRecommendation, "", 1)
	}
	
	// Section 3: Java Keystores
	if keystores, ok := results["Java Keystores"]; ok && keystores != "" {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Java keystores: %s", keystores), scan.InfoRecommendation, "", 1)
	}
	
	// Section 4: JCE Providers
	if jceProviders, ok := results["JCE Providers"]; ok && jceProviders != "" {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("JCE providers: %s", jceProviders), scan.InfoRecommendation, "", 3)
	}
	if bouncyCastle, ok := results["BouncyCastle"]; ok && bouncyCastle != "" {
		rm.AddStatus(moduleID, 4, 2, fmt.Sprintf("BouncyCastle: %s", bouncyCastle), scan.InfoRecommendation, "", 4)
	}
	
	// Section 5: Java PQC Support
	if javaPQCSupport, ok := results["Java PQC Support"]; ok && javaPQCSupport != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("Java PQC support: %s", javaPQCSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 6: Python Runtime Status
	if pythonStatus, ok := results["Python"]; ok {
		if pythonStatus == "Installed" {
			if pythonVersion, ok := results["Python Version"]; ok && pythonVersion != "" {
				rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("Python: Installed (version %s)", pythonVersion), scan.InfoRecommendation, "", 4)
			} else {
				rm.AddStatus(moduleID, 6, 1, "Python: Installed", scan.InfoRecommendation, "", 4)
			}
		} else {
			rm.AddStatus(moduleID, 6, 1, "Python: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 7: Python Crypto Modules
	if pythonCryptoModules, ok := results["Python Crypto Modules"]; ok && pythonCryptoModules != "" {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("Python crypto modules: %s", pythonCryptoModules), scan.InfoRecommendation, "", 5)
	}
	
	// Section 8: Python PQC Support
	if pythonPQCSupport, ok := results["Python PQC Support"]; ok && pythonPQCSupport != "" {
		rm.AddStatus(moduleID, 8, 1, fmt.Sprintf("Python PQC support: %s", pythonPQCSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 9: Node.js Runtime Status
	if nodeStatus, ok := results["Node.js"]; ok {
		if nodeStatus == "Installed" {
			if nodeVersion, ok := results["Node.js Version"]; ok && nodeVersion != "" {
				rm.AddStatus(moduleID, 9, 1, fmt.Sprintf("Node.js: Installed (version %s)", nodeVersion), scan.InfoRecommendation, "", 4)
			} else {
				rm.AddStatus(moduleID, 9, 1, "Node.js: Installed", scan.InfoRecommendation, "", 4)
			}
		} else {
			rm.AddStatus(moduleID, 9, 1, "Node.js: Not installed", scan.InfoRecommendation, "", 1)
		}
	}

	// Section 10: Node.js Crypto Modules
	if nodeCryptoModules, ok := results["Node.js Crypto Modules"]; ok && nodeCryptoModules != "" {
		rm.AddStatus(moduleID, 10, 1, fmt.Sprintf("Node.js crypto modules: %s", nodeCryptoModules), scan.InfoRecommendation, "", 1)
	}
	
	// Section 11: Node.js PQC Support
	if nodePQCSupport, ok := results["Node.js PQC Support"]; ok && nodePQCSupport != "" {
		rm.AddStatus(moduleID, 11, 1, fmt.Sprintf("Node.js PQC support: %s", nodePQCSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 12: AWS Load Balancer Status (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok {
		awsItemID := 1
		rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("AWS Environment: %s", awsEnv), scan.InfoRecommendation, "Runtime environment running in AWS environment with potential load balancer crypto termination", 1)
		awsItemID++

		if instanceID, ok := awsResults["AWS Instance ID"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "EC2 instance identifier for load balancer association analysis", 1)
			awsItemID++
		}

		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("Load Balancer Type: %s", lbType), scan.InfoRecommendation, "Type of AWS load balancer handling runtime traffic", 1)
			awsItemID++
		}

		if lbName, ok := awsResults["Load Balancer Name"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("Load Balancer Name: %s", lbName), scan.InfoRecommendation, "AWS load balancer name for runtime traffic management", 1)
			awsItemID++
		}

		if runtimePorts, ok := awsResults["Runtime Ports"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("Runtime Ports: %s", runtimePorts), scan.InfoRecommendation, "Load balancer ports serving runtime application traffic", 1)
			awsItemID++
		}

		if sslPolicy, ok := awsResults["SSL Policy"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("SSL Policy: %s", sslPolicy), scan.InfoRecommendation, "Load balancer SSL/TLS policy for runtime crypto termination", 1)
			awsItemID++
		}

		if protocols, ok := awsResults["TLS Protocols"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("TLS Protocols: %s", protocols), scan.InfoRecommendation, "Supported TLS protocol versions for runtime connections", 1)
			awsItemID++
		}

		if cipherCount, ok := awsResults["Cipher Suite Count"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("Cipher Suite Count: %s", cipherCount), scan.InfoRecommendation, "Number of cipher suites available for runtime encryption", 1)
			awsItemID++
		}

		if pqcScore, ok := awsResults["PQC Readiness Score"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("PQC Readiness Score: %s", pqcScore), scan.InfoRecommendation, "Load balancer PQC readiness assessment for runtime traffic", 1)
			awsItemID++
		}

		if pqcAssessment, ok := awsResults["PQC Assessment"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("PQC Assessment: %s", pqcAssessment), scan.InfoRecommendation, "Overall assessment of load balancer PQC readiness for runtime environments", 1)
			awsItemID++
		}

		if cliStatus, ok := awsResults["AWS CLI Status"]; ok {
			rm.AddStatus(moduleID, 12, awsItemID, fmt.Sprintf("AWS CLI Status: %s", cliStatus), scan.InfoRecommendation, "AWS CLI availability for load balancer crypto inspection", 1)
		}
	}
}

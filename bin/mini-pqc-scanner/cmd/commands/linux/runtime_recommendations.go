package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateRuntimeRecommendations creates structured recommendations from runtime check results
// @TODO:
func generateRuntimeRecommendations(results map[string]string, awsResults map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testruntime"] // Should be 10

	// Generate Java recommendations
	if javaStatus, ok := results["Java"]; ok && javaStatus == "Installed" {
		// Section 1: Java Immediate Actions
		sectionID := 1

		// Check if BouncyCastle is present
		if _, ok := results["BouncyCastle"]; !ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Install BouncyCastle for experimental PQC algorithm support",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Migrate from RSA/DSA to at least EC algorithms for better security",
			Type:      scan.WarningRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    3,
			Text:      "Update to latest Java version for best cryptographic support",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})

		// Section 2: Java Future Preparation
		sectionID = 2

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "Monitor JEP (JDK Enhancement Proposals) for official PQC support",
			Type:      scan.InfoRecommendation,
			Severity:  1, // Low severity - informational
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Consider hybrid certificates with both classical and PQ algorithms",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    3,
			Text:      "Plan for migration to NIST PQC standards when Java adds native support",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Generate Python recommendations
	if pythonStatus, ok := results["Python"]; ok && pythonStatus == "Installed" {
		// Section 3: Python Immediate Actions
		sectionID := 3

		// Check if PQC modules are installed
		if pqcModules, ok := results["Python PQC Modules"]; !ok || pqcModules == "" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Install liboqs-python or other PQC modules for post-quantum algorithm support",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
		}

		// Only recommend ECC if classic crypto algorithms are detected
		if classicCrypto, ok := results["Python Classic Crypto"]; ok && classicCrypto == "Found" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Text:      "Python: Replace RSA/DSA with ECC interim; plan ML-DSA-87/ML-KEM-1024 migration",
				Type:      scan.CriticalRecommendation,
				Details: "RSA and DSA are quantum-vulnerable and must be replaced. ECC is transitional only - plan for post-quantum migration.\n\n" +
					"Immediate transition (ECC interim):\n" +
					"• Replace RSA signatures with ECDSA or Ed25519\n" +
					"• Replace DSA signatures with ECDSA or Ed25519\n" +
					"• Use P-384 curves or Ed25519 for better classical security\n\n" +
					"Post-quantum migration planning:\n" +
					"• Plan to replace ECC signatures with ML-DSA-87 when available\n" +
					"• Plan to replace ECDH key exchange with ML-KEM-1024 in TLS contexts\n" +
					"• Monitor Python 'cryptography' library for PQC algorithm support\n" +
					"• ECC is NOT quantum-safe - it is only a transitional improvement\n" +
					"While ECC is not quantum-resistant, it is a better intermediate step before adopting full post-quantum algorithms.",
				Severity: 4, // High severity - quantum-vulnerable algorithms need migration planning
			})
		}

		// Only recommend removing SHA-1 and MD5 if they are detected in APPLICATION code (not libraries)
		if classicCrypto, ok := results["Python Classic Crypto"]; ok && classicCrypto == "Found" {
			// Build location information for application code findings
			locationInfo := ""
			if locs, ok := results["Python Classic Crypto Locations"]; ok && locs != "" {
				files := strings.Split(locs, ", ")
				locationInfo = "\nDetected in application code:\n"
				for _, f := range files {
					locationInfo += " • " + f + "\n"
				}
			}
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    3,
				Text:      "Python: Remove MD5/SHA-1 from application code - broken regardless of PQC",
				Type:      scan.CriticalRecommendation,
				Details: "MD5 and SHA-1 usage detected in application code. These algorithms are cryptographically broken and must be removed immediately, regardless of post-quantum cryptography concerns.\n\n" +
					"Critical security issues:\n" +
					"• MD5 is completely broken with known collision attacks since 2004\n" +
					"• SHA-1 has been practically broken since 2017 with demonstrated collision attacks\n" +
					"• Both algorithms are unsuitable for any security context\n\n" +
					"Immediate replacements:\n" +
					"• Use SHA-256, SHA-384, or SHA-3 for general hashing needs\n" +
					"• For password hashing, use Argon2, bcrypt, or PBKDF2\n" +
					"• In Python, use 'hashlib' module for SHA-256/SHA-3 or 'passlib' for password hashing\n\n" +
					"Example replacement in Python:\n" +
					"```python\n" +
					"# Remove immediately:\n" +
					"# hashlib.md5(data).hexdigest()  # BROKEN\n" +
					"# hashlib.sha1(data).hexdigest()  # BROKEN\n\n" +
					"# Use instead:\n" +
					"import hashlib\n" +
					"hashlib.sha256(data).hexdigest()  # Secure\n" +
					"```" +
					locationInfo,
				Severity: 5, // Very High severity - broken crypto must be removed immediately
			})
		}
		
		// Report library references separately as informational (not critical)
		if libraryRefs, ok := results["Python Library Crypto References"]; ok && libraryRefs == "Found" {
			// Build location information for library references
			libraryLocationInfo := ""
			if locs, ok := results["Python Library Crypto Reference Locations"]; ok && locs != "" {
				files := strings.Split(locs, ", ")
				libraryLocationInfo = "\nLibrary references found in:\n"
				for _, f := range files {
					libraryLocationInfo += " • " + f + "\n"
				}
			}
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    4,
				Text:      "Python: MD5/SHA-1 references found in system libraries (informational)",
				Type:      scan.InfoRecommendation,
				Details: "MD5 and SHA-1 references were detected in Python system libraries. This is typically expected behavior and does not require immediate action.\n\n" +
					"Context:\n" +
					"• System libraries often contain legacy algorithm support for compatibility\n" +
					"• These references may be in documentation, version strings, or fallback code\n" +
					"• No action required unless your application code explicitly uses these algorithms\n\n" +
					"Monitoring recommendations:\n" +
					"• Ensure your application code uses secure alternatives (SHA-256, SHA-3, etc.)\n" +
					"• Consider library updates if security patches are available\n" +
					"• Review application dependencies for unnecessary legacy crypto usage" +
					libraryLocationInfo,
				Severity: 1, // Low severity - informational only
			})
		}

		// Section 4: Python Future Preparation
		sectionID = 4

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "Monitor PEPs (Python Enhancement Proposals) for official PQC support",
			Type:      scan.InfoRecommendation,
			Severity:  1, // Low severity - informational
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Python: Consider hybrid approaches combining classical and PQ algorithms",
			Type:      scan.InfoRecommendation,
			Details:   "Hybrid (or composite) cryptography uses both a classical and a post-quantum primitive together so that the connection remains secure even if either one is broken in the future.  For CNSA 2.0 compliance, combine X25519 (ECDH) with ML-KEM-1024 for key-exchange, or use ML-DSA-87 signatures with Ed25519.  Major TLS libraries such as OpenSSL 3.5+, BoringSSL and wolfSSL have support for these hybrid groups (OpenSSL 3.5+: X25519MLKEM1024; legacy OQS naming: x25519_mlkem1024).  In Python you can experiment today using `pyca/cryptography` built against an OpenSSL that includes native ML-KEM-1024 support:\n\n• Generate a CNSA-aligned hybrid private key:\n```python\nfrom cryptography.hazmat.primitives.asymmetric import x25519\nfrom oqs import KeyEncapsulation\n# classical key\nklass = x25519.X25519PrivateKey.generate()\n# pqc key (CNSA 2.0 target)\npqc   = KeyEncapsulation('ML-KEM-1024').generate_keypair()\n```\n• When standards mature you will be able to negotiate these hybrids transparently in TLS 1.3 handshakes.  Planning for CNSA-aligned hybrids now lets you keep backward compatibility with legacy clients while adding PQ security head-room.",
			Severity:  2, // Low-medium severity – informational but important for transition planning
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    3,
			Text:      "Plan for migration to NIST PQC standards when Python crypto libraries add support",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Generate Node.js recommendations
	if nodeStatus, ok := results["Node.js"]; ok && nodeStatus == "Installed" {
		// Section 5: Node.js Immediate Actions
		sectionID := 5

		// Only make this recommendation if classic crypto is detected in Node.js code
		if nodeCrypto, ok := results["Node.js Classic Crypto"]; ok && nodeCrypto == "Found" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Node.js: Replace RSA/DSA with ECC interim; plan ML-DSA-87/ML-KEM-1024 migration",
				Type:      scan.CriticalRecommendation,
				Details: "RSA, DSA, and ECDSA are quantum-vulnerable. ECC is transitional only - plan for post-quantum migration.\n\n" +
					"Immediate transition (ECC interim):\n" +
					"• Replace RSA/DSA with Ed25519 or ECDSA P-384 for better classical security\n" +
					"• Use Node.js 'crypto' module with modern curves (Ed25519, P-384)\n" +
					"• Avoid RSA/DSA in new code development\n\n" +
					"Post-quantum migration planning:\n" +
					"• Plan to replace ECC signatures with ML-DSA-87 when Node.js supports it\n" +
					"• Plan to replace ECDH key exchange with ML-KEM-1024 in TLS contexts\n" +
					"• Monitor Node.js crypto module updates for PQC algorithm support\n" +
					"• ECC is NOT quantum-safe - it is only a transitional improvement\n" +
					"• Older versions of libraries like 'node-forge', 'jsrsasign', or 'crypto-js' that don't support modern algorithms\n\n" +
					"Recommended alternatives:\n" +
					"• Use 'node-oqs' (Open Quantum Safe) for post-quantum cryptography\n" +
					"• Consider 'libsodium.js' or 'tweetnacl.js' for modern, high-security cryptography\n" +
					"• If you must use the built-in crypto module, prefer Ed25519 over ECDSA when possible\n\n" +
					"Example replacement in Node.js:\n" +
					"```javascript\n" +
					"// Instead of:\n" +
					"// const crypto = require('crypto');\n" +
					"// const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {\n" +
					"//   modulusLength: 2048,\n" +
					"// });\n\n" +
					"// Use libsodium.js for modern cryptography:\n" +
					"const sodium = require('libsodium-wrappers');\n" +
					"await sodium.ready;\n" +
					"const keyPair = sodium.crypto_sign_keypair();\n" +
					"```\n\n" +
					"For post-quantum options:\n" +
					"```javascript\n" +
					"// Using node-oqs for post-quantum cryptography:\n" +
					"const oqs = require('node-oqs');\n" +
					"const sig = new oqs.Signature('Dilithium2');\n" +
					"const keyPair = sig.keypair();\n" +
					"```",
				Severity: 3, // Medium severity - important for PQC readiness
			})
		} else {
			// If no classic crypto is detected, still provide informational guidance
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Node.js: Transition to ECC interim; plan ML-DSA-87/ML-KEM-1024 migration",
				Type:      scan.WarningRecommendation,
				Details: "For new Node.js code, prefer modern cryptographic libraries that offer better security and potential quantum resistance.\n\n" +
					"Recommended libraries:\n" +
					"• 'node-oqs' (Open Quantum Safe) for post-quantum cryptography\n" +
					"• 'libsodium.js' or 'tweetnacl.js' for modern, high-security cryptography\n" +
					"• If using the built-in crypto module, prefer Ed25519 over ECDSA when possible",
				Severity: 1, // Low severity - informational
			})
		}

		// Build list of files containing hard-coded classic crypto if captured
		locationInfoNode := ""
		if locs, ok := results["Node.js Classic Crypto Locations"]; ok && locs != "" {
			files := strings.Split(locs, ", ")
			locationInfoNode = "\nDetected in:\n"
			for _, f := range files {
				locationInfoNode += " • " + f + "\n"
			}
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Node.js: Avoid hardcoded classical crypto like crypto.createSign('RSA-SHA256')",
			Type:      scan.WarningRecommendation,
			Details:   "Hard-coding algorithm strings ties your application to specific classical algorithms and makes migration to PQC or hybrid algorithms difficult." + locationInfoNode,
			Severity:  3, // Medium severity - important for PQC readiness
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    3,
			Text:      "Monitor npm for PQC-capable libraries (e.g., @openpgp/js)",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})

		// Section 6: Node.js Future Preparation
		sectionID = 6

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "Watch for Node.js and npm ecosystem PQC support",
			Type:      scan.InfoRecommendation,
			Severity:  1, // Low severity - informational
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Plan for migration to NIST PQC standards when available",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Section 7: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID := 7
		itemID := 1

		// Runtime environment and AWS load balancer coordination
		if _, ok := awsResults["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate runtime crypto libraries with AWS load balancer configurations",
				Type:      scan.InfoRecommendation,
				Details:   "Your runtime environments (Java, Python, Node.js) operate behind an AWS load balancer. Consider these coordination strategies:\n\n" +
					"• Runtime crypto libraries handle application-level encryption and internal service communication\n" +
					"• AWS load balancer manages internet-facing TLS termination and traffic distribution\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND update runtime crypto libraries\n" +
					"• Runtime PQC libraries (BouncyCastle, cryptography, Node crypto) should be updated independently\n" +
					"• Monitor both AWS security updates and runtime ecosystem PQC library availability\n" +
					"• Consider runtime-specific AWS integrations (AWS SDK crypto, KMS client libraries)\n\n" +
					"This coordinated approach ensures end-to-end cryptographic security from network edge to application runtime.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific runtime deployment considerations
		if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy alongside runtime crypto library improvements",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. While upgrading your runtime crypto libraries (Java BouncyCastle, Python cryptography, Node.js crypto) improves application-level security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites to complement runtime-level cryptographic improvements.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// AWS infrastructure recommendations for runtime environments
		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS infrastructure for runtime environment security and PQC readiness",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For runtime environments in AWS:\n\n" +
					"• Use AWS Systems Manager for secure runtime configuration and library management\n" +
					"• Enable AWS CloudTrail for auditing runtime crypto library changes and deployments\n" +
					"• Use AWS Secrets Manager for runtime application crypto keys and certificates\n" +
					"• Consider AWS Lambda for serverless runtime environments with managed crypto updates\n" +
					"• Implement AWS CodeDeploy for safe runtime library upgrades with rollback capability\n" +
					"• Use AWS Parameter Store for runtime crypto configuration and library version management\n" +
					"• Monitor AWS security bulletins for runtime platform and infrastructure updates\n\n" +
					"This AWS-integrated approach provides enterprise-grade runtime security with cloud-native deployment and library management.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

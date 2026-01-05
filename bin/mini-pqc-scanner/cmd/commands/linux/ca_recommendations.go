package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateCARecommendations creates structured recommendations from CA check results
func generateCARecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testca"] // Should be 3

	// Section 1: Installation Recommendations
	sectionID := 1
	itemID := 1

	// Check if OpenSSL is installed
	if openssl, ok := results["OpenSSL"]; ok {
		if strings.Contains(openssl, "Not installed") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Install OpenSSL",
				Type:      scan.InfoRecommendation,
				Details:   "sudo apt install openssl",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// Check if EasyRSA is installed
	if easyrsa, ok := results["EasyRSA"]; ok {
		if strings.Contains(easyrsa, "Not installed") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Install EasyRSA for PQC-ready Certificate Authority management",
				Type:      scan.InfoRecommendation,
				Details:   "EasyRSA is critical for your PQC migration strategy because it allows you to manage your Certificate Authority infrastructure with support for stronger cryptographic algorithms.\n\n" +
					"PQC relevance of EasyRSA:\n" +
					"• EasyRSA 3.1+ supports configurable key types and sizes, essential for PQC transition\n" +
					"• It allows you to upgrade from vulnerable RSA-2048 to stronger RSA-4096 as an interim measure\n" +
					"• When PQC algorithms become standardized, newer EasyRSA versions will likely add support first\n" +
					"• It provides a migration path for your PKI from classical to post-quantum cryptography\n\n" +
					"Installation recommendation:\n" +
					"• Install from GitHub (https://github.com/OpenVPN/easy-rsa) for the latest version with better crypto support\n" +
					"• Package managers often have older versions: apt install easy-rsa (only if latest GitHub version isn't feasible)\n\n" +
					"Post-installation PQC preparation:\n" +
					"• Configure KEY_SIZE=4096 in vars file as a quantum-resistant interim measure\n" +
					"• Monitor the EasyRSA project for updates that add support for NIST PQC standard algorithms\n" +
					"• Plan to regenerate all CA certificates with PQC algorithms once supported",
				Severity:  2, // Low-medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// Section 2: OpenSSL PQC Support Recommendations
	sectionID = 2
	itemID = 1

	// Check OpenSSL PQC support
	if opensslPQC, ok := results["OpenSSL PQC Support"]; ok {
		if strings.Contains(opensslPQC, "No") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Upgrade to OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 certificate issuance",
				Type:      scan.CriticalRecommendation,
				Details:   "Without OpenSSL 3.5+, CA tools cannot natively issue certificates with ML-KEM-1024 or ML-DSA-87 algorithms. " +
					"OpenSSL 3.5+ provides native support for CNSA 2.0 target algorithms without requiring external providers. " +
					"This is essential for hybrid certificate issuance (ECDSA+ML-DSA-87) and CNSA alignment. " +
					"Upgrade from current version to OpenSSL 3.5+ to enable native PQC certificate generation.",
				Severity:  5, // Very High severity - critical for native PQC certificate issuance
			})
			itemID++
		} else if strings.Contains(opensslPQC, "Partial") {
			// Check if OQS provider is installed
			if oqsProvider, ok := results["OQS Provider"]; ok && !strings.Contains(oqsProvider, "Installed") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Install OQS provider for OpenSSL",
					Type:      scan.InfoRecommendation,
					Details:   "Install the OQS provider to enable PQC algorithms with OpenSSL 3.x",
					Kind:      scan.KindRecommendation,
					Severity:  5, // Highest severity - critical missing PQC component
				})
				itemID++
			}
		}
	}

	// Section 3: Certificate Management Recommendations
	sectionID = 3
	itemID = 1

	// Check if any CA tools are installed
	caToolsInstalled := false
	if openssl, ok := results["OpenSSL"]; ok && !strings.Contains(openssl, "Not installed") {
		caToolsInstalled = true
	}
	if easyrsa, ok := results["EasyRSA"]; ok && !strings.Contains(easyrsa, "Not installed") {
		caToolsInstalled = true
	}

	// Only show PQC recommendations if CA tools are installed
	if caToolsInstalled {
		// Recommend hybrid certificates for CNSA alignment
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Implement hybrid certificates (ECDSA+ML-DSA-87) for CNSA 2.0 alignment",
			Type:      scan.CriticalRecommendation,
			Details:   "Deploy hybrid certificates combining ECDSA P-384 with ML-DSA-87 signatures for CNSA 2.0 compliance. " +
				"This approach provides classical security during transition while enabling post-quantum readiness. " +
				"Hybrid certificates ensure compatibility with both classical and PQC-aware clients. " +
				"Requires OpenSSL 3.5+ for native ML-DSA-87 support in certificate generation. " +
				"Configure CA tools to issue dual-algorithm certificates with both ECDSA and ML-DSA-87 signatures.",
			Severity:  4, // High severity - critical for CNSA alignment and PQC transition
		})
		itemID++

		// Recommend monitoring NIST PQC standardization
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Monitor NIST PQC standardization",
			Type:      scan.InfoRecommendation,
			Details:   "Stay updated with NIST PQC standardization for certificate algorithms",
			Severity:  2, // Low-medium severity - informational but affects planning
		})
		itemID++

		// Add specific recommendation from results if available
		if pqcRecommendation, ok := results["PQC Recommendation"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Follow PQC recommendation",
				Type:      scan.InfoRecommendation,
				Details:   pqcRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}

		// Recommend testing tools
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Explore PQC testing tools",
			Type:      scan.InfoRecommendation,
			Details:   "For testing PQC certificates, explore liboqs and OQS-OpenSSL provider",
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// CA and AWS Certificate Manager coordination
		if _, ok := results["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate local CA infrastructure with AWS Certificate Manager",
				Type:      scan.InfoRecommendation,
				Details:   "Your CA infrastructure runs behind an AWS load balancer. Consider these certificate management strategies:\n\n" +
					"• Use AWS Certificate Manager (ACM) for load balancer TLS certificates (automatic renewal, AWS-managed)\n" +
					"• Use local CA (OpenSSL/EasyRSA) for internal service certificates and client authentication\n" +
					"• For comprehensive PQC readiness: monitor AWS ACM for PQC certificate support AND upgrade local CA tools\n" +
					"• Consider hybrid approach: ACM for internet-facing, local CA for internal PQC testing\n" +
					"• Plan certificate migration strategy for when PQC certificates become available\n\n" +
					"This dual-layer approach provides both AWS-managed convenience and local PQC preparation.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific CA deployment considerations
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy alongside local CA improvements",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. While upgrading your local CA infrastructure improves internal certificate security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites for internet-facing certificate validation.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Certificate management recommendations for AWS infrastructure
		if lbType, ok := results["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS certificate management for CA infrastructure",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For CA infrastructure in AWS:\n\n" +
					"• Use AWS Certificate Manager for load balancer certificates (free, auto-renewal)\n" +
					"• Use AWS Private Certificate Authority for internal PKI if budget allows\n" +
					"• Store CA private keys securely using AWS KMS or AWS CloudHSM\n" +
					"• Use AWS Secrets Manager for certificate and key rotation\n" +
					"• Monitor AWS Certificate Manager for PQC certificate support announcements\n" +
					"• Plan certificate backup and disaster recovery using AWS services\n\n" +
					"This AWS-integrated approach provides enterprise-grade certificate management with PQC preparation.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

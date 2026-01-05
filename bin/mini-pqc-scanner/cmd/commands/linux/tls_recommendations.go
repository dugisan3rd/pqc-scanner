package linux

import (
	"fmt"
	"strconv"
	"strings"
	"mini-pqc/scan"
)

// generateTLSRecommendations creates structured recommendations based on TLS scan results
func generateTLSRecommendations(result *scan.TLSScanResult, awsResults map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testtls"] // Module ID for testtls

	// Section 1: CRITICAL - Key Exchange Vulnerabilities (HNDL Risk)
	sectionID := 1
	itemID := 1
	
	// CRITICAL: Key exchange vulnerabilities (Harvest Now, Decrypt Later)
	if result.KeyExchangeVulnerable {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "CRITICAL: Migrate key exchange to PQC/hybrid algorithms immediately",
			Type:      scan.CriticalRecommendation,
			Details:   "TLS endpoints using RSA/ECDH for key exchange are vulnerable to 'Harvest Now, Decrypt Later' attacks. Adversaries can record encrypted traffic today and decrypt it later once quantum computers arrive. Immediate migration to PQC KEMs (ML-KEM/Kyber) or hybrid key exchange is strongly recommended.",
			Severity:  5, // CRITICAL severity
		})
		itemID++
	}
	
	// Section 2: MODERATE - Certificate Signature Vulnerabilities
	sectionID = 2
	itemID = 1

	// Recommendations based on compliance status
	if !result.IsCompliant {
		// Handle deprecated protocols
		if len(result.DeprecatedProtocols) > 0 {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Disable deprecated TLS protocol versions (TLS 1.0, TLS 1.1)",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}

		// Handle weak ciphers
		if len(result.WeakCiphers) > 0 {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Remove weak cipher suites from your TLS configuration",
				Type:      scan.WarningRecommendation,
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		}

		// Handle PFS issues
		if !result.HasPFS {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Enable Perfect Forward Secrecy (PFS) cipher suites",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// MODERATE: Certificate signature recommendations
	if result.SignatureVulnerable {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "MODERATE: Plan migration to PQC signatures for long-lived artifacts",
			Type:      scan.WarningRecommendation,
			Details:   "TLS certificates use ECC/RSA signatures. While quantum-vulnerable, the risk is less immediate since certificates are short-lived. Migration to PQC signatures (ML-DSA/Dilithium) should be planned, especially for long-lived roots and code-signing, but is not as urgent as PQC key exchange.",
			Severity:  3, // MODERATE severity
		})
		itemID++
	}
	
	// Section 3: Immediate Technical Issues
	sectionID = 3
	itemID = 1


	// Section 4: Future Preparation
	sectionID = 4
	itemID = 1

	// General TLS recommendations
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Prefer TLS 1.3; restrict TLS 1.2 to ECDHE with AEAD only",
		Type:      scan.InfoRecommendation,
		Severity:  2, // Low-medium severity - informational but affects testing
	})
	itemID++

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Use only AEAD cipher suites. For TLS 1.2, allow only AES-GCM or ChaCha20-Poly1305; TLS 1.3 is AEAD-only",
		Type:      scan.InfoRecommendation,
		Severity:  2, // Low-medium severity - informational but affects testing
	})
	itemID++

	// PQC recommendations
	if !result.IsPQCConfigured {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Track vendor TLS stacks for hybrid KEM support (e.g., ML-KEM-768 (Kyber) hybrids) and plan enablement when available",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Adopt hybrid KEM key exchanges (e.g., X25519+ML-KEM-768 (Kyber)) when supported by your stack and dependencies",
			Type:      scan.InfoRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// SSL Policy upgrade recommendations
		if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy for better PQC readiness",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. Consider upgrading to a more recent SSL policy that supports TLS 1.3 and modern cipher suites.", pqcReadiness),
					Severity:  4, // High severity - critical for PQC readiness
				})
				itemID++
			}
		}

		// TLS protocol recommendations for load balancer
		if protocols, ok := awsResults["TLS Protocols"]; ok {
			if !strings.Contains(protocols, "TLSv1.3") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Configure AWS load balancer to support TLS 1.3",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current protocols: %s. TLS 1.3 is essential for post-quantum key exchange support. Update your load balancer SSL policy to include TLS 1.3.", protocols),
					Severity:  3, // Medium-high severity
				})
				itemID++
			}
		}

		// Cipher suite recommendations
		if cipherCount, ok := awsResults["Cipher Suite Count"]; ok {
			if count, err := strconv.Atoi(cipherCount); err == nil && count < 15 {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Increase cipher suite diversity on AWS load balancer",
					Type:      scan.InfoRecommendation,
					Details:   fmt.Sprintf("Current cipher count: %s. Consider upgrading to an SSL policy with more cipher suites for better compatibility and security.", cipherCount),
					Severity:  2, // Low-medium severity
				})
				itemID++
			}
		}

		// Load balancer type recommendations
		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			if strings.Contains(strings.ToLower(lbType), "classic") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Consider migrating from Classic Load Balancer to Application Load Balancer",
					Type:      scan.InfoRecommendation,
					Details:   "Application Load Balancers (ALB) provide better SSL policy management, more modern cipher suites, and enhanced support for TLS 1.3 - all important for PQC readiness.",
					Severity:  2, // Low-medium severity
				})
				itemID++
			}
		}

		// General AWS load balancer PQC preparation
		if _, ok := awsResults["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Monitor AWS for post-quantum cryptography SSL policy updates",
				Type:      scan.InfoRecommendation,
				Details:   "AWS regularly updates SSL policies with new security features. Monitor AWS documentation and security bulletins for PQC-ready SSL policies as they become available.",
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

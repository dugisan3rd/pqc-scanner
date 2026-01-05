package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateIPsecRecommendations creates structured recommendations from IPsec check results
func generateIPsecRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testipsec"] // Should be 3

	// Section 1: Installation Recommendations
	sectionID := 1

	// Check if IPsec is installed
	ipsecInstalled := false
	if ipsec, ok := results["IPsec"]; ok {
		if strings.Contains(ipsec, "Not installed") {
			// Only provide status information that IPsec is not installed
			// No recommendation to install unless specifically required
			return recommendations
		}
		ipsecInstalled = true
	}
	
	// If IPsec is not installed, don't provide any recommendations
	if !ipsecInstalled {
		return recommendations
	}

	// Section 2: Configuration Recommendations
	sectionID = 2

	// Check for legacy/weak IKE algorithms
	if legacyIKE, ok := results["Legacy IKE Algorithms"]; ok && legacyIKE == "true" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "Replace legacy IKE algorithms with stronger alternatives",
			Type:      scan.WarningRecommendation,
			Details:   "Replace DES, MD5, and SHA1 with AES, SHA2, or ChaCha20-Poly1305",
			Severity:  4, // High severity - critical for PQC implementation
		})
	}

	// Check for legacy/weak ESP algorithms
	if legacyESP, ok := results["Legacy ESP Algorithms"]; ok && legacyESP == "true" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2,
			Text:      "Replace legacy ESP algorithms with stronger alternatives",
			Type:      scan.WarningRecommendation,
			Details:   "Replace DES, MD5, and SHA1 with AES, SHA2, or ChaCha20-Poly1305",
			Severity:  4, // High severity - critical for PQC implementation
		})
	}

	// Check for legacy/weak DH groups
	if dhSecurity, ok := results["DH Groups Security"]; ok {
		if dhSecurity == "Insecure" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    3,
				Text:      "Replace weak Diffie-Hellman groups with stronger ones",
				Type:      scan.WarningRecommendation,
				Details:   "Use at least modp4096, ecp384, or curve25519 for better security",
				Severity:  4, // High severity - critical for PQC implementation
			})
		}
	}

	// Section 3: Certificate Recommendations
	sectionID = 3

	// Check for legacy certificate algorithms
	if legacyCert, ok := results["Legacy Certificate Algorithm"]; ok && legacyCert == "true" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "Replace certificates using legacy algorithms",
			Type:      scan.WarningRecommendation,
			Details:   "Generate new certificates using at least SHA-256 and RSA-3072 or ECC",
			Severity:  4, // High severity - critical for PQC implementation
		})
	}

	// Check certificate security
	if certSecurity, ok := results["Certificate Security"]; ok {
		if strings.Contains(certSecurity, "Insecure") || strings.Contains(certSecurity, "Vulnerable") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Text:      "Upgrade certificate security",
				Type:      scan.WarningRecommendation,
				Details:   "Use ECC certificates with P-384 or higher for better classical security",
				Severity:  3, // Medium severity - important for PQC readiness
			})
		}
	}

	// Section 4: PQC Readiness Recommendations
	sectionID = 4

	// Check PQC support
	if pqcSupport, ok := results["PQC Support"]; ok {
		if strings.Contains(pqcSupport, "Not detected") || strings.Contains(pqcSupport, "Not available") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Monitor for PQC support in future IPsec releases",
				Type:      scan.InfoRecommendation,
				Details:   "IPsec PQC support is still experimental and not widely available",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
		} else if strings.Contains(pqcSupport, "Experimental") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Text:      "Test experimental PQC support with caution",
				Type:      scan.InfoRecommendation,
				Details:   "Experimental PQC plugins should not be used in production yet",
				Severity:  3, // Medium severity - important for PQC readiness
			})
		}
	}

	// Check PQC readiness
	if pqcReadiness, ok := results["PQC Readiness"]; ok {
		if strings.Contains(pqcReadiness, "Poor") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    3, // Fixed duplicate ItemID
				Text:      "First, deploy a working IKEv2 baseline (AEAD + PFS). Then target RFC 9370 Multiple Key Exchanges once your stack supports it",
				Type:      scan.CriticalRecommendation,
				Details:   "Step 1 - Establish IKEv2 baseline:\n" +
					"• Configure IKEv2 with AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305)\n" +
					"• Enable Perfect Forward Secrecy with strong DH groups (19, 20, 21)\n" +
					"• Use modern authentication (ECC certificates, strong PSKs)\n" +
					"• Verify /etc/ipsec.conf and /etc/ipsec.secrets configuration\n\n" +
					"Step 2 - Target RFC 9370 hybrid path:\n" +
					"• RFC 9370 Multiple Key Exchanges enables hybrid classical+quantum-safe key exchange\n" +
					"• Monitor strongSwan/Libreswan for RFC 9370 implementation (hybrid ECDHE+ML-KEM-1024)\n" +
					"• This is the standardized hybrid path for IKEv2 PQC transition\n\n" +
					"Step 3 - PSK-mixing fallback:\n" +
					"• Keep PSK-mixing per RFC 8784 as quantum-resilient fallback\n" +
					"• PSK mixing provides immediate quantum resistance while hybrids mature\n" +
					"• Use strong, regularly rotated pre-shared keys for critical connections",
				Severity:  5, // Highest severity - critical for PQC functionality
			})
		} else if strings.Contains(pqcReadiness, "Fair") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    4,
				Text:      "Strengthen IKEv2 baseline and prepare for RFC 9370 hybrid key exchange",
				Type:      scan.WarningRecommendation,
				Details:   "Current configuration shows fair readiness. Enhance your setup:\n\n" +
					"IKEv2 baseline improvements:\n" +
					"• Ensure AEAD-only cipher suites (remove CBC modes)\n" +
					"• Verify PFS with strong DH groups (prefer group 21: Curve25519)\n" +
					"• Update to latest strongSwan/Libreswan for security fixes\n\n" +
					"RFC 9370 preparation:\n" +
					"• Monitor vendor roadmaps for Multiple Key Exchanges support\n" +
					"• Plan hybrid ECDHE+ML-KEM-1024 migration when available\n" +
					"• Test PSK-mixing (RFC 8784) as interim quantum-resilient protection\n\n" +
					"This layered approach provides immediate security improvements while preparing for standardized PQC transition.",
				Severity:  3, // Medium severity - important for PQC readiness
			})
		}
	}

	// Add IETF RFC recommendation only if IPsec is installed
	if ipsec, ok := results["IPsec"]; ok && !strings.Contains(ipsec, "Not installed") {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    5, // Fixed duplicate ItemID
			Text:      "Follow IETF RFC 8784 (PSK-mixing) and RFC 9370 (Multiple Key Exchanges) for IPsec PQC transition",
			Type:      scan.InfoRecommendation,
			Details:   "Standards-based IPsec PQC transition strategy:\n\n" +
				"RFC 8784 - PSK Mixing in IKEv2:\n" +
				"• Immediate quantum-resilient protection through PSK mixing\n" +
				"• Combines classical key exchange with pre-shared key material\n" +
				"• Provides quantum resistance even with classical algorithms\n" +
				"• Use for critical connections requiring immediate protection\n\n" +
				"RFC 9370 - Multiple Key Exchanges in IKEv2:\n" +
				"• Standardized framework for hybrid classical+quantum-safe key exchange\n" +
				"• Enables parallel ECDHE and ML-KEM-1024 key derivation\n" +
				"• The official path for IKEv2 PQC hybrid implementation\n" +
				"• Monitor strongSwan/Libreswan for RFC 9370 support\n\n" +
				"Migration strategy: Start with IKEv2+AEAD baseline, add PSK-mixing for critical tunnels, migrate to RFC 9370 hybrids when available.",
			Severity:  3, // Medium severity - important for PQC readiness
		})
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID := 1

		// IPSec and AWS load balancer coordination
		if _, ok := results["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate IPSec VPN and AWS load balancer security architectures",
				Type:      scan.InfoRecommendation,
				Details:   "Your IPSec implementation runs behind an AWS load balancer. Consider these security coordination strategies:\n\n" +
					"• IPSec provides secure site-to-site or remote access VPN tunneling\n" +
					"• AWS load balancer handles internet-facing TLS termination for web interfaces\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND strengthen IPSec crypto algorithms\n" +
					"• Consider separate security policies for IPSec tunnels and web management interfaces\n" +
					"• Monitor both AWS SSL policy updates and IPSec PQC developments (IETF RFC 8784, RFC 9370)\n\n" +
					"This dual-layer approach protects both VPN tunnels and web management traffic.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific IPSec deployment considerations
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy for IPSec server infrastructure",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. Your IPSec server infrastructure is accessible through an AWS load balancer with limited PQC readiness. While IPSec tunnels use their own crypto algorithms, upgrading the load balancer's SSL policy will improve PQC readiness for web-based management interfaces, monitoring dashboards, and API endpoints.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Network architecture recommendations for IPSec in AWS
		if lbType, ok := results["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS network architecture for IPSec VPN deployment",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For IPSec deployments in AWS:\n\n" +
					"• Use Network Load Balancer (NLB) for UDP/TCP VPN traffic if load balancing IPSec directly\n" +
					"• Use Application Load Balancer (ALB) for HTTPS management interfaces\n" +
					"• Consider AWS Site-to-Site VPN as an alternative or complement to IPSec\n" +
					"• Implement proper security groups for IPSec ports (UDP 500, 4500)\n" +
					"• Use AWS Certificate Manager for TLS certificates on management interfaces\n" +
					"• Consider AWS Transit Gateway for complex multi-site IPSec architectures\n\n" +
					"This architecture supports both secure VPN tunneling and PQC-ready management interfaces.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

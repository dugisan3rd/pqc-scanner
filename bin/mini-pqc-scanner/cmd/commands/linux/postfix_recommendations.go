package linux

import (
	"fmt"
	"strings"
	"mini-pqc/scan"
)

// generatePostfixRecommendations creates structured recommendations based on Postfix audit results
func generatePostfixRecommendations(
	tlsEnabled bool,
	weakCiphers bool,
	daneSupport bool,
	mtaStsSupport bool,
	certAlgorithm string,
	classicOnlyCrypto bool,
	postfixInstalled bool,
	awsResults map[string]string,
) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testpostfix"] // Should be 11

	// Section 8.1: Immediate PQC Preparation Actions
	sectionID := 1
	itemID := 1

	// 8.1.1 Enable TLS for both incoming (MX) and outgoing (submission, relay) connections
	if !tlsEnabled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Enable TLS for both incoming (MX) and outgoing (submission, relay) connections",
			Type:      scan.CriticalRecommendation,
			Details:   "Set smtpd_tls_security_level=encrypt (or dane if DNSSEC-validating resolver available) for inbound MX. " +
				"Set smtp_tls_security_level=encrypt or dane for outbound mail. " +
				"Opportunistic may mode should be phased out before PQC rollout.",
			Severity:  5, // VERY HIGH
		})
	}
	itemID++

	// 8.1.2 Use TLSv1.2 or TLSv1.3 and disable older protocols
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Use TLSv1.2 or TLSv1.3 and disable older protocols",
		Type:      scan.WarningRecommendation,
		Details:   "Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1 with: " +
			"smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1 and " +
			"smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1.",
		Severity:  4, // HIGH
	})
	itemID++

	// 8.1.3 Use "high" cipher preference and exclude weak ciphers
	if weakCiphers {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Use \"high\" cipher preference and exclude weak ciphers",
			Type:      scan.WarningRecommendation,
			Details:   "Restrict TLS 1.2 to AEAD+PFS suites (AES-GCM or ChaCha20-Poly1305 with ECDHE). " +
				"Enable tls_preempt_cipherlist = yes and smtpd_tls_eecdh_grade = strong.",
			Severity:  4, // HIGH
		})
	}
	itemID++

	// 8.1.4 Implement DANE (RFC 7672) for inbound SMTP security
	if !daneSupport {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Implement DANE (RFC 7672) for inbound SMTP security",
			Type:      scan.WarningRecommendation,
			Details:   "Requires DNSSEC-signed zone and TLSA records for MX hosts. " +
				"Ensures cryptographic authenticity without relying solely on PKIX CA trust anchors, " +
				"and provides a PQC migration path for SMTP.",
			Severity:  4, // HIGH
		})
	}
	itemID++

	// 8.1.5 Configure MTA-STS (RFC 8461) and TLS Reporting (RFC 8460)
	if !mtaStsSupport {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Configure MTA-STS (RFC 8461) and TLS Reporting (RFC 8460)",
			Type:      scan.WarningRecommendation,
			Details:   "Serve an mta-sts.txt policy and configure TLSRPT reporting to detect " +
				"downgrade or PQC negotiation failures during rollout.",
			Severity:  4, // HIGH
		})
	}
	itemID++

	// 8.1.6 Upgrade certificate/key strength
	if certAlgorithm == "RSA-1024" || certAlgorithm == "DSA" || certAlgorithm == "RSA-2048" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Upgrade certificate/key strength",
			Type:      scan.InfoRecommendation,
			Details:   "Replace RSA-2048 keys with ECDSA P-384 (CNSA-aligned) or RSA-3072. " +
				"Plan migration to ML-DSA-87 once supported in OpenSSL/Postfix for hybrid or pure PQC signatures.",
			Severity:  3, // MODERATE
		})
	}
	itemID++

	// 8.1.7 Link Postfix against OpenSSL ≥ 3.5 for native ML-KEM-1024/ML-DSA-87 support
	if postfixInstalled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Link Postfix against OpenSSL ≥ 3.5 for native ML-KEM-1024/ML-DSA-87 support",
			Type:      scan.WarningRecommendation,
			Details:   "If remaining on OpenSSL 3.2–3.4, install and enable the OQS provider to experiment " +
				"with PQC hybrid KEMs in test/staging environments.",
			Severity:  4, // HIGH
		})
	}
	itemID++

	// 8.1.8 Prepare for PQC-capable key exchange testing
	if postfixInstalled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Prepare for PQC-capable key exchange testing",
			Type:      scan.InfoRecommendation,
			Details:   "After upgrade, run:\n" +
				"openssl s_client -starttls smtp -connect mail.example.com:25 -groups secp384r1mlkem1024\n" +
				"Verify key_share extension contains ML-KEM-1024 and review Postfix TLS logs for PQC negotiation.",
			Severity:  3, // MODERATE
		})
	}
	itemID++

	// Section 8.2: Future Preparation
	sectionID = 2
	itemID = 1

	// 8.2.1 Monitor IETF LAMPS & TCPM drafts for PQC-protected SMTP standards
	if postfixInstalled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Monitor IETF LAMPS & TCPM drafts for PQC-protected SMTP standards",
			Type:      scan.InfoRecommendation,
			Details:   "Adopt implementations once consensus algorithms are available in OpenSSL and Postfix.",
			Severity:  1, // LOW
		})
		itemID++

		// 8.2.2 Plan migration to quantum-resistant certificates and DANE-based trust
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Plan migration to quantum-resistant certificates and DANE-based trust",
			Type:      scan.InfoRecommendation,
			Details:   "When ecosystem support matures, replace classical-only leaf certificates with " +
				"PQC/hybrid-signed equivalents and update TLSA records accordingly.",
			Severity:  3, // MODERATE
		})
		itemID++

		// 8.2.3 Increase TLS log verbosity during PQC rollout
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Increase TLS log verbosity during PQC rollout",
			Type:      scan.InfoRecommendation,
			Details:   "Set smtpd_tls_loglevel=2 and smtp_tls_loglevel=2 temporarily to verify " +
				"PQC cipher negotiation and detect fallback events.",
			Severity:  3, // MODERATE
		})
		itemID++
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// Postfix and AWS load balancer coordination
		if _, ok := awsResults["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate Postfix mail security with AWS load balancer configurations",
				Type:      scan.InfoRecommendation,
				Details:   "Your Postfix mail server runs behind an AWS load balancer. Consider these email security coordination strategies:\n\n" +
					"• Postfix handles SMTP/SMTPS mail transport with TLS encryption\n" +
					"• AWS load balancer handles internet-facing TLS termination for webmail interfaces\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND strengthen Postfix TLS settings\n" +
					"• Consider separate security policies for mail transport (SMTP) and webmail interfaces (HTTPS)\n" +
					"• Implement DANE and MTA-STS for enhanced mail transport security\n" +
					"• Monitor both AWS SSL policy updates and Postfix TLS developments\n\n" +
					"This dual-layer approach protects both mail transport and webmail access.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific Postfix deployment considerations
		if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy for Postfix mail infrastructure",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. Your Postfix mail server infrastructure is accessible through an AWS load balancer with limited PQC readiness. While Postfix mail transport uses its own TLS settings, upgrading the load balancer's SSL policy will improve PQC readiness for webmail interfaces, administrative panels, and API endpoints.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Mail infrastructure recommendations for AWS
		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS infrastructure for secure Postfix mail deployment",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For Postfix mail deployments in AWS:\n\n" +
					"• Use Application Load Balancer (ALB) for HTTPS webmail interfaces\n" +
					"• Consider AWS Simple Email Service (SES) as complement for outbound mail\n" +
					"• Implement proper security groups for SMTP ports (25, 587, 465)\n" +
					"• Use AWS Certificate Manager for TLS certificates on webmail interfaces\n" +
					"• Consider AWS WorkMail as managed alternative for enterprise email\n" +
					"• Implement AWS CloudWatch for mail server monitoring and alerting\n\n" +
					"This AWS-integrated approach provides enterprise-grade mail infrastructure with PQC preparation.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

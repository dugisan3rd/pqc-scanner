package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strconv"
	"strings"
)

// generateOpenVPNRecommendations creates structured recommendations from OpenVPN check results
func generateOpenVPNRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	// Module ID for OpenVPN command
	moduleID := scan.CommandModules["testopenvpn"]

	// Section 1: Installation Recommendations
	sectionID := 1
	itemID := 1

	// Check if OpenVPN is installed
	openvpnInstalled := false
	if openvpn, ok := results["OpenVPN"]; ok {
		if !strings.Contains(openvpn, "Not installed") {
			openvpnInstalled = true
		}
		// We no longer recommend installing OpenVPN if it's not installed
	}
	
	// If OpenVPN is not installed, don't provide any recommendations
	if !openvpnInstalled {
		return recommendations
	}

	// Section 2: TLS Key Exchange Recommendations
	sectionID = 2
	itemID = 1

	// Check TLS key exchange status
	if status, ok := results["TLSKeyExchangeStatus"]; ok && status == "Insecure" {
		if reason, ok := results["TLSKeyExchangeStatusReason"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Upgrade TLS key exchange settings",
				Type:      scan.WarningRecommendation,
				Details:   fmt.Sprintf("Issues found: %s\n\nRecommended actions:\n- Prefer TLS 1.3 (set 'tls-version-min 1.3'); if not supported, use 'tls-version-min 1.2'\n- Enforce ECDHE and remove legacy DH parameters (avoid 'dh1024.pem')\n- On OpenVPN 2.5+, set 'data-ciphers AES-256-GCM:CHACHA20-POLY1305'\n- Protect control channel with 'tls-crypt-v2' (or 'tls-crypt' on older setups)\n\nReferences:\n- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final\n- OpenVPN 2.6 manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/\n- OpenVPN PQCrypto notes: https://community.openvpn.net/PQCryptoOpenVPN", reason),
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		}
	}

	// Check for legacy DH parameters
	if legacyDHCount, ok := results["LegacyDHCount"]; ok && legacyDHCount != "0" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Replace legacy DH parameters",
			Type:      scan.WarningRecommendation,
			Details:   "Prefer ECDHE and remove static DH where possible; for TLS 1.2 environments, set 'ecdh-curve secp384r1' and avoid 'dh1024.pem'. Reference: OpenVPN 2.6 manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
			Severity:  4, // High severity - critical for PQC implementation
		})
		itemID++
	}

	// Check for legacy ciphers
	if legacyCipherCount, ok := results["LegacyCipherCount"]; ok && legacyCipherCount != "0" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Replace legacy ciphers",
			Type:      scan.WarningRecommendation,
			Details:   "On OpenVPN 2.5+, replace 'cipher ...' with 'data-ciphers AES-256-GCM:CHACHA20-POLY1305'. Avoid BF-CBC/3DES/RC2. Reference: OpenVPN 2.6 manual (data-ciphers): https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
			Severity:  5, // Critical severity - legacy ciphers are non-compliant with modern guidance
		})
		itemID++
	}

	// Check for TLS minimum version
	if noTLSMinCount, ok := results["NoTLSMinCount"]; ok && noTLSMinCount != "0" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Set minimum TLS version",
			Type:      scan.WarningRecommendation,
			Details:   "Set 'tls-version-min 1.3' where supported; otherwise 'tls-version-min 1.2'. Reference: OpenVPN 2.6 manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
			Severity:  3, // Medium severity - important for NIST SP 800-52r2 alignment
		})
		itemID++
	}

	// TLS minimum explicitly set but below 1.2 (TLS 1.0/1.1) — disallowed per NIST SP 800-52r2
	if below12, ok := results["TLSMinBelow12Count"]; ok && below12 != "0" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Disallow TLS 1.0/1.1 (set tls-version-min >= 1.2)",
			Type:      scan.WarningRecommendation,
			Details:   "TLS 1.0/1.1 are deprecated and must not be used. Set 'tls-version-min 1.2' (or 1.3 where supported). Reference: NIST SP 800-52r2.",
			Severity:  4, // High severity
		})
		itemID++
	}

	// Prefer TLS 1.3 when only 1.2 is configured (no 1.3 present)
	if v12, ok12 := results["TLSMin12Count"]; ok12 && v12 != "0" {
		if v13, ok13 := results["TLSMin13OrHigherCount"]; ok13 && v13 == "0" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Prefer TLS 1.3 where supported",
				Type:      scan.InfoRecommendation,
				Details:   "TLS 1.2 is acceptable under NIST SP 800-52r2, but prefer TLS 1.3 for stronger defaults and performance. Set 'tls-version-min 1.3' when your OpenVPN/OpenSSL stack supports it.",
				Severity:  2, // Low severity informational preference
			})
			itemID++
		}
	}

	// Control channel hardening
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Harden control channel (tls-crypt-v2)",
		Type:      scan.InfoRecommendation,
		Details:   "Protect the TLS control channel with 'tls-crypt-v2' (OpenVPN 2.5+). Use 'tls-crypt' on older versions. This adds PSK-based protection independent of classical public-key crypto and mitigates control-channel probing.\nReferences:\n- OpenVPN TLS control channel: https://openvpn.net/as-docs/tls-control-channel.html\n- OpenVPN PQCrypto notes: https://community.openvpn.net/PQCryptoOpenVPN",
		Severity:  1, // Low severity - informational
	})
	itemID++

	// Section 3: Certificate Recommendations
	sectionID = 3
	itemID = 1

	// Check certificate type
	if certType, ok := results["CertificateType"]; ok {
		// Warn only if RSA key size is below 3072 bits (per NIST SP 800-57 ~128-bit security)
		if strings.Contains(certType, "RSA") {
			rsaSize := 0
			if parts := strings.Split(certType, "-"); len(parts) > 1 {
				if s, err := strconv.Atoi(parts[1]); err == nil {
					rsaSize = s
				}
			}
			if rsaSize < 3072 {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade RSA certificate key size",
					Type:      scan.WarningRecommendation,
					Details:   "If using RSA, use at least 3072-bit keys; consider ECDSA (P-256/P-384) or Ed25519 and short-lived certificates. Reference: NIST SP 800-57 Part 1 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final",
					Severity:  3, // Medium severity - upgrade to 128-bit security strength
				})
				itemID++
			}
		}

		if pqcReady, ok := results["CertificatePQCReady"]; ok && pqcReady == "false" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Prepare for PQC certificates",
				Type:      scan.InfoRecommendation,
				Details:   "Monitor for hybrid ECC+ML-DSA certificates as standards and tooling mature; mainstream OpenVPN does not yet support PQC/hybrid certificates. References: FIPS 204 ML-DSA: https://csrc.nist.gov/pubs/fips/204/final, OpenVPN PQCrypto notes: https://community.openvpn.net/PQCryptoOpenVPN",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		}
	}

	// Section 4: OpenSSL Recommendations
	sectionID = 4
	itemID = 1

	// Check OpenSSL version for PQC readiness
	if pqcReady, ok := results["OpenSSLPQCReady"]; ok && pqcReady == "false" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Upgrade OpenSSL for PQC support",
			Type:      scan.InfoRecommendation,
			Details:   "For experimental PQC/hybrid TLS, OpenSSL 3.2+ with a PQC provider (e.g., oqs-provider) is required; mainstream OpenVPN does not yet support PQC TLS handshakes. Track IETF ECDHE-MLKEM and vendor support. References: OpenSSL 3.2 notes: https://www.openssl.org/news/openssl-3.2-notes.html, OQS TLS: https://openquantumsafe.org/applications/tls.html, IETF ECDHE-MLKEM draft: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/",
			Severity:  2, // Low severity - plan/track for PQ migration
		})
		itemID++
	}

	// Section 5: EasyRSA Recommendations
	sectionID = 5
	itemID = 1

	// Check EasyRSA defaults
	if keySize, ok := results["EasyRSADefaultKeySize"]; ok {
		if strings.Contains(keySize, "RSA-2048") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Increase EasyRSA default key size",
				Type:      scan.WarningRecommendation,
				Details:   "Prefer EC (P-256/P-384) or Ed25519 for performance; if RSA is required set KEY_SIZE=3072 or higher in EasyRSA vars. Reference: EasyRSA docs: https://github.com/OpenVPN/easy-rsa",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	if digest, ok := results["EasyRSADefaultDigest"]; ok {
		if digest == "SHA1" || digest == "MD5" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Upgrade EasyRSA default digest",
				Type:      scan.WarningRecommendation,
				Details:   "Set DIGEST=sha256 or sha384; avoid SHA-1 and MD5. Reference: EasyRSA docs: https://github.com/OpenVPN/easy-rsa",
				Severity:  4, // High severity - SHA-1/MD5 are not acceptable under modern guidance
			})
			itemID++
		}
	}

	// Add general PQC recommendation (OpenVPN is already confirmed to be installed at this point)
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Monitor OpenVPN for PQC support",
		Type:      scan.InfoRecommendation,
		Details:   "Mainstream OpenVPN does not yet support PQC algorithms. Monitor standards and vendor support; in the interim prefer TLS 1.3, ECDHE, AEAD data-ciphers, and enable tls-crypt-v2. References: FIPS 203 ML-KEM: https://csrc.nist.gov/pubs/fips/203/final, FIPS 204 ML-DSA: https://csrc.nist.gov/pubs/fips/204/final, IETF hybrid TLS: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/, OQS TLS: https://openquantumsafe.org/applications/tls.html",
		Severity:  2, // Low-medium severity - informational but affects testing
	})

	// Section 4: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 4
		itemID = 1

		// OpenVPN and AWS load balancer coordination
		if _, ok := results["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate OpenVPN and AWS load balancer security architectures",
				Type:      scan.InfoRecommendation,
				Details:   "Your OpenVPN server runs behind an AWS load balancer. Consider these security coordination strategies:\n\n" +
					"- OpenVPN provides secure tunneling with classical crypto (RSA, AES, SHA)\n" +
					"- AWS load balancer handles internet-facing TLS termination for web interfaces\n" +
					"- For comprehensive PQC readiness: upgrade load balancer SSL policies for web traffic AND strengthen OpenVPN crypto settings\n" +
					"- Consider separate security policies for VPN traffic (UDP/TCP) and web management interfaces (HTTPS)\n" +
					"- Monitor both AWS SSL policy updates and OpenVPN PQC developments\n\n" +
					"See AWS SSL policies: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/ssl-policies.html\n\n" +
					"This dual-layer approach protects both VPN tunnels and web management traffic.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific OpenVPN deployment considerations
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy for OpenVPN server infrastructure",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. Your OpenVPN server infrastructure is accessible through an AWS load balancer with limited PQC readiness. While OpenVPN tunnels use their own crypto, upgrading the load balancer's SSL policy will improve PQC readiness for web-based management interfaces, monitoring dashboards, and API endpoints.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Network architecture recommendations for OpenVPN in AWS
		if lbType, ok := results["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS network architecture for OpenVPN deployment",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For OpenVPN deployments in AWS:\n\n" +
					"- Use Network Load Balancer (NLB) for UDP/TCP VPN traffic if load balancing OpenVPN directly\n" +
					"- Use Application Load Balancer (ALB) for HTTPS management interfaces and web portals\n" +
					"- Consider AWS Client VPN as an alternative or complement to OpenVPN\n" +
					"- Implement proper security groups for OpenVPN ports (typically 1194 UDP)\n" +
					"- Use AWS Certificate Manager for TLS certificates on management interfaces\n\n" +
					"This architecture supports both secure VPN tunneling and PQC-ready management interfaces.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

package linux

import (
	"mini-pqc/scan"
	"strconv"
	"strings"
)

// isLibraryOpenSSLVersionSufficient checks if the current OpenSSL version meets PQC requirements (3.2.0+)
func isLibraryOpenSSLVersionSufficient(version string) bool {
	if version == "" {
		return false
	}
	
	// Extract version number from output like "OpenSSL 3.2.2 4 Jun 2024"
	parts := strings.Fields(version)
	if len(parts) < 2 {
		return false
	}
	
	versionStr := parts[1] // Should be "3.2.2"
	versionParts := strings.Split(versionStr, ".")
	if len(versionParts) < 2 {
		return false
	}
	
	major, err1 := strconv.Atoi(versionParts[0])
	minor, err2 := strconv.Atoi(versionParts[1])
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	// Check if version is 3.2.0 or higher
	if major > 3 {
		return true
	}
	if major == 3 && minor >= 2 {
		return true
	}
	
	return false
}

// generateLibraryRecommendations creates structured recommendations based on library scan results
func generateLibraryRecommendations(opensslResult *scan.LibraryScanResult, gnutlsInfo GnuTLSInfo) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testlib"] // Module ID for testlib

	// Section 1: OpenSSL Recommendations
	sectionID := 1
	itemID := 1

	// OpenSSL recommendations based on version and provider status
	if opensslResult != nil {
		if !opensslResult.HasPQCSupport && !opensslResult.IsPQCCapable {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Upgrade to OpenSSL 3.5+ for native ML-KEM/ML-DSA support",
				Type:      scan.CriticalRecommendation,
				Details:   "For OpenSSL 3.2-3.4, OQS provider can be used as alternative (test-only). See: https://github.com/open-quantum-safe/oqs-provider",
				Severity:  5, // Very high severity - critical for PQC implementation
			})
			itemID++
		} else if opensslResult.IsPQCCapable && !opensslResult.HasPQCSupport {
			if !opensslResult.HasOQSProvider {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade to OpenSSL 3.5+ for native ML-KEM/ML-DSA support",
					Type:      scan.CriticalRecommendation,
					Details:   "For OpenSSL 3.2-3.4, OQS provider can be used as alternative (test-only). See: https://github.com/open-quantum-safe/oqs-provider",
					Severity:  5, // Very high severity - critical for PQC implementation
				})
				itemID++
			}
		} else if opensslResult.HasPQCSupport && !opensslResult.HasOQSProvider {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "For additional PQC algorithms, consider installing the OQS provider",
				Type:      scan.InfoRecommendation,
				Details:   "See: https://github.com/open-quantum-safe/oqs-provider",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		}
	}

	// Section 2: GnuTLS Recommendations
	sectionID = 2
	itemID = 1

	// GnuTLS recommendations
	if !gnutlsInfo.Installed {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Consider installing GnuTLS for additional cryptographic capabilities",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	} else {
		// Version recommendations
		if gnutlsInfo.Version != "" {
			if !gnutlsInfo.VersionSufficient {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade GnuTLS to at least version 3.6.14 for better PQC support",
					Type:      scan.WarningRecommendation,
					Severity:  3, // Medium severity - important for PQC readiness
				})
				itemID++
			}

			// CECPQ2 recommendations
			if gnutlsInfo.CECPQ2Support != "Supported" {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Track ECDHE-MLKEM support in GnuTLS; CECPQ2 is obsolete",
					Type:      scan.InfoRecommendation,
					Details:   "Monitor GnuTLS development for IETF hybrid ECDHE-MLKEM support (X25519MLKEM768, P-256MLKEM768, P-384MLKEM1024). CECPQ2 was a Google/BoringSSL experiment removed in 2023.",
					Severity:  2, // Low severity - informational guidance
				})
				itemID++

				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Consider using OpenSSL 3.2+ with OQS provider for complete PQC support",
					Type:      scan.InfoRecommendation,
					Severity:  3, // Medium severity - important for PQC readiness
				})
				itemID++
			}
		}
	}

	return recommendations
}

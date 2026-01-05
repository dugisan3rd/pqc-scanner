package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strconv"
	"strings"
)

// checkDistributionVersionForPQC checks if the Linux distribution version meets PQC requirements
func checkDistributionVersionForPQC(distroID, distroVersion string) *scan.Recommendation {
	distroID = strings.ToLower(distroID)
	
	switch distroID {
	case "ubuntu":
		return checkUbuntuVersionForPQC(distroVersion)
	case "debian":
		return checkDebianVersionForPQC(distroVersion)
	case "alpine":
		return checkAlpineVersionForPQC(distroVersion)
	case "amzn":
		return checkAmazonLinuxVersionForPQC(distroVersion)
	case "almalinux", "rocky", "rhel", "centos":
		return checkRHELVersionForPQC(distroID, distroVersion)
	default:
		// For unknown distributions, provide general guidance
		return &scan.Recommendation{
			Type:     scan.InfoRecommendation,
			Text:     "Verify Linux distribution supports PQC requirements",
			Details:  fmt.Sprintf("Distribution: %s %s. Ensure your distribution provides OpenSSL 3.x (minimum 3.0; prefer 3.2+), Linux kernel ≥5.15, TLS 1.3 enabled, and a provider-capable OpenSSL build. For PQC evaluation you may use the OQS provider only in test environments; for production follow vendor FIPS guidance.", distroID, distroVersion),
			Severity: 3,
		}
	}
}

// checkUbuntuVersionForPQC checks Ubuntu version against PQC requirements
func checkUbuntuVersionForPQC(version string) *scan.Recommendation {
	// Parse version (e.g., "20.04", "22.04", "24.04")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil
	}
	
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	
	// Target: 22.04 LTS or higher
	if major < 22 || (major == 22 && minor < 4) {
		return &scan.Recommendation{
			Type:     scan.WarningRecommendation,
			Text:     "Upgrade Ubuntu to 22.04 LTS or higher for PQC readiness",
			Details:  fmt.Sprintf("Current version: Ubuntu %s. Target: Ubuntu 22.04 LTS (or 24.04 LTS). Ubuntu 22.04+ includes OpenSSL 3.x and TLS 1.3 by default. Ubuntu 20.04 uses OpenSSL 1.1.x and lacks the provider model needed for PQC evaluation. For production, follow Canonical FIPS guidance.", version),
			Severity: 4,
		}
	}
	
	return nil
}

// checkDebianVersionForPQC checks Debian version against PQC requirements
func checkDebianVersionForPQC(version string) *scan.Recommendation {
	// Parse version (e.g., "11", "12")
	major, err := strconv.Atoi(strings.Split(version, ".")[0])
	if err != nil {
		return nil
	}
	
	// Target: Debian 12 (Bookworm) or higher
	if major < 12 {
		return &scan.Recommendation{
			Type:     scan.WarningRecommendation,
			Text:     "Upgrade Debian to version 12 (Bookworm) or higher for PQC readiness",
			Details:  fmt.Sprintf("Current version: Debian %s. Target: Debian 12 (Bookworm) or newer. Debian 12 includes OpenSSL 3.x and TLS 1.3 by default; older releases use OpenSSL 1.1.x. For PQC evaluation, use the OQS provider only in non-production environments.", version),
			Severity: 4,
		}
	}
	
	return nil
}

// checkAlpineVersionForPQC checks Alpine Linux version against PQC requirements
func checkAlpineVersionForPQC(version string) *scan.Recommendation {
	// Parse version (e.g., "3.18", "3.19")
	if version == "edge" {
		return nil // Edge is always current
	}
	
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil
	}
	
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	
	// Target: Alpine 3.19+ or Edge
	if major < 3 || (major == 3 && minor < 19) {
		return &scan.Recommendation{
			Type:     scan.WarningRecommendation,
			Text:     "Upgrade Alpine Linux to 3.19+ or Edge for PQC readiness",
			Details:  fmt.Sprintf("Current version: Alpine %s. Target: Alpine 3.19+ or Edge. Alpine 3.19+ provides OpenSSL 3.x in main; earlier releases typically ship OpenSSL 1.1.x. If you need services linked against OpenSSL 3.x (e.g., nginx/apache), use a build or package that links to OpenSSL 3.x.", version),
			Severity: 4,
		}
	}
	
	return nil
}

// checkAmazonLinuxVersionForPQC checks Amazon Linux version against PQC requirements
func checkAmazonLinuxVersionForPQC(version string) *scan.Recommendation {
	// Parse version (e.g., "2", "2023")
	if version == "2023" {
		return nil // 2023 is the target version
	}
	
	major, err := strconv.Atoi(version)
	if err != nil {
		return nil
	}
	
	// Target: Amazon Linux 2023
	if major < 2023 {
		return &scan.Recommendation{
			Type:     scan.WarningRecommendation,
			Text:     "Upgrade to Amazon Linux 2023 for PQC readiness",
			Details:  fmt.Sprintf("Current version: Amazon Linux %s. Target: Amazon Linux 2023. AL2023 includes OpenSSL 3.x and kernel 6.1+. Amazon Linux 2 commonly uses OpenSSL 1.0/1.1 and lacks the provider model required for PQC evaluation.", version),
			Severity: 4,
		}
	}
	
	return nil
}

// checkRHELVersionForPQC checks RHEL derivatives version against PQC requirements
func checkRHELVersionForPQC(distroID, version string) *scan.Recommendation {
	// Parse version (e.g., "8.5", "9.2")
	major, err := strconv.Atoi(strings.Split(version, ".")[0])
	if err != nil {
		return nil
	}
	
	// Target: RHEL 9.x derivatives
	if major < 9 {
		distroName := strings.Title(distroID)
		if distroID == "rhel" {
			distroName = "RHEL"
		} else if distroID == "almalinux" {
			distroName = "AlmaLinux"
		} else if distroID == "rocky" {
			distroName = "Rocky Linux"
		} else if distroID == "centos" {
			distroName = "CentOS"
		}
		
		return &scan.Recommendation{
			Type:     scan.WarningRecommendation,
			Text:     fmt.Sprintf("Upgrade %s to version 9.x for PQC readiness", distroName),
			Details:  fmt.Sprintf("Current version: %s %s. Target: %s 9.x. RHEL 9.x derivatives include OpenSSL 3.x and kernel 5.14+. Use system-wide crypto policies and vendor FIPS modules per guidance; PQC algorithms are not part of current FIPS-validated modules.", distroName, version, distroName),
			Severity: 4,
		}
	}
	
	return nil
}

// generateEnvRecommendations creates structured recommendations from environment check results
func generateEnvRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["env"] // Should be 1

	// Section 1: OpenSSL Recommendations
	sectionID := 1

	// OpenSSL recommendations
	if openssl, ok := results["OpenSSL"]; ok {
		// Check if the detected OpenSSL version supports PQC (OpenSSL 3.x or later)
		if !strings.Contains(openssl, "3.") {
			// Recommend upgrade for PQC readiness
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Type:      scan.WarningRecommendation,
				Text:      "Install OpenSSL 3.x (prefer 3.2+) to enable provider-based crypto and TLS 1.3.",
				Details: fmt.Sprintf(
					"Detected OpenSSL version: %s. OpenSSL 1.x lacks the provider model and cannot integrate PQC providers. OpenSSL 3.x introduces the provider-based architecture required to evaluate NIST PQC algorithms (e.g., ML-KEM [FIPS 203], ML-DSA [FIPS 204]) and to use TLS 1.3 consistently. Plan migration off 1.x.",
					openssl,
				),
				Severity:  4, // High severity - critical for PQC implementation
			})
		} else {
			// If on OpenSSL 3.0.x, suggest moving to >=3.2 for stability/fixes
			if strings.Contains(openssl, "OpenSSL 3.0.") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    3,
					Type:      scan.InfoRecommendation,
					Text:      "Consider upgrading OpenSSL to 3.2+ for improved provider stability and TLS 1.3 fixes",
					Details:   "Detected: " + openssl,
					Severity:  2,
				})
			}
		}
	}

	// OQS Provider recommendations
	if oqsProvider, ok := results["OQS Provider"]; ok {
		if oqsProvider == "Installed" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Type:      scan.SuccessRecommendation,
				Text:      "OQS Provider is installed and detected",
				Details:   "The Open Quantum Safe (OQS) provider is correctly installed and recognized by OpenSSL. This enables access to post-quantum algorithms such as ML-KEM and ML-DSA in testing and transition environments.",
				Severity:  3, // Medium severity - important for PQC readiness
			})
		} else if oqsProvider == "Not installed" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Type:      scan.InfoRecommendation,
				Text:      "Optional: Install the OQS provider for OpenSSL (test only) to evaluate PQC algorithms",
				Details: "The OQS provider was not detected. OpenSSL 3.x supports external providers but does not include PQC algorithms by default. " +
					"If you need to evaluate PQC in test environments, install the Open Quantum Safe (OQS) provider (ML-KEM/ML-DSA). " +
					"See https://github.com/open-quantum-safe/oqs-provider for installation and integration steps. " +
					"Do not use OQS in production unless explicitly authorized; it is not FIPS-validated.",
				Severity:  2,
			})
		} else {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2,
				Type:      scan.InfoRecommendation,
				Text:      "OpenSSL provider status unknown",
				Details:   "OpenSSL did not return provider information. Ensure OpenSSL 3.x is installed and run 'openssl list -providers'. If using a restricted/FIPS build, provider listing may be disabled. Configure OQS provider if appropriate for testing.",
				Severity:  3,
			})
		}
	}

	// Section 2: Web Server Recommendations
	sectionID = 2

	// Nginx recommendations
	if nginx, ok := results["Nginx"]; ok && nginx != "Not installed" {
		itemID := 1
		if nginxOpenSSL, ok := results["Nginx OpenSSL"]; ok {
			if strings.Contains(nginxOpenSSL, "3.") {
				// COMMENTED OUT: nginx scans are already performed automatically when nginx is detected
				// recommendations = append(recommendations, scan.Recommendation{
				// 	ModuleID:  moduleID,
				// 	SectionID: sectionID,
				// 	ItemID:    itemID,
				// 	Text:      "Run 'nginx' command for detailed Nginx configuration analysis",
				// 	Type:      scan.InfoRecommendation,
				// 	Severity:  2, // Low-medium severity - informational but affects testing
				// })
			} else {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Use an Nginx build linked against OpenSSL 3.x for TLS 1.3 and PQC evaluation",
					Type:      scan.WarningRecommendation,
					Details:   "Current OpenSSL linked with Nginx: " + nginxOpenSSL,
					Severity:  4, // High severity - critical for PQC implementation
				})
			}
			itemID++
		}
	}

	// Apache recommendations
	if apache, ok := results["Apache"]; ok && apache != "Not installed" {
		itemID := 3
		if apacheOpenSSL, ok := results["Apache OpenSSL"]; ok {
			if strings.Contains(apacheOpenSSL, "3.") {
				// COMMENTED OUT: apache scans are already performed automatically when apache is detected
				// recommendations = append(recommendations, scan.Recommendation{
				// 	ModuleID:  moduleID,
				// 	SectionID: sectionID,
				// 	ItemID:    itemID,
				// 	Text:      "Run 'apache' command for detailed Apache configuration analysis",
				// 	Type:      scan.InfoRecommendation,
				// 	Severity:  2, // Low-medium severity - informational but affects testing
				// })
			} else {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Use an Apache build linked against OpenSSL 3.x for TLS 1.3 and PQC evaluation",
					Type:      scan.WarningRecommendation,
					Details:   "Current OpenSSL linked with Apache: " + apacheOpenSSL,
					Severity:  4, // High severity - critical for PQC implementation
				})
			}
			itemID++
		}
	}

	// Section 3: VPN Recommendations
	sectionID = 3

	// WireGuard is now only reported in status, not in recommendations

	// OpenVPN recommendations - Commented out since dedicated 'openvpn' command provides detailed analysis
	/*
	if openvpn, ok := results["OpenVPN"]; ok && openvpn != "Not installed" {
		itemID := 3
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "OpenVPN needs configuration for PQC readiness",
			Type:      scan.WarningRecommendation,
			Details:   "Run 'openvpn' command for detailed analysis and recommendations.",
		})
		itemID++
	}
	*/

	// IPsec recommendations - Commented out since dedicated 'ipsec' command provides detailed analysis
	/*
	if ipsec, ok := results["IPsec"]; ok && ipsec != "Not installed" {
		itemID := 5
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "IPsec needs evaluation for PQC readiness",
			Type:      scan.WarningRecommendation,
			Details:   "Run 'ipsec' command for detailed analysis and recommendations.",
		})
		itemID++
	}
	*/

	// Section 4: Linux Distribution Recommendations
	sectionID = 4
	itemID := 1

	// Linux distribution version upgrade recommendations
	if distroID, hasDistroID := results["Distribution ID"]; hasDistroID {
		if distroVersion, hasDistroVersion := results["Distribution Version"]; hasDistroVersion {
			recommendation := checkDistributionVersionForPQC(distroID, distroVersion)
			if recommendation != nil {
				recommendation.ModuleID = moduleID
				recommendation.SectionID = sectionID
				recommendation.ItemID = itemID
				recommendations = append(recommendations, *recommendation)
				itemID++
			}
		}
	}

	// Section 5: Virtualization/Cloud Recommendations
	sectionID = 5
	itemID = 1

	// Cloud environment recommendations
	hasCloudIndicators := false
	cloudKeys := []string{"DMI", "Hypervisor", "MAC OUI", "Cloud-Init", "EC2 Metadata", "EC2 Instance ID"}

	for _, key := range cloudKeys {
		if _, exists := results[key]; exists {
			hasCloudIndicators = true
			break
		}
	}

	if hasCloudIndicators {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Confirm cloud provider's PQC migration timeline",
			Type:      scan.InfoRecommendation,
			Details:   "Cloud environments may handle some aspects of cryptography on your behalf. Check with your provider about their PQC transition plans.",
		})
		itemID++
	}

	// TPM recommendations
	if tpmVersion, ok := results["TPM Version"]; ok && tpmVersion != "Not detected" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Keep TPM/firmware up to date (orthogonal to PQC algorithms)",
			Type:      scan.InfoRecommendation,
			Details:   "Current TPM version: " + tpmVersion + ". TPM does not directly implement PQC algorithms but underpins platform security (e.g., secure/verified boot).",
		})
		itemID++
	}

	return recommendations
}

package linux

import (
	"mini-pqc/scan"
	"strings"
)

// generateFirmwareRecommendations creates structured recommendations from firmware check results
func generateFirmwareRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["firmware"] // Should be 2

	// Check if we're in a WSL/VM/guest environment where firmware access is not available
	isGuestEnvironment := false
	if env, ok := results["Environment"]; ok {
		if strings.Contains(env, "Virtual Machine") || strings.Contains(env, "Cloud") || strings.Contains(env, "WSL") || strings.Contains(env, "Container") {
			isGuestEnvironment = true
		}
	}

	// If in WSL/VM/guest environment, add informational message and provide host-scoped recommendations
	if isGuestEnvironment {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 1,
			ItemID:    1,
			Text:      "Firmware management handled by host/hypervisor (WSL/VM environment)",
			Type:      scan.InfoRecommendation,
			Details:   "In WSL/VM/guest environments, firmware security (UEFI, TPM, Secure Boot) is managed by the host system or hypervisor. These findings are informational and not actionable within the guest environment. For comprehensive security, ensure the host system has proper firmware security configurations.",
			Severity:  1, // Low severity - informational
		})
		
		// Add host-scoped informational recommendations
		if uefi, ok := results["UEFI"]; ok && strings.Contains(uefi, "Not detected") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: 1,
				ItemID:    2,
				Text:      "Host system: Verify UEFI firmware (informational - host-scoped)",
				Type:      scan.InfoRecommendation,
				Details:   "The host system appears to use legacy BIOS. For comprehensive security, ensure the host system uses UEFI firmware with Secure Boot enabled. This is managed at the host level, not within the WSL/VM guest.",
				Severity:  1, // Low severity - informational, host-scoped
			})
		}
		
		if sb, ok := results["Secure Boot"]; ok && (sb == "Disabled" || sb == "Not available (no UEFI detected)") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: 1,
				ItemID:    3,
				Text:      "Host system: Verify Secure Boot configuration (informational - host-scoped)",
				Type:      scan.InfoRecommendation,
				Details:   "Secure Boot appears to be disabled or unavailable on the host system. For comprehensive security, ensure Secure Boot is enabled on the host system's UEFI firmware. This is managed at the host level, not within the WSL/VM guest.",
				Severity:  1, // Low severity - informational, host-scoped
			})
		}
		
		if tpm, ok := results["TPM"]; ok && tpm == "Not detected" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: 1,
				ItemID:    4,
				Text:      "Host system: Verify TPM availability (informational - host-scoped)",
				Type:      scan.InfoRecommendation,
				Details:   "TPM hardware is not detected. In WSL/VM environments, TPM access depends on host system configuration and hypervisor settings. For comprehensive security, ensure the host system has TPM 2.0 enabled and properly configured.",
				Severity:  1, // Low severity - informational, host-scoped
			})
		}
		
		return recommendations
	}

	// Section 1: Boot Security Recommendations (only for bare metal systems)
	sectionID := 1
	itemID := 1

	// Check UEFI status (bare metal only - guest environments handled above)
	if uefi, ok := results["UEFI"]; ok {
		if strings.Contains(uefi, "Not detected") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Update to UEFI firmware if possible",
				Type:      scan.WarningRecommendation,
				Details:   "Legacy BIOS lacks modern security features needed for quantum-safe boot chains",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		} else if strings.Contains(uefi, "32-bit") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Consider upgrading to 64-bit UEFI",
				Type:      scan.InfoRecommendation,
				Details:   "64-bit UEFI provides better compatibility with modern security features",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		}
	}

	// Check Secure Boot status (bare metal only - guest environments handled above)
	if sb, ok := results["Secure Boot"]; ok {
		if sb == "Disabled" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Enable Secure Boot",
				Type:      scan.WarningRecommendation,
				Details:   "Secure Boot helps prevent unauthorized boot code execution",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		} else if sb == "Not configured" || strings.Contains(sb, "unknown") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Configure Secure Boot",
				Type:      scan.WarningRecommendation,
				Details:   "Secure Boot is available but not properly configured",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		} else if sb == "Not available (no UEFI detected)" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Update firmware to support UEFI and Secure Boot",
				Type:      scan.WarningRecommendation,
				Details:   "Modern security features require UEFI firmware",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// Check TPM status (bare metal only - guest environments handled above)
	if tpm, ok := results["TPM"]; ok {
		if tpm == "Not detected" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Add a TPM module if hardware supports it",
				Type:      scan.InfoRecommendation,
				Details:   "TPM provides hardware-based security features",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		} else if strings.Contains(tpm, "TPM 1.") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Consider upgrading to TPM 2.0",
				Type:      scan.InfoRecommendation,
				Details:   "TPM 2.0 provides better algorithm agility for post-quantum era",
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// Section 2: PQC Firmware Recommendations
	sectionID = 2
	itemID = 1

	// Check PQC firmware support
	if pqcSupport, ok := results["PQC Firmware Support"]; ok {
		if strings.Contains(pqcSupport, "Not detected") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Update firmware to support quantum-safe boot signatures",
				Type:      scan.CriticalRecommendation,
				Details:   "Current RSA-only boot chain is vulnerable to quantum attacks",
				Severity:  5, // Highest severity - critical for PQC functionality
			})
			itemID++
		}
	}

	// Check boot chain security
	if bootSecurity, ok := results["Boot Chain Security"]; ok {
		if strings.Contains(bootSecurity, "RSA-only") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Implement hybrid signatures in boot chain",
				Type:      scan.WarningRecommendation,
				Details:   "Hybrid signatures combine classical (RSA/ECDSA) with post-quantum algorithms",
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		}
	}

	// Section 3: BMC/IPMI Recommendations
	sectionID = 3
	itemID = 1

	// Check BMC presence
	if bmcPresent, ok := results["BMC Present"]; ok && bmcPresent == "Yes (/dev/ipmi0)" || bmcPresent == "Yes (/dev/bmc)" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Verify BMC firmware is up-to-date",
			Type:      scan.WarningRecommendation,
			Details:   "BMC firmware often contains security vulnerabilities",
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Secure BMC network access",
			Type:      scan.WarningRecommendation,
			Details:   "Isolate BMC on a separate management network with strict access controls",
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	}

	// Environment-specific recommendations
	if env, ok := results["Environment"]; ok {
		if env == "On-Premises or Edge Server" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Implement physical security measures",
				Type:      scan.InfoRecommendation,
				Details:   "On-premises servers require physical security controls",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		} else if env == "Virtual Machine (not bare metal)" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Verify hypervisor security",
				Type:      scan.InfoRecommendation,
				Details:   "VM security depends on hypervisor security",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++
		}
	}

	return recommendations
}

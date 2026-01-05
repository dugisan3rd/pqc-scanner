package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateFirmwareStatus creates structured status items from firmware scan results
func generateFirmwareStatus(results map[string]string, rm *scan.RecommendationManager) {
	// Module ID for firmware command - using 2 as requested by the user
	moduleID := scan.CommandModules["firmware"] // Should be 2

	// Determine if we're in a WSL/VM/guest environment
	isGuestEnvironment := false
	if environment, ok := results["Environment"]; ok {
		if strings.Contains(environment, "Virtual Machine") || strings.Contains(environment, "WSL") || strings.Contains(environment, "Container") {
			isGuestEnvironment = true
		}
	}

	// Section 1: Environment Status
	if environment, ok := results["Environment"]; ok && environment != "" {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("Environment: %s", environment), scan.InfoRecommendation, "", 1)
	}

	// Section 2: UEFI Status
	if uefi, ok := results["UEFI"]; ok && uefi != "" {
		if isGuestEnvironment {
			rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("UEFI: %s (Host managed / N/A in WSL/VM)", uefi), scan.InfoRecommendation, "UEFI firmware is managed by the host system or hypervisor in virtualized environments", 1)
		} else {
			// Determine severity based on UEFI availability for bare metal
			severity := 1
			if strings.Contains(uefi, "Not detected") {
				severity = 2 // Low-medium for bare metal without UEFI
			}
			rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("UEFI: %s", uefi), scan.InfoRecommendation, "", severity)
		}
	}

	// Section 3: Secure Boot Status
	if secureBoot, ok := results["Secure Boot"]; ok && secureBoot != "" {
		if isGuestEnvironment {
			rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Secure Boot: %s (Host managed / N/A in WSL/VM)", secureBoot), scan.InfoRecommendation, "Secure Boot is managed by the host system or hypervisor in virtualized environments", 1)
		} else {
			// Determine severity based on Secure Boot availability for bare metal
			severity := 1
			if strings.Contains(secureBoot, "Not available") || strings.Contains(secureBoot, "Disabled") {
				severity = 3 // Medium severity for bare metal without Secure Boot
			}
			rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("Secure Boot: %s", secureBoot), scan.InfoRecommendation, "", severity)
		}
	}

	// Section 4: TPM Status
	if tpm, ok := results["TPM"]; ok && tpm != "" {
		if isGuestEnvironment {
			rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("TPM: %s (Host managed / N/A in WSL/VM)", tpm), scan.InfoRecommendation, "TPM hardware is managed by the host system or hypervisor in virtualized environments", 1)
			if tpmVersion, ok := results["TPM Version"]; ok && tpmVersion != "" {
				rm.AddStatus(moduleID, 4, 2, fmt.Sprintf("TPM Version: %s (Host managed)", tpmVersion), scan.InfoRecommendation, "TPM version is determined by host system hardware", 1)
			}
		} else {
			// Determine severity based on TPM availability for bare metal
			severity := 1
			if strings.Contains(tpm, "Not detected") {
				severity = 3 // Medium severity for bare metal without TPM
			}
			rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("TPM: %s", tpm), scan.InfoRecommendation, "", severity)
			if tpmVersion, ok := results["TPM Version"]; ok && tpmVersion != "" {
				rm.AddStatus(moduleID, 4, 2, fmt.Sprintf("TPM Version: %s", tpmVersion), scan.InfoRecommendation, "", severity)
			}
		}
	}

	// Section 5: BMC/IPMI Status
	if bmc, ok := results["BMC"]; ok && bmc != "" {
		rm.AddStatus(moduleID, 5, 1, fmt.Sprintf("BMC: %s", bmc), scan.InfoRecommendation, "", 1)
		if bmcVersion, ok := results["BMC Version"]; ok && bmcVersion != "" {
			rm.AddStatus(moduleID, 5, 2, fmt.Sprintf("BMC Version: %s", bmcVersion), scan.InfoRecommendation, "", 1)
		}
	}

	// Section 6: PQC Support Status
	if pqcSupport, ok := results["PQC Support"]; ok && pqcSupport != "" {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("PQC Support: %s", pqcSupport), scan.InfoRecommendation, "", 2)
	}

	// Section 7: Signing Algorithm Status
	if signingAlgo, ok := results["Signing Algorithm"]; ok && signingAlgo != "" {
		rm.AddStatus(moduleID, 7, 1, fmt.Sprintf("Signing Algorithm: %s", signingAlgo), scan.InfoRecommendation, "", 2)
	}
}

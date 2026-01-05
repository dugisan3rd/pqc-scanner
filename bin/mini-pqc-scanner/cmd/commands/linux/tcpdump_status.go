package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateTcpdumpStatus adds structured status items for the tcpdump command.
// ModuleID 17 corresponds to tcpdump recommendations.
func generateTcpdumpStatus(results map[string]string, rm *scan.RecommendationManager) {
	moduleID := scan.CommandModules["testtcpdump"] // Should be 17

	// Section 1: Installation & version
	if path, ok := results["TcpdumpPath"]; ok {
		rm.AddStatus(moduleID, 1, 1, fmt.Sprintf("tcpdump installed: %s", path), scan.InfoRecommendation, "", 1)
	} else {
		rm.AddStatus(moduleID, 1, 1, "tcpdump: Not installed", scan.CriticalRecommendation, "", 3)
	}
	if ver, ok := results["TcpdumpVersion"]; ok && ver != "" {
		rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("tcpdump version: %s", ver), scan.InfoRecommendation, "", 1)
	}

	// Section 2: TLS library linkage
	if lib, ok := results["TLSLibrary"]; ok {
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("TLS library: %s", lib), scan.InfoRecommendation, "", 1)
	}

	// Section 3: Protocol support
	if support, ok := results["TLSSupport"]; ok {
		rm.AddStatus(moduleID, 3, 1, fmt.Sprintf("TLS protocol decoding: %s", support), scan.InfoRecommendation, "", 1)
	}
	if support, ok := results["SSHSupport"]; ok {
		rm.AddStatus(moduleID, 3, 2, fmt.Sprintf("SSH protocol decoding: %s", support), scan.InfoRecommendation, "", 1)
	}
	if support, ok := results["IPsecSupport"]; ok {
		rm.AddStatus(moduleID, 3, 3, fmt.Sprintf("IPsec protocol decoding: %s", support), scan.InfoRecommendation, "", 1)
	}
	if support, ok := results["QUICSupport"]; ok {
		rm.AddStatus(moduleID, 3, 4, fmt.Sprintf("QUIC protocol support: %s", support), scan.InfoRecommendation, "", 1)
	}

	// Section 4: Tshark availability
	if tshark, ok := results["TsharkPath"]; ok {
		rm.AddStatus(moduleID, 4, 1, fmt.Sprintf("tshark installed: %s", tshark), scan.InfoRecommendation, "", 1)
		if v, ok := results["TsharkVersion"]; ok {
			rm.AddStatus(moduleID, 4, 2, fmt.Sprintf("tshark version: %s", v), scan.InfoRecommendation, "", 1)
		}
	} else {
		rm.AddStatus(moduleID, 4, 1, "tshark: Not installed", scan.InfoRecommendation, "", 1)
	}

	// Section 5: Process tracking capability
	if checkBCCInstalled() {
		rm.AddStatus(moduleID, 5, 1, "Process tracking capability: Available", scan.InfoRecommendation, "", 1)
	} else {
		rm.AddStatus(moduleID, 5, 1, "Process tracking capability: Not available - BCC tools not installed", scan.WarningRecommendation, "", 2)
	}

	// Process tracking results if available
	if tracking, ok := results["ProcessTracking"]; ok {
		switch tracking {
		case "Success":
			rm.AddStatus(moduleID, 5, 2, "Process tracking: Successful", scan.InfoRecommendation, "", 1)
			if count, ok := results["ProcessTrackingCount"]; ok {
				rm.AddStatus(moduleID, 5, 3, fmt.Sprintf("Processes tracked: %s", count), scan.InfoRecommendation, "", 1)
			}
		case "Failed":
			rm.AddStatus(moduleID, 5, 2, "Process tracking: Failed", scan.WarningRecommendation, "", 2)
		case "Failed - BCC not installed":
			rm.AddStatus(moduleID, 5, 2, "Process tracking: Failed - BCC tools not installed", scan.WarningRecommendation, "", 2)
		}
	}

	// Section 6: Capture results
	if capture, ok := results["CaptureResults"]; ok {
		rm.AddStatus(moduleID, 6, 1, fmt.Sprintf("Capture results: %s", capture), scan.InfoRecommendation, "", 1)
	}
}

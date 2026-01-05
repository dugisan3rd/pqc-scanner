package linux

import (
	"fmt"
	"mini-pqc/scan"
)

// generateLibraryStatus creates structured status items from library scan results
func generateLibraryStatus(openSSLResult *scan.LibraryScanResult, gnutlsInfo GnuTLSInfo, rm *scan.RecommendationManager) {
	// Module ID for library command
	moduleID := scan.CommandModules["testlib"] // Should be 14

	// Add OpenSSL status
	if openSSLResult != nil {
		// S14.1.1 OpenSSL version status → HIGH (or VERY HIGH if PQC needed now)
		versionStatus := fmt.Sprintf("OpenSSL version: %s", openSSLResult.Version)
		var versionSeverity int
		if openSSLResult.HasPQCSupport {
			versionStatus += " (Native ML-KEM-1024/ML-DSA-87 support)"
			versionSeverity = 4 // HIGH - has PQC support
		} else if openSSLResult.IsPQCCapable {
			versionStatus += " (Provider framework only - requires OQS provider for PQC)"
			versionSeverity = 5 // VERY HIGH - PQC needed now (requires OQS provider)
		} else {
			versionStatus += " (No PQC support)"
			versionSeverity = 5 // VERY HIGH - PQC needed now (no support at all)
		}
		rm.AddStatus(moduleID, 1, 1, versionStatus, scan.InfoRecommendation, "", versionSeverity)

		// S14.1.2 OpenSSL details status → NONE (inventory)
		if openSSLResult.Details != "" {
			rm.AddStatus(moduleID, 1, 2, fmt.Sprintf("Details: %s", openSSLResult.Details), scan.InfoRecommendation, "", 0)
		}

		// S14.1.3 OQS provider status → VERY HIGH
		if openSSLResult.IsPQCCapable || openSSLResult.HasPQCSupport {
			oqsStatus := "OQS provider: "
			if openSSLResult.HasOQSProvider {
				oqsStatus += "Installed and registered"
			} else {
				oqsStatus += "Not installed or not registered"
			}
			rm.AddStatus(moduleID, 1, 3, oqsStatus, scan.InfoRecommendation, "", 5)
		}
	}

	// Add GnuTLS status
	if gnutlsInfo.Installed {
		// S14.2.1 GnuTLS version status → LOW
		rm.AddStatus(moduleID, 2, 1, fmt.Sprintf("GnuTLS version: %s", gnutlsInfo.Version), scan.InfoRecommendation, "", 1)

		// GnuTLS CECPQ2 support status (obsolete - removed from BoringSSL 2023)
		rm.AddStatus(moduleID, 2, 2, fmt.Sprintf("CECPQ2 Support: %s (obsolete)", gnutlsInfo.CECPQ2Support), scan.InfoRecommendation, "", 2)

		// GnuTLS linked tools
		if len(gnutlsInfo.LinkedTools) > 0 {
			rm.AddStatus(moduleID, 2, 3, fmt.Sprintf("Tools linked with GnuTLS: %s", gnutlsInfo.LinkedTools[0]), scan.InfoRecommendation, "", 1)
			// Add additional tools if there are more than one
			for i := 1; i < len(gnutlsInfo.LinkedTools); i++ {
				rm.AddStatus(moduleID, 2, 3+i, fmt.Sprintf("                         %s", gnutlsInfo.LinkedTools[i]), scan.InfoRecommendation, "", 1)
			}
		}
	} else {
		// S14.2.1 GnuTLS not installed → LOW
		rm.AddStatus(moduleID, 2, 1, "GnuTLS: Not installed", scan.InfoRecommendation, "", 1)
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// generateTcpdumpRecommendations generates structured recommendations for tcpdump
func generateTcpdumpRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := []scan.Recommendation{}

	// Get the module ID for tcpdump (using 17 as it appears to be the next available ID)
	moduleID := 17

	// Check if tcpdump is installed
	if results["Tcpdump"] == "Not installed" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 1,
			ItemID:    1,
			Text:      "Install tcpdump for network traffic analysis",
			Type:      scan.CriticalRecommendation,
			Details:   "Tcpdump is a powerful tool for analyzing network traffic and can help identify non-PQC compliant protocols and encryption methods. Install tcpdump using your package manager (e.g., apt install tcpdump, yum install tcpdump).",
			Severity:  3, // Medium severity - important for PQC readiness assessment
		})
		return recommendations
	}

	// Check TLS library and PQC support
	if tlsLib, ok := results["TLSLibrary"]; ok {
		if tlsLib == "OpenSSL" {
			// Check if OpenSSL version supports PQC
			if !strings.Contains(results["PQCSupport"], "Supported") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: 2,
					ItemID:    1,
					Text:      "Upgrade OpenSSL to version 3.2+ for PQC support",
					Type:      scan.CriticalRecommendation,
					Details:   fmt.Sprintf("Tcpdump is linked against an older version of OpenSSL that does not support post-quantum cryptography. Current version: %s. Upgrade to OpenSSL 3.2 or later to enable PQC support for network traffic analysis.", results["OpenSSLVersion"]),
					Severity:  4, // High severity - critical for PQC implementation
				})
			}
		} else if tlsLib == "GnuTLS" {
			// Check if GnuTLS version supports PQC
			if !strings.Contains(results["PQCSupport"], "Supported") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: 2,
					ItemID:    2,
					Text:      "Upgrade GnuTLS for PQC support",
					Type:      scan.CriticalRecommendation,
					Details:   fmt.Sprintf("Tcpdump is linked against an older version of GnuTLS that does not support post-quantum cryptography. Current version: %s. Upgrade to GnuTLS 3.8 or later to enable PQC support for network traffic analysis.", results["GnuTLSVersion"]),
					Severity:  4, // High severity - critical for PQC implementation
				})
			}
		}
	}

	// Check QUIC protocol support
	if results["QUICSupport"] == "Not supported" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 3,
			ItemID:    1,
			Text:      "Upgrade tcpdump for QUIC protocol support",
			Type:      scan.CriticalRecommendation,
			Details:   "Your version of tcpdump does not support the QUIC protocol, which is used by HTTP/3 and is important for modern encrypted traffic analysis. Upgrade to the latest version of tcpdump to ensure support for QUIC protocol analysis.",
			Severity:  3, // Medium severity - important for PQC readiness assessment
		})
	}

	// General recommendation for using tcpdump for PQC analysis
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: 4,
		ItemID:    1,
		Text:      "Use tcpdump to monitor for non-PQC compliant protocols",
		Type:      scan.InfoRecommendation,
		Details:   "Regularly monitor network traffic to identify legacy cryptographic protocols and algorithms that are not quantum-resistant. Use commands like 'tcpdump -i any -n port 443 -vvv' to capture and analyze TLS handshakes, looking for key exchange algorithms that are not quantum-resistant.",
		Severity:  2, // Low-medium severity - informational but affects testing
	})

	// Recommendation for analyzing captured traffic
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: 4,
		ItemID:    2,
		Text:      "Analyze captured traffic for PQC readiness",
		Type:      scan.InfoRecommendation,
		Details:   "Capture traffic with 'tcpdump -i any -w capture.pcap port 443' and then analyze with Wireshark to identify non-PQC compliant protocols and algorithms.",
		Severity:  2, // Low-medium severity - informational but affects testing
	})

	// Check if tshark is installed
	if tshark, ok := results["tshark"]; ok && tshark == "Not installed" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 4,
			ItemID:    3,
			Text:      "Install tshark for advanced protocol analysis",
			Type:      scan.InfoRecommendation,
			Details:   "Tshark is the command-line version of Wireshark and provides more advanced protocol analysis capabilities than tcpdump. It's particularly useful for analyzing encrypted traffic and identifying non-PQC compliant protocols.",
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Process tracking recommendations
	// Check if BCC tools are installed
	if !checkBCCInstalled() {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 5,
			ItemID:    1,
			Text:      "Install BCC tools for process-to-network flow correlation",
			Type:      scan.InfoRecommendation,
			Details:   "BCC (BPF Compiler Collection) tools enable process tracking and correlation with network flows, which is valuable for identifying which applications are using non-PQC compliant protocols. Install with 'apt install python3-bcc' on Debian/Ubuntu or equivalent for your distribution.",
			Severity:  2, // Low-medium severity - enhances analysis capabilities
		})
	}

	// Recommend using process tracking for PQC analysis
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: 5,
		ItemID:    2,
		Text:      "Use process tracking to identify applications needing PQC upgrades",
		Type:      scan.InfoRecommendation,
		Details:   "When capturing network traffic, use the -process-track flag to correlate network flows with originating processes. This helps identify specific applications that need to be upgraded to support post-quantum cryptography. Example: 'pqc-scanner testtcpdump -dump -process-track -s 60'",
		Severity:  2, // Low-medium severity - enhances analysis capabilities
	})

	// If process tracking was attempted but failed
	if tracking, ok := results["ProcessTracking"]; ok && (tracking == "Failed" || tracking == "Failed - BCC not installed") {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: 5,
			ItemID:    3,
			Text:      "Troubleshoot process tracking functionality",
			Type:      scan.WarningRecommendation,
			Details:   "Process tracking failed during the last capture. Ensure BCC tools are properly installed and that you have sufficient permissions to run eBPF programs (typically requires root or CAP_BPF capability).",
			Severity:  2, // Low-medium severity
		})
	}

	return recommendations
}

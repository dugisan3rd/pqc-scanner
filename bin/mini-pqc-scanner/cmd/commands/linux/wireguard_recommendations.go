package linux

import (
	"fmt"
	"strings"
	"mini-pqc/scan"
)

// generateWireguardRecommendations generates recommendations based on WireGuard scan results
func generateWireguardRecommendations(results map[string]string) []scan.Recommendation {
	var recommendations []scan.Recommendation
	moduleID := scan.CommandModules["testwireguard"]
	sectionID := 1
	itemID := 1

	// Check if WireGuard is installed
	if installed, ok := results["WireGuard Installed"]; ok {
		if installed == "Yes" {
			// Get WireGuard version if available
			version := "Unknown"
			if v, ok := results["WireGuard Version"]; ok && v != "Unknown" {
				version = v
			}
			
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Add Rosenpass alongside WireGuard for post-quantum key exchange",
				Type:      scan.CriticalRecommendation,
				Severity:  5, // Very high severity - critical for PQC readiness
				Details:   fmt.Sprintf("Detected WireGuard version: %s\n\n" +
					"Hybrid WireGuard + Rosenpass deployment strategy:\n\n" +
					"Current WireGuard setup:\n" +
					"• WireGuard uses Curve25519 (classical) for key exchange\n" +
					"• ChaCha20-Poly1305 for tunnel encryption (quantum-safe symmetric)\n" +
					"• Keep existing WireGuard configuration and performance\n\n" +
					"Rosenpass hybrid add-on:\n" +
					"• Deploy Rosenpass alongside WireGuard (not replacement)\n" +
					"• Rosenpass provides post-quantum KEX using Kyber or Classic McEliece\n" +
					"• Rosenpass feeds quantum-safe key material to WireGuard as PSK\n" +
					"• Creates hybrid classical+quantum-safe key derivation\n\n" +
					"Implementation approach:\n" +
					"• Install Rosenpass: https://rosenpass.eu/\n" +
					"• Configure Rosenpass to generate PSKs for WireGuard peers\n" +
					"• WireGuard continues normal operation with PQ-enhanced PSKs\n" +
					"• Label as 'hybrid add-on' - maintains WG performance with PQ security", version),
			})
		} else {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Install WireGuard for secure VPN connectivity",
				Type:      scan.InfoRecommendation,
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			
			// Early return if not installed
			return recommendations
		}
		itemID++
	}

	// Kernel module status is now handled in the status section
	// Not adding kernel module recommendations here

	// Interface status is now handled in the status section
	// Not adding interface recommendations here

	// Section 2: Tools
	if tools, ok := results["Tools"]; ok && tools == "Missing" {
		sectionID = 2
		itemID = 1
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Install WireGuard tools with 'apt install wireguard-tools'",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// WireGuard and AWS load balancer coordination
		if _, ok := results["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Consider WireGuard and AWS load balancer crypto coordination",
				Type:      scan.InfoRecommendation,
				Details:   "Your system runs WireGuard VPN behind an AWS load balancer. Consider these PQC preparation strategies:\n\n" +
					"• WireGuard provides secure tunneling with Rosenpass hybrid PQ enhancement\n" +
					"• AWS load balancer handles internet-facing TLS termination\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND deploy WireGuard+Rosenpass hybrid\n" +
					"• This dual-layer approach protects both web traffic (via load balancer) and VPN traffic (via WireGuard+Rosenpass)\n\n" +
					"Monitor both AWS SSL policy updates and Rosenpass development for WireGuard integration.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific WireGuard deployment considerations
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Prioritize AWS load balancer SSL policy upgrade for WireGuard server",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. Your WireGuard server is accessible through an AWS load balancer with limited PQC readiness. While WireGuard tunnels remain secure with classical crypto, upgrading the load balancer's SSL policy will improve PQC readiness for any web-based management interfaces or API endpoints.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Network architecture recommendations
		if lbType, ok := results["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS network architecture for WireGuard VPN deployment",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For WireGuard deployments in AWS:\n\n" +
					"• Use Network Load Balancer (NLB) for UDP traffic if load balancing WireGuard directly\n" +
					"• Use Application Load Balancer (ALB) for HTTPS management interfaces\n" +
					"• Consider AWS VPN solutions alongside WireGuard for hybrid approaches\n" +
					"• Implement proper security groups for WireGuard UDP ports\n\n" +
					"This architecture supports both secure VPN tunneling and PQC-ready web interfaces.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

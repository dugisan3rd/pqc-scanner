package linux

import (
	"fmt"
	"mini-pqc/scan"
	"strings"
)

// using shared isOpenSSHAtLeast from openssh_version.go

// generateOpenSSHRecommendations creates structured recommendations from OpenSSH check results
func generateOpenSSHRecommendations(results map[string]string, hostKeyResults map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testopenssh"] // Should be 6

	// Determine PQC readiness thresholds based on precise OpenSSH versions
	clientAtLeast99 := false
	clientAtLeast100 := false
	if clientVersion, ok := results["OpenSSHClientVersion"]; ok {
		if isOpenSSHAtLeast(clientVersion, 9, 9) {
			clientAtLeast99 = true
		}
		if isOpenSSHAtLeast(clientVersion, 10, 0) {
			clientAtLeast100 = true
		}
	}
	serverAtLeast99 := false
	serverAtLeast100 := false
	if serverVersion, ok := results["OpenSSHServerVersion"]; ok {
		if isOpenSSHAtLeast(serverVersion, 9, 9) {
			serverAtLeast99 = true
		}
		if isOpenSSHAtLeast(serverVersion, 10, 0) {
			serverAtLeast100 = true
		}
	}
	anyAtLeast99 := clientAtLeast99 || serverAtLeast99
	anyAtLeast100 := clientAtLeast100 || serverAtLeast100

	// Section 1: Configuration Recommendations
	sectionID := 1
	itemID := 1

	// PQC readiness actions
	if !anyAtLeast99 {
		// Older than 9.9: must upgrade to gain hybrid PQC KEX support
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Upgrade to OpenSSH 10.0+ for built-in hybrid PQC key exchange",
			Type:      scan.WarningRecommendation,
			Details:   "OpenSSH 9.9 introduces the hybrid post-quantum key exchange (mlkem768x25519-sha256). OpenSSH 10.0 enables it by default. Upgrade to 10.0+ to get hybrid PQC KEX by default.",
			Kind:      scan.KindRecommendation,
			Severity:  3,
		})
		itemID++
	} else if anyAtLeast99 && !anyAtLeast100 {
		// 9.9+ but not 10.0: available but not default; ensure it is enabled
		kexHasHybrid := false
		if kex, ok := results["KexAlgorithms"]; ok && strings.Contains(kex, "mlkem768x25519-sha256") {
			kexHasHybrid = true
		}
		if !kexHasHybrid {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Enable hybrid PQC key exchange on OpenSSH 9.9+",
				Type:      scan.WarningRecommendation,
				Details:   "On OpenSSH 9.9–9.9.x, the hybrid KEX (mlkem768x25519-sha256) is available but not default. Add it to KexAlgorithms to enable.",
				Kind:      scan.KindRecommendation,
				Severity:  3,
				FixScript: "#!/bin/bash\nset -e\nCONF_DIR=\"/etc/ssh/sshd_config.d\"\nif [ -d \"$CONF_DIR\" ]; then\n  FILE=\"$CONF_DIR/99-pqc-kex.conf\"\n  printf \"KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\\n\" > \"$FILE\"\nelse\n  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)\n  printf \"\n# Enable hybrid PQC KEX\nKexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n\" >> /etc/ssh/sshd_config\nfi\nif command -v systemctl >/dev/null 2>&1; then systemctl restart sshd; else service sshd restart; fi\necho \"Hybrid PQC KEX enabled (mlkem768x25519-sha256)\"\n",
			})
			itemID++
		}
		// Optional: advise upgrade to 10.0+ for default behavior
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Plan upgrade to OpenSSH 10.0+ (hybrid PQC KEX becomes default)",
			Type:      scan.InfoRecommendation,
			Kind:      scan.KindRecommendation,
			Severity:  2,
		})
		itemID++
	} else if anyAtLeast100 {
		// 10.0+: default includes hybrid; warn if an explicit KexAlgorithms overrides it without the hybrid
		if kex, ok := results["KexAlgorithms"]; ok && !strings.Contains(kex, "mlkem768x25519-sha256") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Update KexAlgorithms to include hybrid PQC KEX (10.0+)",
				Type:      scan.WarningRecommendation,
				Details:   "OpenSSH 10.0+ defaults to mlkem768x25519-sha256, but an explicit KexAlgorithms directive appears to override the default without the hybrid KEX. Include the hybrid or remove the directive.",
				Kind:      scan.KindRecommendation,
				Severity:  3,
				FixScript: "#!/bin/bash\nset -e\nCONF_DIR=\"/etc/ssh/sshd_config.d\"\nif [ -d \"$CONF_DIR\" ]; then\n  FILE=\"$CONF_DIR/99-pqc-kex.conf\"\n  printf \"KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\\n\" > \"$FILE\"\nelse\n  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)\n  printf \"\n# Ensure hybrid PQC KEX on 10.0+\nKexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n\" >> /etc/ssh/sshd_config\nfi\nif command -v systemctl >/dev/null 2>&1; then systemctl restart sshd; else service sshd restart; fi\necho \"Hybrid PQC KEX ensured (mlkem768x25519-sha256)\"\n",
			})
			itemID++
		}
	}

	// Check if we're using a sample config
	if _, usingSample := results["UsingSampleConfig"]; usingSample {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Install OpenSSH server if you plan to use it",
			Type:      scan.InfoRecommendation,
			Kind:      scan.KindRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	}

	// Check if any fields are using defaults
	defaultFields := []string{}
	for _, field := range []string{"HostKeyAlgorithms", "PubkeyAcceptedAlgorithms", "CASignatureAlgorithms"} {
		if results[field] == "Default (not explicitly set)" {
			defaultFields = append(defaultFields, field)
		}
	}

	if len(defaultFields) > 0 {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Explicitly configure security algorithms",
			Type:      scan.WarningRecommendation,
			Details:   "Ensure HostKeyAlgorithms, PubkeyAcceptedAlgorithms, and CASignatureAlgorithms only include modern algorithms (e.g., ssh-ed25519, rsa-sha2-256, rsa-sha2-512). Avoid legacy algorithms like ssh-rsa (SHA-1) and ssh-dss (DSA).",
			Kind:      scan.KindRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	}

	// Check for ssh-rsa
	hasLegacy := false
	for _, field := range []string{"HostKeyAlgorithms", "PubkeyAcceptedAlgorithms", "CASignatureAlgorithms"} {
		if strings.Contains(results[field], "ssh-rsa") {
			hasLegacy = true
			break
		}
	}

	if hasLegacy {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Remove 'ssh-rsa' from algorithm lists",
			Type:      scan.CriticalRecommendation,
			Details:   "ssh-rsa uses SHA-1, which is vulnerable to chosen-prefix attacks and collision attacks",
			Kind:      scan.KindRecommendation,
			Severity:  4, // High severity - critical for PQC implementation
			FixScript: "#!/bin/bash\n\n# Backup the SSH config file\ncp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)\n\n# Remove ssh-rsa from HostKeyAlgorithms\nif grep -q \"HostKeyAlgorithms\" /etc/ssh/sshd_config; then\n    sed -i 's/\\(HostKeyAlgorithms.*\\)ssh-rsa\\(.*\\)/\\1\\2/g' /etc/ssh/sshd_config\n    sed -i 's/HostKeyAlgorithms.*,\\s*,/HostKeyAlgorithms /g' /etc/ssh/sshd_config # Clean up double commas\nelse\n    echo \"HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\" >> /etc/ssh/sshd_config\nfi\n\n# Remove ssh-rsa from PubkeyAcceptedAlgorithms\nif grep -q \"PubkeyAcceptedAlgorithms\" /etc/ssh/sshd_config; then\n    sed -i 's/\\(PubkeyAcceptedAlgorithms.*\\)ssh-rsa\\(.*\\)/\\1\\2/g' /etc/ssh/sshd_config\n    sed -i 's/PubkeyAcceptedAlgorithms.*,\\s*,/PubkeyAcceptedAlgorithms /g' /etc/ssh/sshd_config # Clean up double commas\nelse\n    echo \"PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\" >> /etc/ssh/sshd_config\nfi\n\n# Remove ssh-rsa from CASignatureAlgorithms\nif grep -q \"CASignatureAlgorithms\" /etc/ssh/sshd_config; then\n    sed -i 's/\\(CASignatureAlgorithms.*\\)ssh-rsa\\(.*\\)/\\1\\2/g' /etc/ssh/sshd_config\n    sed -i 's/CASignatureAlgorithms.*,\\s*,/CASignatureAlgorithms /g' /etc/ssh/sshd_config # Clean up double commas\nelse\n    echo \"CASignatureAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\" >> /etc/ssh/sshd_config\nfi\n\n# Restart SSH service\nif command -v systemctl &> /dev/null; then\n    systemctl restart sshd\nelse\n    service sshd restart\nfi\n\necho \"ssh-rsa has been removed from SSH configuration\"\n",
		})
		itemID++
	}

	// Recommend modern algorithms
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Enable modern algorithms for better security",
		Type:      scan.InfoRecommendation,
		Details:   "ssh-ed25519 (EdDSA with Curve25519), ecdsa-sk (ECDSA with security keys), ed25519-sk (EdDSA with security keys)",
		Kind:      scan.KindRecommendation,
		Severity:  3, // Medium severity - important for PQC readiness
	})
	itemID++

	// Section 2: Host Key Recommendations
	sectionID = 2
	itemID = 1

	if hostKeysFound, exists := hostKeyResults["HostKeysFound"]; exists {
		// Check if we have RSA keys
		hasRSAKey := false
		hasED25519Key := false
		hasFIDO2Key := false

		for key := range hostKeyResults {
			if strings.Contains(key, "rsa") {
				hasRSAKey = true
			} else if strings.Contains(key, "ed25519") && !strings.Contains(key, "sk") {
				hasED25519Key = true
			} else if strings.Contains(key, "sk") {
				hasFIDO2Key = true
			}
		}

		// Host key specific recommendations
		if hostKeysFound == "true" || hostKeyResults["SampleData"] == "true" {
			if hasRSAKey {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Replace RSA keys, keep hybrid KEX - migrate to ED25519 until ML-DSA-87 available",
					Type:      scan.WarningRecommendation,
					Details:   "Keep ED25519 host keys until ML-DSA-87 is available in OpenSSH. " +
						"Plan to move hybrid key exchange from ML-KEM-768 to ML-KEM-1024 when OpenSSH supports it. " +
						"Current action: sudo rm /etc/ssh/ssh_host_rsa_key* && sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\" " +
						"Future: Monitor OpenSSH releases for ML-DSA-87 signature support and ML-KEM-1024 hybrid KEX.",
					Kind:      scan.KindRecommendation,
					Severity:  4, // High severity - critical for PQC transition planning
				})
				itemID++
			}

			if !hasED25519Key {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Generate ED25519 host keys (modern, preferred)",
					Type:      scan.WarningRecommendation,
					Details:   "Run: sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\"",
					Kind:      scan.KindRecommendation,
					Severity:  3, // Medium severity - important for PQC readiness
					FixScript: "#!/bin/bash\n\n# Generate ED25519 host key\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\"\n\n# Update SSH config to use the key\nif ! grep -q \"HostKey /etc/ssh/ssh_host_ed25519_key\" /etc/ssh/sshd_config; then\n    echo \"HostKey /etc/ssh/ssh_host_ed25519_key\" >> /etc/ssh/sshd_config\nfi\n\n# Restart SSH service\nif command -v systemctl &> /dev/null; then\n    systemctl restart sshd\nelse\n    service sshd restart\nfi\n\necho \"ED25519 host key generated and configured\"\n",
					DockerInsert: "{\"action\": \"generate\", \"component\": \"ssh_host_ed25519_key\", \"type\": \"ed25519\"}",
				})
				itemID++
			}

			if !hasFIDO2Key {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Consider using FIDO2 security keys if hardware is available",
					Type:      scan.InfoRecommendation,
					Details:   "Run: sudo ssh-keygen -t ecdsa-sk -f /etc/ssh/ssh_host_ecdsa_sk_key -N \"\"",
					Kind:      scan.KindRecommendation,
					Severity:  2, // Low-medium severity - informational but affects testing
				})
				itemID++
			}
		}
	}

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// OpenSSH and AWS load balancer coordination
		if _, ok := results["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate OpenSSH and AWS load balancer security configurations",
				Type:      scan.InfoRecommendation,
				Details:   "Your OpenSSH server runs behind an AWS load balancer. Consider these security coordination strategies:\n\n" +
					"- OpenSSH handles direct SSH connections (typically port 22) with PQC-ready key exchange\n" +
					"- AWS load balancer handles HTTP/HTTPS traffic termination\n" +
					"- Ensure both layers use strong cryptography: OpenSSH 10.0+ for SSH, modern SSL policies for load balancer\n" +
					"- Consider SSH key-based authentication with PQC-ready algorithms\n" +
					"- Monitor both OpenSSH updates and AWS SSL policy announcements\n\n" +
					"This dual-layer approach ensures comprehensive PQC preparation for both SSH and web traffic.",
				Kind:      scan.KindRecommendation,
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific OpenSSH deployment considerations
		if pqcReadiness, ok := results["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy alongside OpenSSH improvements",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. While upgrading OpenSSH to 10.0p2+ improves SSH security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites for web traffic protection.", pqcReadiness),
					Kind:      scan.KindRecommendation,
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// SSH access through AWS infrastructure recommendations
		if lbType, ok := results["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS infrastructure for secure OpenSSH access",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For secure OpenSSH deployment in AWS:\n\n" +
					"• Use AWS Systems Manager Session Manager for browser-based SSH access\n" +
					"• Implement AWS security groups to restrict SSH access (port 22)\n" +
					"• Consider AWS Certificate Manager for TLS certificates on load balancer\n" +
					"• Use AWS CloudTrail to log SSH access attempts\n" +
					"• Enable VPC Flow Logs for network traffic analysis\n\n" +
					"This infrastructure approach complements OpenSSH PQC improvements with AWS-native security features.", lbType),
				Kind:      scan.KindRecommendation,
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

package linux

import (
	"fmt"
	"strings"
	"mini-pqc/scan"
)

// generateNginxRecommendations creates structured recommendations based on nginx scan results
func generateNginxRecommendations(results map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["nginx"] // Module ID for nginx

	// Check if Nginx is installed
	if nginxInstalled, ok := results["Nginx Installed"]; ok && nginxInstalled == "No" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  1,
			ItemID:   1,
			Text:     "Install Nginx 1.25.x or later for best PQC support",
			Severity: 4, // High severity - critical for PQC implementation
		})
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  1,
			ItemID:   2,
			Text:     "When configuring, use OpenSSL 3.x with oqs-provider for PQC support",
			Severity: 4, // High severity - critical for PQC implementation
		})
		return recommendations
	}

	// Check NGINX version for PQC compatibility
	if nginxVer, ok := results["Nginx"]; ok {
		if strings.Contains(nginxVer, "1.20.") || strings.Contains(nginxVer, "1.21.") || 
		   strings.Contains(nginxVer, "1.22.") || strings.Contains(nginxVer, "1.23.") || 
		   strings.Contains(nginxVer, "1.24.") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  1,
				ItemID:   3,
				Text:     "Upgrade to Nginx 1.25.x+ compiled/linked against OpenSSL 3.5+ with CNSA-strength hybrid groups",
				Type:     scan.CriticalRecommendation,
				Details:  "Nginx 1.25.x+ compiled with OpenSSL 3.5+ provides native ML-KEM-1024/ML-DSA-87 support for CNSA 2.0 compliance.\n\n" +
					"Configuration steps:\n" +
					"1. Compile Nginx 1.25.x+ against OpenSSL 3.5+\n" +
					"2. Configure CNSA-strength hybrid groups:\n" +
					"   ```nginx\n" +
					"   ssl_conf_command Groups SecP384r1MLKEM1024:X25519MLKEM1024:MLKEM1024;\n" +
					"   ```\n" +
					"3. Use pure ML-KEM-1024 when client ecosystem supports it:\n" +
					"   ```nginx\n" +
					"   ssl_conf_command Groups MLKEM1024:SecP384r1MLKEM1024;\n" +
					"   ```\n\n" +
					"Verification (on-wire testing):\n" +
					"• Test hybrid negotiation: `openssl s_client -connect yoursite.com:443 -groups SecP384r1MLKEM1024`\n" +
					"• Verify key_share extension contains ML-KEM-1024 in TLS handshake\n" +
					"• Check Nginx error logs for successful hybrid group negotiation\n" +
					"• Monitor client compatibility during rollout\n\n" +
					"CNSA 2.0 requirements:\n" +
					"• SecP384r1MLKEM1024 provides CNSA-strength classical + quantum-safe hybrid\n" +
					"• Pure MLKEM1024 is the end-state target when client support matures",
				Severity: 5, // Very High severity - critical for CNSA compliance
			})
		}
	}

	// Check OpenSSL version
	if version, ok := results["OpenSSL Version"]; ok {
		if !strings.HasPrefix(version, "3.") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  2,
				ItemID:   1,
				Text:     fmt.Sprintf("Upgrade Nginx to use OpenSSL 3.x (3.1+ recommended; currently using %s)", version),
				Severity: 4, // High severity - critical for PQC implementation
			})
		}
	} else {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  2,
			ItemID:   2,
			Text:     "Ensure Nginx is compiled with OpenSSL 3.x (3.1+ recommended)",
			Severity: 4, // High severity - critical for PQC implementation
		})
	}

	// Check OQS provider
	if oqsProvider, ok := results["OQS Provider"]; ok {
		if oqsProvider == "Not found" || oqsProvider == "" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  3,
				ItemID:   1,
				Text:     "Build OpenSSL 3.x and oqs-provider from source, then compile NGINX against your custom OpenSSL build",
				Severity: 5, // Highest severity - critical missing PQC component
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  3,
				ItemID:   2,
				Text:     "Follow the official oqs-provider instructions for both build and provider activation: https://github.com/open-quantum-safe/oqs-provider",
				Severity: 4, // High severity - critical for PQC implementation
			})
			
			// Add note about complexity for older NGINX versions
			if nginxVer, ok := results["Nginx"]; ok {
				if strings.Contains(nginxVer, "1.20.") || strings.Contains(nginxVer, "1.21.") || 
				   strings.Contains(nginxVer, "1.22.") || strings.Contains(nginxVer, "1.23.") || 
				   strings.Contains(nginxVer, "1.24.") {
					recommendations = append(recommendations, scan.Recommendation{
						ModuleID: moduleID,
						SectionID:  3,
						ItemID:   3,
						Text:     "Note: For NGINX 1.20.1 and other older versions, PQC integration is complex and may require patching. Upgrading to NGINX 1.25.x+ is strongly recommended",
						Severity: 3, // Medium severity - important for PQC readiness
					})
				}
			}
		}
	} else {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  3,
			ItemID:   4,
			Text:     "Build OpenSSL 3.x and oqs-provider from source, then compile NGINX against your custom OpenSSL build",
			Severity: 5, // Highest severity - critical missing PQC component
		})
	}

	// Check OQS provider configuration
	if oqsProvider, ok := results["OQS Provider"]; ok && oqsProvider != "Not found" && oqsProvider != "" {
		if oqsConfigured, ok := results["OQS Provider Configured"]; !ok || oqsConfigured != "Yes" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  4,
				ItemID:   1,
				Text:     "Configure Nginx to use the OQS provider with 'ssl_conf_command Providers oqs;'",
				Severity: 4, // High severity - critical for PQC implementation
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  4,
				ItemID:   2,
				Text:     "Ensure OPENSSL_CONF environment variable is set correctly for Nginx service",
				Severity: 3, // Medium severity - important for PQC readiness
			})
		}
	}

	// Check TLS version configuration for PQC readiness
	itemID := 1
	
	// Check TLS 1.3 - Required for PQC
	if results["TLS 1.3"] != "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Enable TLS 1.3 with 'ssl_protocols TLSv1.2 TLSv1.3;' - ML-KEM (Kyber) is only available in TLS 1.3",
			Severity: 4, // High severity - critical for PQC implementation
			Details:  "Post-quantum key exchange mechanisms (ML-KEM/Kyber) require TLS 1.3. TLS 1.2 and earlier versions cannot support quantum-safe key agreement.",
		})
		itemID++
	}
	
	// Warn about TLS 1.2 - Problematic for full PQC
	if results["TLS 1.2"] == "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Migrate to TLS 1.3-only configuration for full PQC support",
			Type:     scan.WarningRecommendation,
			Severity: 3, // Medium severity - migration planning needed
			Details:  "Keep TLS 1.2 for legacy client compatibility temporarily but limit to AEAD+PFS cipher suites only (AES-GCM, ChaCha20-Poly1305 with ECDHE). " +
				"Post-quantum key exchange (ML-KEM-1024) is only available in TLS 1.3. " +
				"Plan to remove TLS 1.2 support once hybrid ML-KEM-1024 key exchange is widely supported by clients and infrastructure. " +
				"Configure ssl_protocols TLSv1.3 TLSv1.2; and ssl_ciphers to restrict TLS 1.2 to AEAD+PFS only.",
		})
		itemID++
	}
	
	// Critical warnings for insecure TLS versions
	if results["TLS 1.1"] == "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Disable TLS 1.1 immediately - Insecure and incompatible with PQC",
			Severity: 5, // Critical severity - security risk
			Details:  "TLS 1.1 has known vulnerabilities and cannot support post-quantum cryptography. Remove 'TLSv1.1' from ssl_protocols directive.",
		})
		itemID++
	}
	
	if results["TLS 1.0"] == "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Disable TLS 1.0 immediately - Insecure and incompatible with PQC",
			Severity: 5, // Critical severity - security risk
			Details:  "TLS 1.0 has critical vulnerabilities and cannot support post-quantum cryptography. Remove 'TLSv1' from ssl_protocols directive.",
		})
		itemID++
	}
	
	if results["SSL 3.0"] == "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Disable SSL 3.0 immediately - Critically insecure",
			Severity: 5, // Critical severity - major security risk
			Details:  "SSL 3.0 is critically vulnerable (POODLE attack) and completely incompatible with modern cryptography. Remove 'SSLv3' from ssl_protocols directive.",
		})
		itemID++
	}
	
	if results["SSL 2.0"] == "Enabled" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  5,
			ItemID:   itemID,
			Text:     "Disable SSL 2.0 immediately - Critically insecure",
			Severity: 5, // Critical severity - major security risk
			Details:  "SSL 2.0 has fundamental design flaws and is completely insecure. Remove 'SSLv2' from ssl_protocols directive.",
		})
		itemID++
	}

	// Add OQS provider recommendations for OpenSSL 3.2-3.4 legacy option
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID: moduleID,
		SectionID:  5,
		ItemID:   itemID,
		Text:     "(Legacy option) Build with OQS provider if on OpenSSL 3.2–3.4",
		Type:     scan.CriticalRecommendation,
		Severity: 5, // VERY HIGH (only if OpenSSL < 3.5)
		Details:  "If upgrading to OpenSSL 3.5+ isn't possible yet, build OpenSSL 3.2–3.4 with the OQS provider and compile Nginx against it for PQC testing.\n\n" +
			"OQS provider instructions:\n" +
			"Follow: https://github.com/open-quantum-safe/oqs-provider",
	})
	itemID++

	// Check ML-KEM (Kyber) support
	if results["Kyber KEM Support"] == "Not configured" &&
		(results["Kyber in Includes"] == "" || results["Kyber in Includes"] == "Not found in included files") {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  6,
			ItemID:   1,
			Text:     "Add ML-KEM (Kyber) key exchange support",
			Details:  "For legacy OpenSSL/OQS: 'ssl_conf_command Curves kyber768:prime256v1;'. For OpenSSL 3.2+: 'ssl_conf_command Groups X25519MLKEM768:X25519;'.",
			Severity: 4,
		})
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID: moduleID,
			SectionID:  6,
			ItemID:   2,
			Text:     "Enable hybrid X25519+ML-KEM groups",
			Details:  "Legacy naming: 'ssl_conf_command Curves p256_kyber768:x25519_kyber768;'. New naming (OpenSSL 3.2+): 'ssl_conf_command Groups X25519MLKEM768:X25519;'.",
			Severity: 3,
		})
	}

	// Check PQC connection test results
	if sslConn, ok := results["SSL Connection"]; ok {
		if strings.EqualFold(sslConn, "Failed") {
			// Connection troubleshooting
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   1,
				Text:     "Could not connect to Nginx SSL port. Verify Nginx is running with 'systemctl status nginx'",
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   2,
				Text:     "Check if SSL is enabled on the tested port with 'grep -r listen /etc/nginx/'",
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   3,
				Text:     "Check Nginx error logs with 'tail -n 50 /var/log/nginx/error.log'",
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   4,
				Text:     "Ensure SSL certificates exist and are readable by Nginx",
			})
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   5,
				Text:     "If Nginx fails to start with 'library has no ciphers' error, set OPENSSL_CONF environment variable",
			})
		} else if pqcNegotiated, ok := results["PQC Negotiated"]; ok {
			if pqcNegotiated == "false" {
				// Handshake succeeded but no PQC
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID: moduleID,
					SectionID:  7,
					ItemID:   1,
					Text:     "PQC negotiation test failed: TLS handshake completed but no ML-KEM (Kyber) algorithm was used",
				})
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID: moduleID,
					SectionID:  7,
					ItemID:   2,
					Text:     "Check that 'ssl_conf_command Curves' includes Kyber algorithms and they are prioritized",
				})
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID: moduleID,
					SectionID:  7,
					ItemID:   3,
					Text:     "Verify that the OQS provider is properly loaded by Nginx at runtime",
				})
			} else if pqcNegotiated == "unknown" {
				// Could not determine KEX
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID: moduleID,
					SectionID:  7,
					ItemID:   4,
					Text:     "TLS handshake observed but key exchange could not be determined. Re-run with 'openssl s_client -groups' and verify curves include ML-KEM",
				})
			}
		}
	} else if pqcTest, ok := results["PQC Connection Test"]; ok {
		// Backward-compatibility with older scanner strings
		if strings.HasPrefix(strings.ToLower(pqcTest), "failed to connect") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID: moduleID,
				SectionID:  8,
				ItemID:   1,
				Text:     "Could not connect to Nginx SSL port. Verify Nginx is running with 'systemctl status nginx'",
			})
		}
	}

	// Add verification recommendation for PQC handshake
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID: moduleID,
		SectionID:  9,
		ItemID:   1,
		Text:     "After deployment, verify PQC is active using: 'openssl s_client -groups' to confirm PQC key exchange (e.g., X25519MLKEM768) is being negotiated",
		Severity: 3, // Medium severity - important for PQC readiness
	})

	// Add general recommendation to test configuration
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID: moduleID,
		SectionID:  9,
		ItemID:   2,
		Text:     "Test your configuration syntax with: 'nginx -t' (note: this only checks syntax, not PQC operation)",
	})

	return recommendations
}

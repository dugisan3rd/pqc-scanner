package linux

import (
	"fmt"
	"strings"

	"mini-pqc/scan"
)

// generateApacheRecommendations generates recommendations based on Apache scan results
func generateApacheRecommendations(results map[string]string) []scan.Recommendation {
	// Check if Apache is installed but not running
	installed, installedOk := results["Apache Installed"]
	status, statusOk := results["Apache Status"]
	
	// If Apache is not installed, return empty recommendations
	if !installedOk || installed == "No" {
		return []scan.Recommendation{}
	}
	
	// If Apache is installed but not running, add a note about this
	notRunning := !statusOk || status != "Running"
	
	// Still continue with recommendations since Apache is installed
	// But add a note about Apache not running if that's the case
	var recommendations []scan.Recommendation
	moduleID := scan.CommandModules["testapache"]
	sectionID := 1
	itemID := 1
	
	// Add a note if Apache is installed but not running
	if notRunning {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Type:      scan.WarningRecommendation,
			Text:      "Apache is installed but not running",
			Details:   "Apache is installed but not currently running. Start Apache to enable full testing of its PQC capabilities.",
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	}

	// Check if Apache is installed and provide PQC readiness guidance
	if installed, ok := results["Apache Installed"]; ok && installed == "No" {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Type:      scan.InfoRecommendation,
			Text:      "Apache HTTP Server is not installed",
			Details:   "If you plan to use Apache as your web server or TLS endpoint, ensure it is installed and properly configured. Apache is a widely used HTTP server that supports TLS via OpenSSL.",
			Severity:  1, // Low severity - purely informational
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Type:      scan.InfoRecommendation,
			Text:      "Configure Apache with OpenSSL 3.x and oqs-provider to enable post-quantum cryptography",
			Details: "To evaluate or deploy CNSA 2.0-aligned post-quantum algorithms (e.g., ML-KEM, ML-DSA), Apache must be linked against OpenSSL 3.x, and a compatible PQC provider (such as the Open Quantum Safe provider) must be configured. " +
				"Note that stock Apache packages do not yet support PQC providers by default—manual compilation of Apache with a custom OpenSSL+oqs build is currently required. " +
				"This setup is recommended for testing and pre-production environments where PQC-readiness evaluation is in scope. See: https://github.com/open-quantum-safe/oqs-provider",
			Severity:  3, // Medium severity - important for PQC readiness
		})
		return recommendations
	}

	// Check OpenSSL version used by Apache (or system default)
	if openSSLVersion, ok := results["OpenSSL Version"]; ok {
		if !strings.HasPrefix(openSSLVersion, "3.") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.WarningRecommendation,
				Text:      fmt.Sprintf("Upgrade to OpenSSL 3.x for post-quantum cryptographic support (detected version: %s)", openSSLVersion),
				Details: "OpenSSL 1.x and earlier do not support provider-based cryptography and cannot be used with post-quantum extensions such as the Open Quantum Safe (OQS) provider. " +
					"CNSA 2.0 mandates support for post-quantum key exchange (ML-KEM) and signature (ML-DSA) algorithms, which are only feasible in OpenSSL 3.x environments. " +
					"Upgrading to OpenSSL 3.x is a prerequisite for future-proofing your system against quantum threats and ensuring cryptographic agility.",
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		} else {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.SuccessRecommendation,
				Text:      fmt.Sprintf("Apache is using OpenSSL %s, which supports provider-based architecture", openSSLVersion),
				Details: "OpenSSL 3.x enables dynamic integration of cryptographic providers such as OQS for post-quantum algorithm support. This is foundational for enabling CNSA 2.0 readiness and adopting PQC primitives like ML-KEM and ML-DSA. " +
					"Ensure the appropriate provider (e.g., `oqs-provider`) is installed and configured to realize PQC capabilities.",
				Severity:  3, // Medium severity - positive but requires further action
			})
			itemID++
		}
	}

	// Apache + OQS Provider integration check
	if oqs, ok := results["OQS Provider"]; ok {
		if strings.Contains(oqs, "Installed") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.SuccessRecommendation,
				Text:      "OQS Provider is installed and available to Apache",
				Details: "The Open Quantum Safe (OQS) provider is installed and recognized by the OpenSSL instance used by Apache. " +
					"This enables experimental use of post-quantum algorithms such as ML-KEM and ML-DSA in TLS configurations. Note that " +
					"Apache must be compiled against this OpenSSL build to take advantage of these capabilities. Verify this through `apachectl -V` " +
					"and ensure LD_LIBRARY_PATH or dynamic linking reflects the correct OpenSSL+OQS linkage.",
				Severity:  4, // High severity - critical PQC component is present
			})
			itemID++
		} else {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.WarningRecommendation,
				Kind:      scan.KindRecommendation,
				Text:      "Install and configure the OQS Provider for OpenSSL used by Apache",
				Details: "The OQS Provider is not detected in the OpenSSL instance associated with Apache. Without it, Apache cannot negotiate " +
					"post-quantum key exchanges or signatures aligned with CNSA 2.0 guidance (e.g., ML-KEM and ML-DSA). " +
					"To enable PQC support in Apache, install OpenSSL 3.x with the OQS provider and ensure Apache is either dynamically linked or compiled " +
					"against this build. This configuration is recommended for labs, staging, and transition readiness evaluations, not production NSS use. " +
					"See setup guidance: https://github.com/open-quantum-safe/oqs-provider",
				Severity:  5, // Highest severity - critical missing PQC component
			})
			itemID++
		}
	}

	// TLS protocol and cipher hygiene (alignment with PQC readiness)
	tls13Enabled := (results["TLS 1.3"] == "Enabled")
	if !tls13Enabled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Enable and prefer TLS 1.3 in Apache (mod_ssl)",
			Type:      scan.WarningRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	} else {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Prefer TLS 1.3; restrict TLS 1.2 to ECDHE with AEAD only",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Informational but affects testing
		})
		itemID++
	}

	if ciphers, ok := results["SSL Ciphers"]; ok && ciphers != "" {
		cu := strings.ToUpper(ciphers)
		hasECDHE := strings.Contains(cu, "ECDHE") || strings.Contains(cu, "EECDH")
		hasAEAD := strings.Contains(cu, "GCM") || strings.Contains(cu, "CHACHA20") || strings.Contains(cu, "POLY1305")
		// Detect explicit RSA key exchange allowance via OpenSSL cipher alias 'kRSA'
		hasKxRSA := strings.Contains(cu, "KRSA")
		kxRSADisabled := strings.Contains(cu, "!KRSA")
		allowKxRSA := hasKxRSA && !kxRSADisabled

		if allowKxRSA || !hasECDHE {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Disable RSA key exchange; require ECDHE (PFS) for TLS 1.2 cipher suites",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}

		if !hasAEAD {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Use only AEAD cipher suites. For TLS 1.2, allow only AES-GCM or ChaCha20-Poly1305",
				Type:      scan.WarningRecommendation,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	} else {
		// If cipher string not detected, provide general guidance
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Ensure Apache SSLCipherSuite enforces ECDHE (PFS) and AEAD-only ciphers; exclude RSA key exchange",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Informational
		})
		itemID++
	}

	// Certificate strategy during PQC transition
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Plan migration to PQC/hybrid certificate signatures as ecosystem support matures; in the interim, prefer TLS 1.3 with ECDHE and short-lived certificates",
		Type:      scan.InfoRecommendation,
		Severity:  2, // Informational planning guidance
	})
	itemID++

	// Apache 2.4.x with OpenSSL 3.5+ and CNSA-strength hybrid groups
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Keep Apache 2.4.x but link to OpenSSL 3.5+ and configure CNSA-strength hybrid groups",
		Type:      scan.CriticalRecommendation,
		Details:   "Apache 2.4.x is sufficient for CNSA 2.0 compliance when properly linked to OpenSSL 3.5+ with CNSA-strength hybrid configuration.\n\n" +
			"Build requirements:\n" +
			"• Recompile/relink Apache 2.4.x against OpenSSL 3.5+\n" +
			"• Ensure mod_ssl uses the upgraded OpenSSL library\n\n" +
			"CNSA-strength hybrid group configuration:\n" +
			"```apache\n" +
			"SSLOpenSSLConfCmd Groups SecP384r1MLKEM1024:X25519MLKEM1024:MLKEM1024\n" +
			"```\n\n" +
			"Verification (on-wire testing):\n" +
			"• Test CNSA-strength hybrid: `openssl s_client -connect yoursite.com:443 -groups SecP384r1MLKEM1024`\n" +
			"• Verify key_share extension contains ML-KEM-1024 group code/name in handshake\n" +
			"• Check Apache error logs for successful hybrid group negotiation\n" +
			"• Monitor TLS handshake completion with hybrid groups\n\n" +
			"CNSA 2.0 compliance:\n" +
			"• SecP384r1MLKEM1024 provides CNSA-strength classical + quantum-safe hybrid\n" +
			"• X25519MLKEM1024 offers alternative hybrid with X25519 classical component\n" +
			"• Pure MLKEM1024 for future client ecosystem maturity\n" +
			"• OpenSSL 3.5+ required for native ML-KEM-1024 support without external providers",
		Severity:  5, // Very High severity - critical for CNSA compliance
	})
	itemID++

	// PQC monitoring guidance
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Track vendor TLS stacks for hybrid KEM availability and enable when supported by OpenSSL/mod_ssl and client ecosystem",
		Type:      scan.InfoRecommendation,
		Severity:  2, // Informational
	})
	itemID++

	// Check PQC connection test
	if pqcTest, ok := results["PQC Connection Test"]; ok {
		if strings.HasPrefix(pqcTest, "Success") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Successfully negotiated PQC algorithm in TLS handshake",
				Type:      scan.SuccessRecommendation,
				Severity:  5, // Highest severity - confirms end-to-end PQC functionality
			})
			itemID++
		} else if strings.HasPrefix(pqcTest, "Failed - Negotiated") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "PQC negotiation test failed: TLS handshake completed but no PQC algorithm was used",
				Type:      scan.WarningRecommendation,
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		} else if strings.HasPrefix(pqcTest, "Failed to connect") || strings.Contains(pqcTest, "Failed to connect") {
			// Start a new section for connection issues
			sectionID++
			itemID = 1
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Could not connect to Apache SSL port. Ensure SSL is properly configured and running",
				Type:      scan.WarningRecommendation,
			})
			itemID++
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Verify Apache is running with: 'systemctl status apache2'",
				Type:      scan.InfoRecommendation,
			})
			itemID++
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Check if SSL module is enabled: 'apache2ctl -M | grep ssl'",
				Type:      scan.InfoRecommendation,
			})
			itemID++
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Ensure SSL is properly configured in your virtual hosts",
				Type:      scan.InfoRecommendation,
			})
			itemID++
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Check if port 443 (or your configured SSL port) is open and not blocked by a firewall",
				Type:      scan.InfoRecommendation,
			})
			itemID++
		}
	}

	// Apache PQC TLS negotiation test
	if pqcTest, ok := results["PQC Connection Test"]; ok {
		if strings.HasPrefix(pqcTest, "Success") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.SuccessRecommendation,
				Text:      "Successfully negotiated a post-quantum cryptographic algorithm in TLS handshake",
				Details:   "Your Apache server successfully negotiated a PQC-capable TLS session, indicating that OpenSSL 3.x is correctly linked and the OQS provider is functioning as intended. This aligns with CNSA 2.0 migration goals for secure key establishment (ML-KEM) and digital signatures (ML-DSA).",
				Severity:  5, // Highest severity - confirms end-to-end PQC functionality
			})
			itemID++
		} else if strings.HasPrefix(pqcTest, "Failed - Negotiated") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.WarningRecommendation,
				Text:      "PQC negotiation failed: TLS connection succeeded, but classical cryptography was used",
				Details: "Although the TLS handshake succeeded, no post-quantum key agreement algorithm was negotiated. This likely indicates that the server's OpenSSL build does not have the OQS provider enabled, or the server cipher suites do not prioritize PQC algorithms. " +
					"Review Apache's SSL settings (e.g., `SSLCipherSuite` or `SSLPolicy`) and ensure the server uses the OpenSSL+OQS build. Consider using `openssl s_client -curves` to probe the available groups.",
				Severity:  4, // High severity - critical for PQC implementation
			})
			itemID++
		} else if strings.HasPrefix(pqcTest, "Failed to connect") || strings.Contains(pqcTest, "Failed to connect") {
			// New section for connectivity-level errors
			sectionID++
			itemID = 1
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.WarningRecommendation,
				Text:      "Failed to establish connection to Apache over TLS — check server status and SSL configuration",
				Details:   "The scanner could not establish a TLS connection to Apache. This may indicate Apache is not running, SSL is misconfigured, or port 443 is blocked.",
				Severity:  3, // Medium severity - important for PQC readiness assessment
			})
			itemID++

			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.InfoRecommendation,
				Text:      "Check Apache service status",
				Details:   "Run `systemctl status apache2` or `systemctl status httpd` depending on your OS to confirm the server is active.",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++

			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.InfoRecommendation,
				Text:      "Ensure SSL module is enabled in Apache",
				Details:   "Run `apache2ctl -M | grep ssl` to verify that mod_ssl is loaded. If not, enable it with `a2enmod ssl` (Debian-based) or ensure it's compiled in.",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++

			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.InfoRecommendation,
				Text:      "Review Apache SSL virtual host configuration",
				Details:   "Ensure your virtual host is configured with `SSLEngine on`, valid certificates, and the correct `SSLCertificateFile` and `SSLCertificateKeyFile` paths.",
				Severity:  2, // Low-medium severity - informational but affects testing
			})
			itemID++

			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Type:      scan.InfoRecommendation,
				Text:      "Check network access to port 443",
				Severity:  2, // Low-medium severity - informational but affects testing
				Details:   "Run `ss -tlnp | grep 443` or `netstat -tuln` to ensure Apache is listening. Use `ufw status` or `iptables -L` to check for firewall blocks.",
			})
			itemID++
		}
	}

	// Recommendation for validating PQC-related configuration changes
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Validate your PQC-ready Apache configuration",
		Type:      scan.InfoRecommendation,
		Details:   "After implementing PQC-related changes to your Apache configuration, validate them thoroughly:\n\n" +
			"Validation steps:\n" +
			"• Syntax check: Run 'apachectl configtest' to verify configuration syntax\n" +
			"• TLS handshake test: Use 'openssl s_client -connect your-server:443' to verify TLS connections\n" +
			"• Cipher suite verification: Check supported ciphers with 'nmap --script ssl-enum-ciphers -p 443 your-server'\n" +
			"• Certificate validation: Verify certificate properties with 'openssl x509 -in your-cert.pem -text -noout'\n\n" +
			"These validation steps are critical when implementing PQC-ready configurations to ensure both compatibility and security.",
		Severity:  2, // Low-medium severity - important for PQC implementation
	})

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := results["AWS Environment"]; ok && awsEnv != "" {
		sectionID = 3
		itemID = 1

		// SSL Policy upgrade recommendations for Apache behind AWS load balancer
		if lbPQC, ok := results["LB PQC Ready"]; ok {
			lbPQCVal := strings.ToLower(lbPQC)
			if lbPQCVal == "false" || strings.Contains(lbPQCVal, "needs upgrade") || strings.Contains(lbPQCVal, "poor") || lbPQCVal == "unknown" {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy for Apache backend",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current LB PQC readiness: %s. Consider upgrading the load balancer's SSL policy to support TLS 1.3 and modern AEAD cipher suites, which improves internet-facing crypto regardless of Apache's local configuration.", lbPQC),
					Severity:  4, // High severity - critical for internet-facing PQC readiness
				})
				itemID++
			}
		}

		// TLS protocol recommendations for load balancer
		if protocols, ok := results["Listener 1 Protocols"]; ok {
			if !strings.Contains(protocols, "TLSv1.3") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Configure AWS load balancer to support TLS 1.3 for Apache traffic",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current LB supported protocols: %s. While Apache may support modern TLS, internet-facing traffic is limited by the load balancer's SSL policy. Update the policy to include TLS 1.3 support for better PQC readiness.", protocols),
					Severity:  3, // Medium-high severity
				})
				itemID++
			}
		}

		// Load balancer and Apache coordination recommendations
		if clb, ok := results["Classic Load Balancer"]; ok && strings.TrimSpace(clb) != "" {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Consider migrating from Classic Load Balancer to Application Load Balancer for Apache",
				Type:      scan.InfoRecommendation,
				Details:   "Application Load Balancers (ALB) provide better SSL policy management and more modern cipher suites than Classic Load Balancers. This migration will improve PQC readiness for your Apache-backed application without requiring changes to Apache itself.",
				Severity:  2, // Low-medium severity
			})
			itemID++
		}

		// Apache-specific AWS load balancer recommendations
		hasALB := false
		if _, ok := results["Load Balancer ARN"]; ok { hasALB = true }
		hasCLB := false
		if v, ok := results["Classic Load Balancer"]; ok && strings.TrimSpace(v) != "" { hasCLB = true }
		if hasALB || hasCLB {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate Apache and AWS load balancer PQC preparation",
				Type:      scan.InfoRecommendation,
				Details:   "Your Apache server runs behind an AWS load balancer. For optimal PQC readiness:\n\n" +
					"• Focus load balancer upgrades on internet-facing crypto (SSL policies, TLS versions)\n" +
					"• Configure Apache for backend communication security (if using HTTPS between LB and Apache)\n" +
					"• Monitor AWS announcements for PQC-ready SSL policies\n" +
					"• Test both load balancer and Apache configurations independently\n\n" +
					"This dual-layer approach ensures comprehensive PQC preparation.",
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

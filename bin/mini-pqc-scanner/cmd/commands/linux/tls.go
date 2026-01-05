package linux

import (
	"crypto/tls"
	"fmt"
	"os/exec"
	"strings"
	"mini-pqc/scan"
)

// TestTLD runs a TLS scan on the specified domain and returns structured recommendations
func TestTLD(scanner *scan.TLSScanner, domain string) []scan.Recommendation {
	result := scanner.ScanTLS(domain, "443")
	fmt.Println("\n=== TLS Scan Results ===")
	fmt.Printf("Target: %s:443\n", domain)
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
	} else {
		// Display certificate information
		if result.Certificate != nil {
			fmt.Println("\nCertificate:")
			fmt.Printf("  Subject: %s\n", result.Certificate.Subject)
			fmt.Printf("  Issuer: %s\n", result.Certificate.Issuer)
			fmt.Printf("  Signature Algorithm: %s\n", result.Certificate.SignatureAlgorithm)
			fmt.Printf("  Not Before: %s\n", result.Certificate.NotBefore)
			fmt.Printf("  Not After: %s\n", result.Certificate.NotAfter)
			
			// Display certificate key type and quantum safety information
			if result.CertKeyInfo.Type != "" {
				if result.CertKeyInfo.Type == "RSA" {
					fmt.Printf("  Key Type: %s-%d\n", result.CertKeyInfo.Type, result.CertKeyInfo.Bits)
				} else if result.CertKeyInfo.Type == "ECDSA" {
					fmt.Printf("  Key Type: %s %s\n", result.CertKeyInfo.Type, result.CertKeyInfo.Curve)
				} else {
					fmt.Printf("  Key Type: %s\n", result.CertKeyInfo.Type)
				}
				
				// Display quantum safety warning
				if result.CertKeyInfo.IsQuantumSafe {
					fmt.Printf("  Quantum Safety: [PASS] Safe\n")
				} else {
					fmt.Printf("  Quantum Safety: [FAIL] Not Safe\n")
				}
				fmt.Printf("  %s\n", result.CertKeyInfo.QuantumWarning)
				
				// Display static RSA certificate warning
				if result.CertKeyInfo.IsStaticRSA {
					fmt.Printf("\n  [WARN] Static RSA Certificate Warning:\n")
					fmt.Printf("  %s\n", result.CertKeyInfo.StaticRSAWarning)
				}
			}
		}
		
		// Display TLS version information
		fmt.Printf("\nTLS Version: %s\n", tlsVersionToString(result.TLSVersion))
		
		// Display protocol support and compliance information
		fmt.Println("\nProtocol Support:")
		for version, supported := range result.SupportedProtocols {
			if supported {
				protocolName := tlsVersionToString(version)
				fmt.Printf("  - %s: Supported\n", protocolName)
			}
		}
		
		// Display cipher suite information
		fmt.Println("\nSupported Cipher Suites:")
		if len(result.SupportedCiphers) > 0 {
			// Group ciphers by protocol version for better readability
			ciphersByProtocol := make(map[uint16][]scan.CipherInfo)
			for _, cipher := range result.SupportedCiphers {
				ciphersByProtocol[cipher.Protocol] = append(ciphersByProtocol[cipher.Protocol], cipher)
			}
			
			// Display ciphers by protocol version
			for protocol, ciphers := range ciphersByProtocol {
				fmt.Printf("  %s:\n", tlsVersionToString(protocol))
				for _, cipher := range ciphers {
					if cipher.IsWeak {
						fmt.Printf("    - [WARN] %s (WEAK)\n", cipher.Name)
					} else {
						fmt.Printf("    - %s\n", cipher.Name)
					}
				}
			}
			
			// Display PFS status
			if result.HasPFS {
				fmt.Println("  [PASS] Perfect Forward Secrecy (PFS) is supported")
			} else {
				fmt.Println("  [WARN] Perfect Forward Secrecy (PFS) is NOT supported - security risk")
			}
		} else {
			fmt.Println("  No cipher information available")
		}
		
		// Display weak cipher details if any
		if len(result.WeakCiphers) > 0 {
			fmt.Println("\nWeak Cipher Details:")
			for _, cipher := range result.WeakCiphers {
				fmt.Printf("  [WARN] %s: %s\n", cipher.Name, cipher.WeakReason)
			}
		}
		
		// Display compliance status
		fmt.Println("\nCompliance Status:")
		if result.IsCompliant {
			fmt.Println("  [PASS] Server uses compliant protocols and cipher suites")
		} else {
			fmt.Println("  [FAIL] Server has compliance issues:")
			
			// Show deprecated protocols
			if len(result.DeprecatedProtocols) > 0 {
				fmt.Println("    - Deprecated protocol versions:")
				for _, deprecated := range result.DeprecatedProtocols {
					fmt.Printf("      - %s (security risk)\n", deprecated)
				}
			}
			
			// Show weak cipher issues
			if len(result.WeakCiphers) > 0 {
				fmt.Println("    - Weak cipher suites detected")
			}
			
			// Show PFS issues
			if !result.HasPFS {
				fmt.Println("    - No Perfect Forward Secrecy (PFS) support")
			}
			
			fmt.Println("    Only TLS 1.2+ with strong AEAD ciphers and PFS are recommended for security compliance.")
		}
		
		// Display PQC and hybrid key exchange groups
		if len(result.PQCGroups) > 0 {
			fmt.Println("\nPQC/Hybrid Key Exchange Groups:")
			for _, group := range result.PQCGroups {
				groupType := "Standalone PQC"
				if group.IsHybrid {
					groupType = "Hybrid (Classical+PQC)"
				}
				fmt.Printf("  - %s [%s]\n", group.Name, groupType)
			}
		}
		
		// Display PQC findings
		if result.IsPQCConfigured {
			fmt.Println("\nPQC Findings:")
			for _, finding := range result.PQCFindings {
				fmt.Printf("  - %s\n", finding)
			}
		} else {
			fmt.Println("\nNo PQC-related configurations detected.")
		}
	}
	
	// Create a results map for status items
	resultsMap := make(map[string]string)
	
	// Check AWS environment and load balancers for TLS domain context
	checkAWSEnvironmentForTLS(domain, resultsMap)
	
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Generate status items based on scan results
	resultsMap["TLS Library"] = "OpenSSL"
	resultsMap["Domain"] = domain
	if result.Certificate != nil {
		resultsMap["Certificate Subject"] = result.Certificate.Subject.String()
		resultsMap["Certificate Issuer"] = result.Certificate.Issuer.String()
		resultsMap["Signature Algorithm"] = result.Certificate.SignatureAlgorithm.String()
	}
	if result.CertKeyInfo.Type != "" {
		resultsMap["Key Type"] = result.CertKeyInfo.Type
		if result.CertKeyInfo.IsQuantumSafe {
			resultsMap["Quantum Safety"] = "Safe"
		} else {
			resultsMap["Quantum Safety"] = "Not Safe"
		}
	}
	if result.IsPQCConfigured {
		resultsMap["PQC Support"] = "Configured"
	} else {
		resultsMap["PQC Support"] = "Not Configured"
	}

	// Generate status items
	generateTLSStatus(resultsMap, rm)

	// Generate recommendations based on scan results
	recommendations := generateTLSRecommendations(result, resultsMap)

	// Add recommendations to the manager
	rm.AppendRecommendations(recommendations)

	// Get all recommendations and status items from the manager
	allRecommendations := rm.GetRecommendations()

	// Return all recommendations and status items
	return allRecommendations
}

// checkAWSEnvironmentForTLS checks AWS environment and load balancers for TLS domain context
func checkAWSEnvironmentForTLS(domain string, results map[string]string) {
	// Check if we're in AWS environment
	cmd := exec.Command("curl", "-s", "--connect-timeout", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	if err != nil {
		return // Not in AWS
	}
	
	instanceID := strings.TrimSpace(string(output))
	if instanceID == "" {
		return
	}
	
	results["AWS Environment"] = "Detected"
	results["EC2 Instance ID"] = instanceID
	
	// Check AWS CLI availability
	cmd = exec.Command("aws", "--version")
	_, err = cmd.Output()
	if err != nil {
		results["AWS CLI"] = "Not available"
		return
	}
	results["AWS CLI"] = "Available"
	
	// Note: For TLS domain testing, we show AWS context but the domain
	// testing itself will reveal the actual TLS configuration.
	// The load balancer discovery would require knowing which load balancer
	// serves this specific domain, which is more complex than instance-based discovery.
	
	fmt.Println("\nAWS LOAD BALANCER CONTEXT:")
	fmt.Printf("Testing domain %s from AWS environment (EC2 Instance: %s)\n", domain, instanceID)
	fmt.Println("Note: TLS test results show the actual internet-facing configuration.")
	fmt.Println("If this domain is served through an AWS Load Balancer, the results")
	fmt.Println("reflect the load balancer's SSL/TLS termination configuration.")
	fmt.Println("---------------------------------------------------------------------")
}

// Helper function to convert TLS version number to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

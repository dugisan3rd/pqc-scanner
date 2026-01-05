package linux

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"mini-pqc/scan"
)

// ParseCrtReport represents the structure of the JSON report for the parsecrt command
type ParseCrtReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	CertStats      map[string]int         `json:"cert_stats"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// CertInfo represents information about a certificate
type CertInfo struct {
	filename    string
	absPath     string
	subject     string
	issuer      string
	keyType     string
	keySize     int
	sigAlg      string
	expiry      time.Time
	category    string
	references  []ServiceReference
}

// ServiceReference represents a reference to a service using a certificate
type ServiceReference struct {
	serviceType string
	configFile  string
}

// findCertFiles returns a list of certificate files in the given directory
func findCertFiles(location string) []string {
	files, err := os.ReadDir(location)
	if err != nil {
		return []string{}
	}

	var certFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".crt") || strings.HasSuffix(file.Name(), ".pem") {
			certFiles = append(certFiles, filepath.Join(location, file.Name()))
		}
	}

	return certFiles
}

// parseCertificate parses a certificate file and returns its information
func parseCertificate(certFile string) (CertInfo, error) {
	certInfo := CertInfo{
		filename: filepath.Base(certFile),
		absPath:  certFile,
	}

	file, err := os.Open(certFile)
	if err != nil {
		return certInfo, err
	}
	defer file.Close()

	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return certInfo, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return certInfo, errors.New("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certInfo, err
	}

	certInfo.subject = cert.Subject.CommonName
	certInfo.issuer = cert.Issuer.CommonName
	certInfo.expiry = cert.NotAfter

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		certInfo.keyType = "RSA"
		certInfo.keySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		certInfo.keyType = "ECDSA"
	case *ed25519.PublicKey:
		certInfo.keyType = "Ed25519"
	case *dsa.PublicKey:
		certInfo.keyType = "DSA"
	default:
		certInfo.keyType = "Unknown"
	}

	return certInfo, nil
}

// findServiceReferences finds references to a certificate in service configurations
func findServiceReferences(certFile string) []ServiceReference {
	var references []ServiceReference

	// TO DO: implement service reference finding logic

	return references
}

// ParseCrt executes certificate parsing and analysis
func ParseCrt(verbose bool, jsonOutput bool) []scan.Recommendation {
    // Recommendation manager to collect status + recommendation items
    rm := &scan.RecommendationManager{}
	fmt.Println("\n=== Certificate File Analysis ===")
	fmt.Println("Scanning for certificate files (.crt, .pem) and analyzing them for PQC readiness...")
	fmt.Println("Categorizing certificates by usage priority...")
	fmt.Println("   HIGH PRIORITY: Certificates actively used by services")
	fmt.Println("   MEDIUM PRIORITY: Certificates not in trust store and not in active use")
	fmt.Println("   LOW PRIORITY: Trust store certificates (CA certs)")
	

	// Define common certificate locations to scan
	locations := []string{
		"/etc/ssl/certs",
		"/etc/pki",
		"/etc/nginx/ssl",
		"/etc/apache2/ssl",
		"/etc/postfix/ssl",
		"/etc/letsencrypt/live",
		"/opt",
	}

	// Track statistics
	stats := map[string]int{
		"total":        0,
		"rsa":          0,
		"ecdsa":        0,
		"ed25519":      0,
		"dsa":          0,
		"pqc":          0,
		"unknown":      0,
		"expiring2030": 0,
		"expired":      0,
		"used":         0,
	}

	// Track certificates with issues
	flaggedCerts := []string{}
	
	// Track certificates used by services
	serviceUsage := map[string][]ServiceReference{}
	
	// Store all certificates for categorized display
	var allCertificates []CertInfo

	// Scan each location
	for _, location := range locations {
		if _, err := os.Stat(location); os.IsNotExist(err) {
			continue
		}

		fmt.Printf("\nScanning %s...\n", location)
		certFiles := findCertFiles(location)
		
		for _, certFile := range certFiles {
			certInfo, err := parseCertificate(certFile)
			if err != nil {
				// Skip files that don't contain valid certificates
				continue
			}
			
			// Find service references for this certificate
			certInfo.references = findServiceReferences(certInfo.absPath)
			if len(certInfo.references) > 0 {
				stats["used"]++
				serviceUsage[certInfo.filename] = certInfo.references
				certInfo.category = "high" // High priority - actually in use
			} else {
				// Check if it's a system CA certificate
				if strings.HasPrefix(certInfo.absPath, "/etc/ssl/certs") || 
				   strings.HasPrefix(certInfo.absPath, "/etc/pki") ||
				   strings.Contains(certInfo.subject, "CA") || 
				   strings.Contains(certInfo.issuer, "CA") {
					certInfo.category = "low" // Low priority - trust store cert
				} else {
					certInfo.category = "medium" // Medium priority - not in use but not trust store
				}
			}
			
			stats["total"]++
			
			// Update stats based on key type
			switch certInfo.keyType {
			case "RSA":
				stats["rsa"]++
			case "ECDSA":
				stats["ecdsa"]++
			case "Ed25519":
				stats["ed25519"]++
			case "DSA":
				stats["dsa"]++
			case "PQC":
				stats["pqc"]++
			default:
				stats["unknown"]++
			}
			
			// Check expiration
			if certInfo.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
				stats["expiring2030"]++
				if certInfo.keyType == "RSA" || certInfo.keyType == "ECDSA" || certInfo.keyType == "DSA" {
					flaggedCerts = append(flaggedCerts, fmt.Sprintf("%s (%s %d-bit, expires %s)", 
						certInfo.filename, certInfo.keyType, certInfo.keySize, certInfo.expiry.Format("2006-01-02")))
				}
			}
			
			if certInfo.expiry.Before(time.Now()) {
				stats["expired"]++
			}
			
			// Store certificate for categorized display later
			allCertificates = append(allCertificates, certInfo)
		}
	}

	// Display certificates by priority category
	highPriorityCerts := []CertInfo{}
	mediumPriorityCerts := []CertInfo{}
	lowPriorityCerts := []CertInfo{}
	
	// Group certificates by priority
	for _, cert := range allCertificates {
		switch cert.category {
		case "high":
			highPriorityCerts = append(highPriorityCerts, cert)
		case "medium":
			mediumPriorityCerts = append(mediumPriorityCerts, cert)
		case "low":
			lowPriorityCerts = append(lowPriorityCerts, cert)
		}
	}
	
	// Display high priority certificates (in use)
	fmt.Println("\n=== HIGH PRIORITY CERTIFICATES (IN USE) ===")
	fmt.Printf("   Found %d certificates actively used by services\n", len(highPriorityCerts))
	
	if len(highPriorityCerts) > 0 {
		for _, cert := range highPriorityCerts {
			fmt.Printf("\n  [*] %s\n", cert.filename)
			fmt.Printf("      Subject: %s\n", cert.subject)
			fmt.Printf("      Issuer: %s\n", cert.issuer)
			fmt.Printf("      Key Type: %s", cert.keyType)
			if cert.keySize > 0 {
				fmt.Printf(" (%d-bit)", cert.keySize)
			}
			fmt.Println()
			fmt.Printf("      Signature Algorithm: %s\n", cert.sigAlg)
			fmt.Printf("      Expires: %s", cert.expiry.Format("2006-01-02"))
			
			// Add warning for non-PQC algorithms with long expiry
			if cert.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) && 
				(cert.keyType == "RSA" || cert.keyType == "ECDSA" || cert.keyType == "DSA") {
				fmt.Printf(" [!] CNSA-2030 NON-COMPLIANT")
			}
			fmt.Println()
			
			// Show service usage
			fmt.Printf("      Used by: %d service(s)\n", len(cert.references))
			for i, ref := range cert.references {
				if i < 5 { // Show up to 5 references for high priority certs
					fmt.Printf("        - %s (%s)\n", ref.serviceType, filepath.Base(ref.configFile))
				} else if i == 5 {
					fmt.Printf("        - ... and %d more\n", len(cert.references)-5)
					break
				}
			}
		}
	} else {
		fmt.Println("   No certificates found in active use by services")
	}
	
	// Display medium priority certificates
	fmt.Println("\n=== MEDIUM PRIORITY CERTIFICATES ===")
	fmt.Printf("   Found %d certificates not in trust store and not in active use\n", len(mediumPriorityCerts))
	
	if len(mediumPriorityCerts) > 0 {
		for _, cert := range mediumPriorityCerts {
			fmt.Printf("  - %s (%s", cert.filename, cert.keyType)
			if cert.keySize > 0 {
				fmt.Printf(" %d-bit", cert.keySize)
			}
			fmt.Printf(", expires %s)", cert.expiry.Format("2006-01-02"))
			
			// Add warning for non-PQC algorithms with long expiry
			if cert.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) && 
				(cert.keyType == "RSA" || cert.keyType == "ECDSA" || cert.keyType == "DSA") {
				fmt.Printf(" [!] CNSA-2030 NON-COMPLIANT")
			}
			fmt.Println()
		}
	} else {
		fmt.Println("   No medium priority certificates found")
	}
	
	// Display low priority certificates (trust store) only in verbose mode
	if verbose {
		fmt.Println("\n=== LOW PRIORITY CERTIFICATES (TRUST STORE) ===")
		fmt.Printf("   Found %d trust store certificates\n", len(lowPriorityCerts))
	} else {
		fmt.Println("\n=== LOW PRIORITY CERTIFICATES (TRUST STORE) ===")
		fmt.Printf("   Found %d trust store certificates (use -verbose to show details)\n", len(lowPriorityCerts))
	}
	
	// Count by algorithm type and long expiry for low priority certs
	lowPriorityStats := map[string]int{
		"rsa":          0,
		"ecdsa":        0,
		"ed25519":      0,
		"dsa":          0,
		"pqc":          0,
		"unknown":      0,
		"expiring2030": 0,
	}
	
	for _, cert := range lowPriorityCerts {
		switch cert.keyType {
		case "RSA":
			lowPriorityStats["rsa"]++
		case "ECDSA":
			lowPriorityStats["ecdsa"]++
		case "Ed25519":
			lowPriorityStats["ed25519"]++
		case "DSA":
			lowPriorityStats["dsa"]++
		case "PQC":
			lowPriorityStats["pqc"]++
		default:
			lowPriorityStats["unknown"]++
		}
		
		if cert.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
			lowPriorityStats["expiring2030"]++
		}
	}
	
	// Print summary of low priority certs only in verbose mode
	if verbose {
		fmt.Printf("   Trust store certificates by algorithm:\n")
		fmt.Printf("     - RSA: %d\n", lowPriorityStats["rsa"])
		fmt.Printf("     - ECDSA: %d\n", lowPriorityStats["ecdsa"])
		fmt.Printf("     - Ed25519: %d\n", lowPriorityStats["ed25519"])
		fmt.Printf("     - DSA: %d\n", lowPriorityStats["dsa"])
		fmt.Printf("     - PQC algorithms: %d\n", lowPriorityStats["pqc"])
		
		if lowPriorityStats["expiring2030"] > 0 {
			fmt.Printf("   Trust certificates valid beyond 2030: %d\n", lowPriorityStats["expiring2030"])
		}
		
		// In verbose mode, list all low priority certificates
		for _, cert := range lowPriorityCerts {
			fmt.Printf("  - %s (%s", cert.filename, cert.keyType)
			if cert.keySize > 0 {
				fmt.Printf(" %d-bit", cert.keySize)
			}
			fmt.Printf(", expires %s)", cert.expiry.Format("2006-01-02"))
			
			// Add warning for non-PQC algorithms with long expiry
			if cert.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) && 
				(cert.keyType == "RSA" || cert.keyType == "ECDSA" || cert.keyType == "DSA") {
				fmt.Printf(" [!] CNSA-2030 NON-COMPLIANT")
			}
			fmt.Println()
		}
	} else {
		// In non-verbose mode, just show a summary with focus on potential issues
		if lowPriorityStats["expiring2030"] > 0 {
			fmt.Printf("   Trust certificates valid beyond 2030: %d (potential future risk)\n", lowPriorityStats["expiring2030"])
		}
	}
	
	// Print summary
	fmt.Println("\n=== Certificate Analysis Summary ===")
	fmt.Printf("Total certificates found: %d\n", stats["total"])
	fmt.Printf("Priority breakdown:\n")
	fmt.Printf("  - High priority (in use): %d\n", len(highPriorityCerts))
	fmt.Printf("  - Medium priority: %d\n", len(mediumPriorityCerts))
	fmt.Printf("  - Low priority (trust store): %d\n", len(lowPriorityCerts))
	fmt.Printf("\nKey algorithms across all certificates:\n")
	fmt.Printf("  - RSA: %d\n", stats["rsa"])
	fmt.Printf("  - ECDSA: %d\n", stats["ecdsa"])
	fmt.Printf("  - Ed25519: %d\n", stats["ed25519"])
	fmt.Printf("  - DSA: %d\n", stats["dsa"])
	fmt.Printf("  - PQC algorithms: %d\n", stats["pqc"])
	fmt.Printf("  - Unknown: %d\n", stats["unknown"])
	fmt.Printf("\nExpiration:\n")
	fmt.Printf("  - Expired: %d\n", stats["expired"])
	fmt.Printf("  - Valid beyond 2030: %d\n", stats["expiring2030"])

	// Print flagged certificates only in verbose mode
	if verbose && len(flaggedCerts) > 0 {
		fmt.Println("\n[WARNING] Flagged Certificates (non-PQC with expiry beyond 2030):")
		for _, cert := range flaggedCerts {
			fmt.Printf("  - %s\n", cert)
		}
	}
	
	// Print service usage details
	if len(serviceUsage) > 0 {
		fmt.Println("\nCertificate Service Usage:")
		for certName, refs := range serviceUsage {
			fmt.Printf("  - %s used by:\n", certName)
			
			// Group by service type
			serviceGroups := map[string][]string{}
			for _, ref := range refs {
				serviceGroups[ref.serviceType] = append(serviceGroups[ref.serviceType], filepath.Base(ref.configFile))
			}
			
			for serviceType, configs := range serviceGroups {
				fmt.Printf("    • %s: %s\n", serviceType, strings.Join(configs, ", "))
			}
		}
	}

	// Generate status items based on overall statistics before creating recommendations
    generateParseCrtStatus(stats, rm)

    // Generate recommendations based on findings
	recs := generateCertRecommendations(stats, highPriorityCerts)
	rm.AppendRecommendations(recs)

    // Combined slice for JSON report and return
    recommendations := rm.GetRecommendations()

	// If JSON output is requested, create and save the report
	if jsonOutput {
		// Get server IP address
		var serverIP string
		
		// Get IP address from network interfaces
		addrs, err := net.InterfaceAddrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						serverIP = ipnet.IP.String()
						break
					}
				}
			}
		}
		
		// Default value if no IP found
		if serverIP == "" {
			serverIP = "unknown"
		}
		
		// Create report structure
		report := ParseCrtReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			CertStats:      stats,
			Recommendations: recommendations,
		}
		
		// Create report directory if it doesn't exist
		reportDir := "./report"
		if _, err := os.Stat(reportDir); os.IsNotExist(err) {
			os.MkdirAll(reportDir, 0755)
		}
		
		// Marshal report to JSON
		report.Recommendations = recommendations

        jsonData, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			// Write JSON to file
			filePath := filepath.Join(reportDir, "parsecrt.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/parsecrt.json")
			} else {
				fmt.Printf("\nError writing JSON report: %s\n", err)
			}
		} else {
			fmt.Printf("\nError creating JSON report: %s\n", err)
		}
	}

	return recommendations
}

package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"mini-pqc/scan"
)

// PGPKeyInfo holds information about a PGP key
type PGPKeyInfo struct {
	keyID       string
	keyType     string  // Changed from 'type' which is a reserved keyword
	size        string
	created     string
	expires     string
	fingerprint string
	usage       string
	algorithm   string
	isPQC       bool
}

// PGPReport represents the structure of the JSON report for the pgp command
type PGPReport struct {
	ServerIP       string                 `json:"server_ip"`
	ReportTime     string                 `json:"report_time"`
	GPGVersion     string                 `json:"gpg_version"`
	PQCKeys        []PGPKeyInfo           `json:"pqc_keys"`
	ClassicKeys    []PGPKeyInfo           `json:"classic_keys"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// MarshalJSON implements the json.Marshaler interface for PGPKeyInfo
func (k PGPKeyInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		KeyID       string `json:"key_id"`
		KeyType     string `json:"key_type"`
		Size        string `json:"size"`
		Created     string `json:"created"`
		Expires     string `json:"expires"`
		Fingerprint string `json:"fingerprint"`
		Usage       string `json:"usage"`
		Algorithm   string `json:"algorithm"`
		IsPQC       bool   `json:"is_pqc"`
	}{
		KeyID:       k.keyID,
		KeyType:     k.keyType,
		Size:        k.size,
		Created:     k.created,
		Expires:     k.expires,
		Fingerprint: k.fingerprint,
		Usage:       k.usage,
		Algorithm:   k.algorithm,
		IsPQC:       k.isPQC,
	})
}

// TestPGP checks PGP keys for PQC readiness
func TestPGP(jsonOutput bool) []scan.Recommendation {
    // Recommendation manager to collect status + recommendation items
    rm := &scan.RecommendationManager{}
	fmt.Println("\n=== PGP Key Analysis ===")
	fmt.Println("Checking for GnuPG installation and analyzing keys for PQC readiness...")

	// Check if GnuPG is installed
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		fmt.Println("GnuPG is not installed. Unable to analyze PGP keys.")
		fmt.Println("   To install GnuPG: sudo apt-get install gnupg")
		// Return recommendations even if GnuPG is not installed
		// Return empty slice via manager to include status zeros
        generatePGPStatus(0,0,0,rm)
        return rm.GetRecommendations()
	}

	fmt.Printf("GnuPG found: %s\n", gpgPath)
	
	// Get GnuPG version
	gpgVersion := getGPGVersion()
	fmt.Printf("   Version: %s\n", gpgVersion)
	
	// Check if we have input from stdin for testing
	var keys []PGPKeyInfo
	stdin := bufio.NewReader(os.Stdin)
	if stdinStat, _ := os.Stdin.Stat(); (stdinStat.Mode() & os.ModeCharDevice) == 0 {
		// Data is being piped to stdin
		fmt.Println("Reading key data from stdin (test mode)...")
		keys = parseGPGOutput(stdin)
	} else {
		// No data from stdin, use the normal keyring
		keys = listPGPKeys()
	}
	
	var pqcKeys, classicKeys []PGPKeyInfo
	if len(keys) == 0 {
        fmt.Println("No PGP keys found.")
        generatePGPStatus(0,0,0,rm)
        return rm.GetRecommendations()
    }
	
	fmt.Printf("\nFound %d PGP keys in the keyring\n", len(keys))
	
	// Analyze keys for PQC readiness
	pqcKeys, classicKeys = analyzeKeys(keys)
	
	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	awsResults := make(map[string]string)
	if awsData := inspectAWSLoadBalancerForPGP(); len(awsData) > 0 {
		for key, value := range awsData {
			awsResults[key] = value
		}
	}

	// Generate status items (module 9)
    generatePGPStatus(len(keys), len(pqcKeys), len(classicKeys), rm)
    
    // Generate AWS status items if available
    if len(awsResults) > 0 {
    	generatePGPAWSStatus(awsResults, rm)
    }

    // Generate recommendations
    recommendations := generatePGPRecommendations(pqcKeys, classicKeys, awsResults)
    rm.AppendRecommendations(recommendations)

    combined := rm.GetRecommendations()
	
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
		report := PGPReport{
			ServerIP:       serverIP,
			ReportTime:     time.Now().Format(time.RFC3339),
			GPGVersion:     getGPGVersion(),
			PQCKeys:        pqcKeys,
			ClassicKeys:    classicKeys,
			Recommendations: recommendations,
		}
		
		// Create report directory if it doesn't exist
		reportDir := "./report"
		if _, err := os.Stat(reportDir); os.IsNotExist(err) {
			os.MkdirAll(reportDir, 0755)
		}
		
		// Marshal report to JSON
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			// Write JSON to file
			filePath := filepath.Join(reportDir, "pgp.json")
			err = os.WriteFile(filePath, jsonData, 0644)
			if err == nil {
				fmt.Println("\nJSON report saved to report/pgp.json")
			} else {
				fmt.Printf("\nError writing JSON report: %s\n", err)
			}
		} else {
			fmt.Printf("\nError creating JSON report: %s\n", err)
		}
	}
	
	return combined
}

// getGPGVersion returns the installed GnuPG version
func getGPGVersion() string {
	cmd := exec.Command("gpg", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	
	return "Unknown"
}

// listPGPKeys returns a list of PGP keys in the keyring
func listPGPKeys() []PGPKeyInfo {
	var keys []PGPKeyInfo
	
	cmd := exec.Command("gpg", "--list-keys", "--with-keygrip", "--with-subkey-fingerprint")
	output, err := cmd.Output()
	if err != nil {
		return keys
	}
	
	return parseGPGOutput(strings.NewReader(string(output)))
}

// parseGPGOutput parses GPG output and returns a list of PGP keys
func parseGPGOutput(reader io.Reader) []PGPKeyInfo {
	var keys []PGPKeyInfo
	
	// Regular expressions to extract key information
	// Updated to handle hybrid key formats like "x25519+kyber768"
	pubKeyRegex := regexp.MustCompile(`pub\s+([\w+]+)\s+(\d{4}-\d{2}-\d{2})\s+\[(\w+)(?:\s+(\d{4}-\d{2}-\d{2}))?\]`)
	fingerprintRegex := regexp.MustCompile(`\s+([A-F0-9]{40})`)
	keyIDRegex := regexp.MustCompile(`\s+([A-F0-9]{16})`)
	// Note: We could add subkey regex support in the future if needed
	
	scanner := bufio.NewScanner(reader)
	
	var currentKey PGPKeyInfo
	var collectingKey bool
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Check for pub key line
		if matches := pubKeyRegex.FindStringSubmatch(line); matches != nil {
			if collectingKey {
				keys = append(keys, currentKey)
			}
			
			collectingKey = true
			
			// Extract algorithm and size from combined field (e.g., "rsa2048")
			algoWithSize := matches[1]
			algoName := ""
			size := ""
			
			// Check for hybrid key format (e.g., "x25519+kyber768")
			if strings.Contains(algoWithSize, "+") {
				// Handle hybrid key format
				algoName = algoWithSize
				// For hybrid keys, we don't extract a size since it's part of the algorithm name
				size = ""
			} else {
				// Extract algorithm name and size for standard keys
				algoSizeRegex := regexp.MustCompile(`(\D+)(\d+)`)
				if algoMatches := algoSizeRegex.FindStringSubmatch(algoWithSize); algoMatches != nil {
					algoName = algoMatches[1]
					size = algoMatches[2]
				} else {
					algoName = algoWithSize
					size = "unknown"
				}
			}
			
			currentKey = PGPKeyInfo{
				keyType:   algoName,
				size:      size,
				created:   matches[2],
				usage:     matches[3],
				expires:   matches[4],
				isPQC:     isPQCAlgorithm(algoName),
				algorithm: getAlgorithmName(algoName),
			}
		}
		
		// Check for fingerprint
		if matches := fingerprintRegex.FindStringSubmatch(line); matches != nil && collectingKey {
			currentKey.fingerprint = matches[1]
			currentKey.keyID = matches[1][24:] // Last 16 characters
		}
		
		// Check for key ID
		if matches := keyIDRegex.FindStringSubmatch(line); matches != nil && collectingKey && currentKey.keyID == "" {
			currentKey.keyID = matches[1]
		}
	}
	
	// Add the last key if we were collecting one
	if collectingKey {
		keys = append(keys, currentKey)
	}
	
	return keys
}

// analyzeKeys analyzes PGP keys for PQC readiness and returns slices of PQC and classic keys
func analyzeKeys(keys []PGPKeyInfo) ([]PGPKeyInfo, []PGPKeyInfo) {
	var pqcKeys, classicKeys []PGPKeyInfo
	
	for _, key := range keys {
		if key.isPQC {
			pqcKeys = append(pqcKeys, key)
		} else {
			classicKeys = append(classicKeys, key)
		}
	}
	
	// Print classic (non-PQC) keys
	fmt.Println("\nNon-Quantum-Safe Keys:")
	if len(classicKeys) == 0 {
		fmt.Println("   No non-quantum-safe keys found.")
	} else {
		for _, key := range classicKeys {
			fmt.Printf("   Key ID: %s\n", key.keyID)
			// Format algorithm display based on whether it's a standard or hybrid key
			if strings.Contains(key.keyType, "+") {
				// For hybrid keys, just display the algorithm name without size
				fmt.Printf("     Algorithm: %s\n", key.algorithm)
			} else if key.size != "" {
				// For standard keys with size, display algorithm and size
				fmt.Printf("     Algorithm: %s (%s)\n", key.algorithm, key.keyType+key.size)
			} else {
				// For standard keys without size, just display algorithm
				fmt.Printf("     Algorithm: %s\n", key.algorithm)
			}
			fmt.Printf("     Created: %s\n", key.created)
			if key.expires != "" {
				fmt.Printf("     Expires: %s\n", key.expires)
			} else {
				fmt.Printf("     Expires: Never [!] Consider setting an expiration date\n")
			}
			fmt.Printf("     Usage: %s\n", key.usage)
			fmt.Printf("     Fingerprint: %s\n", key.fingerprint)
			fmt.Println()
		}
	}
	
	// Print PQC keys (if any)
	fmt.Println("\nQuantum-Safe Keys:")
	if len(pqcKeys) == 0 {
		fmt.Println("   No quantum-safe keys found.")
	} else {
		for _, key := range pqcKeys {
			fmt.Printf("   Key ID: %s\n", key.keyID)
			// Format algorithm display based on whether it's a standard or hybrid key
			if strings.Contains(key.keyType, "+") {
				// For hybrid keys, just display the algorithm name without size
				fmt.Printf("     Algorithm: %s\n", key.algorithm)
			} else if key.size != "" {
				// For standard keys with size, display algorithm and size
				fmt.Printf("     Algorithm: %s (%s)\n", key.algorithm, key.keyType+key.size)
			} else {
				// For standard keys without size, just display algorithm
				fmt.Printf("     Algorithm: %s\n", key.algorithm)
			}
			fmt.Printf("     Created: %s\n", key.created)
			if key.expires != "" {
				fmt.Printf("     Expires: %s\n", key.expires)
			} else {
				fmt.Printf("     Expires: Never\n")
			}
			fmt.Printf("     Usage: %s\n", key.usage)
			fmt.Printf("     Fingerprint: %s\n", key.fingerprint)
			fmt.Println()
		}
	}
	
	// Print summary
	fmt.Println("\n=== PGP Key Summary ===")
	fmt.Printf("Total keys: %d\n", len(keys))
	fmt.Printf("Quantum-safe keys: %d\n", len(pqcKeys))
	fmt.Printf("Non-quantum-safe keys: %d\n", len(classicKeys))
	
	return pqcKeys, classicKeys
}

// isPQCAlgorithm checks if the algorithm is a post-quantum algorithm
func isPQCAlgorithm(algorithm string) bool {
	// Check for hybrid keys that include PQC algorithms
	if strings.Contains(strings.ToLower(algorithm), "kyber") ||
		strings.Contains(strings.ToLower(algorithm), "dilithium") ||
		strings.Contains(strings.ToLower(algorithm), "sphincs") ||
		strings.Contains(strings.ToLower(algorithm), "falcon") {
		return true
	}
	
	// Standard GnuPG 2.4.x doesn't support PQC algorithms
	// GnuPG 2.5.0+ supports experimental Kyber in hybrid mode
	return false
}

// getAlgorithmName returns a human-readable name for the algorithm
func getAlgorithmName(alg string) string {
	// Check for hybrid key formats (e.g., "x25519+kyber768")
	if strings.Contains(alg, "+") {
		parts := strings.Split(alg, "+")
		result := ""
		for i, part := range parts {
			if i > 0 {
				result += " + "
			}
			result += getAlgorithmName(part)
		}
		return result + " (Hybrid)"
	}

	// Handle standard algorithms
	switch strings.ToLower(alg) {
	case "rsa":
		return "RSA"
	case "dsa":
		return "DSA"
	case "elg":
		return "ElGamal"
	case "ed":
		return "EdDSA"
	case "cv", "x25519":
		return "Curve25519"
	case "kyber", "kyber768":
		return "Kyber (PQC)"
	case "dilithium":
		return "Dilithium (PQC)"
	case "falcon":
		return "Falcon (PQC)"
	case "sphincs":
		return "SPHINCS+ (PQC)"
	case "mldsa", "ml-dsa":
		return "ML-DSA (PQC)"
	default:
		if isPQCAlgorithm(alg) {
			return alg + " (PQC)"
		}
		return alg
	}
}

// Note: printPGPRecommendations has been replaced by generatePGPRecommendations in pgp_recommendations.go

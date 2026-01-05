package scan

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// LibraryScanner scans for PQC support in cryptographic libraries
type LibraryScanner struct{}

// NewLibraryScanner creates a new LibraryScanner
func NewLibraryScanner() *LibraryScanner {
	return &LibraryScanner{}
}

// LibraryScanResult contains the results of a library scan
type LibraryScanResult struct {
	LibraryName    string
	Version        string
	HasPQCSupport  bool
	IsPQCCapable   bool
	HasOQSProvider bool
	Error          error
	Details        string
}

// ScanOpenSSL checks the OpenSSL version and PQC capabilities
func (s *LibraryScanner) ScanOpenSSL() *LibraryScanResult {
	result := &LibraryScanResult{
		LibraryName: "OpenSSL",
	}

	// Run 'openssl version' command
	cmd := exec.Command("openssl", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Errorf("failed to run openssl command: %v", err)
		return result
	}

	// Parse the output
	versionOutput := strings.TrimSpace(string(output))
	result.Details = versionOutput

	// Extract version using regex
	re := regexp.MustCompile(`OpenSSL\s+(\d+\.\d+\.\d+\w*)`)
	matches := re.FindStringSubmatch(versionOutput)
	if len(matches) < 2 {
		result.Error = fmt.Errorf("could not parse OpenSSL version from: %s", versionOutput)
		return result
	}

	result.Version = matches[1]

	// Check if version has PQC support
	// OpenSSL 3.5+ has native ML-KEM/ML-DSA support, 3.2-3.4 requires OQS provider
	versionParts := strings.Split(result.Version, ".")
	if len(versionParts) >= 2 {
		major := versionParts[0]
		minor := versionParts[1]

		// Convert minor version to int for proper comparison
		minorInt := 0
		if minorVal, err := strconv.Atoi(minor); err == nil {
			minorInt = minorVal
		}

		// OpenSSL 3.5+ has native ML-KEM/ML-DSA support
		if major == "3" && minorInt >= 5 {
			result.HasPQCSupport = true
		} else if major == "3" && (minorInt >= 2 && minorInt <= 4) {
			// OpenSSL 3.2-3.4 is PQC-capable with OQS provider
			result.IsPQCCapable = true
		} else if major == "3" {
			// Other OpenSSL 3.x versions are PQC-capable with extensions
			result.IsPQCCapable = true
		}
	}

	// Check for OQS provider
	if major := versionParts[0]; major == "3" {
		// Try multiple methods to detect OQS provider
		
		// Method 1: Run 'openssl list -providers' command
		cmd := exec.Command("openssl", "list", "-providers")
		providerOutput, err := cmd.CombinedOutput()
		if err == nil {
			// Check if oqsprovider is in the output
			providerList := strings.ToLower(string(providerOutput))
			result.HasOQSProvider = strings.Contains(providerList, "oqsprovider") || strings.Contains(providerList, "oqs")
		}
		
		// Method 2: Check for OQS provider files
		if !result.HasOQSProvider {
			// Check common locations for OQS provider
			paths := []string{
				"/usr/lib/oqs-provider/",
				"/usr/local/lib/oqs-provider/",
				"/usr/lib/x86_64-linux-gnu/ossl-modules/",
				"/usr/local/lib/ossl-modules/",
				"/opt/oqs-provider/lib/",
				"./oqs-provider/build/lib/", // Local build location
			}
			
			for _, path := range paths {
				// Check for oqsprovider.so
				cmd := exec.Command("ls", path+"oqsprovider.so")
				if err := cmd.Run(); err == nil {
					result.HasOQSProvider = true
					result.Details += fmt.Sprintf("\nOQS provider found at: %soqsprovider.so", path)
					break
				}
				
				// Check for liboqsprov.so
				cmd = exec.Command("ls", path+"liboqsprov.so")
				if err := cmd.Run(); err == nil {
					result.HasOQSProvider = true
					result.Details += fmt.Sprintf("\nOQS provider found at: %sliboqsprov.so", path)
					break
				}
			}
		}
		
		// Method 3: Try with custom OpenSSL config
		if !result.HasOQSProvider {
			// Try with the custom OpenSSL config used by Nginx
			cmd := exec.Command("openssl", "list", "-providers")
			cmd.Env = append(cmd.Environ(), "OPENSSL_CONF=/etc/nginx/nginx.conf")
			providerOutput, err := cmd.CombinedOutput()
			if err == nil {
				providerList := strings.ToLower(string(providerOutput))
				if strings.Contains(providerList, "oqsprovider") || strings.Contains(providerList, "oqs") {
					result.HasOQSProvider = true
					result.Details += "\nOQS provider detected with Nginx configuration"
				}
			}
		}
	}

	return result
}

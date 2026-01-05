package linux

import (
	"os/exec"
	"strings"
)

// checkOpenSSLInstallation checks if OpenSSL is installed and gets its version
func checkOpenSSLInstallation(results map[string]string) {
	cmd := exec.Command("which", "openssl")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		results["OpenSSL"] = "Not installed"
		return
	}

	opensslPath := strings.TrimSpace(string(output))
	results["OpenSSL Path"] = opensslPath

	// Get OpenSSL version
	cmd = exec.Command("openssl", "version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		results["OpenSSL"] = "Installed (version unknown)"
		return
	}

	version := strings.TrimSpace(string(output))
	results["OpenSSL"] = version

	// Check if OQS provider is installed
	cmd = exec.Command("openssl", "list", "-providers")
	output, err = cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "oqsprovider") {
			results["OQS Provider"] = "Installed"
		} else {
			results["OQS Provider"] = "Not installed"
		}
	} else {
		results["OQS Provider"] = "Status unknown"
	}
}

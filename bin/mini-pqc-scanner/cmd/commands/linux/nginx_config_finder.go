package linux

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// FindNginxConfigFile attempts to locate the Nginx configuration file using multiple methods
// Returns the path to the config file and an error if not found
func FindNginxConfigFile() (string, error) {
	// Method 1: Try nginx -V to get the config path
	if configPath, err := findNginxConfViaNginxV(); err == nil {
		return configPath, nil
	}

	// Method 2: Check common paths
	if configPath := findNginxConfFallbackPaths(); configPath != "" {
		return configPath, nil
	}

	// Method 3: Use find command as a last resort
	if configPath := findNginxConfWithFind(); configPath != "" {
		return configPath, nil
	}

	return "", fmt.Errorf("Nginx configuration file not found")
}

// findNginxConfViaNginxV extracts the config path from `nginx -V` output
func findNginxConfViaNginxV() (string, error) {
	// Try to find nginx binary
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		return "", fmt.Errorf("Nginx binary not found in PATH")
	}

	// Run nginx -V to get config information
	cmd := exec.Command(nginxBin, "-V")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr // nginx -V outputs to stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Failed to run nginx -V: %v", err)
	}
	output := stderr.String()

	// Extract --conf-path and --prefix from output
	confPath := extractFlagValue(output, `--conf-path=(\S+)`)
	prefix := extractFlagValue(output, `--prefix=(\S+)`)

	if confPath != "" {
		// If path is relative, prepend prefix
		if !strings.HasPrefix(confPath, "/") && prefix != "" {
			confPath = prefix + "/" + confPath
		}
		
		// Verify the file exists
		if _, err := os.Stat(confPath); err == nil {
			return confPath, nil
		} else {
			return "", fmt.Errorf("Config path from build not found: %s", confPath)
		}
	}

	return "", fmt.Errorf("Could not extract config path from nginx -V")
}

// extractFlagValue extracts a value from a flag pattern in the input string
func extractFlagValue(input, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// findNginxConfFallbackPaths checks common Nginx config file paths
func findNginxConfFallbackPaths() string {
	paths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	}
	
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	return ""
}

// findNginxConfWithFind uses the find command to search for nginx.conf
func findNginxConfWithFind() string {
	// Use find with a timeout to prevent hanging on large filesystems
	cmd := exec.Command("find", "/", "-name", "nginx.conf", "-type", "f")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil // silence permission errors
	
	// Set a timeout using the timeout command
	timeoutCmd := exec.Command("timeout", "30", "sh", "-c", cmd.String())
	if err := timeoutCmd.Run(); err != nil {
		return ""
	}
	
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			// Prioritize /etc/nginx paths if found
			if strings.Contains(line, "/etc/nginx") {
				return line
			}
		}
	}
	
	// If no /etc/nginx path found, return the first result
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	
	return ""
}

// GetNginxSSLSettings extracts SSL-related settings from Nginx config
// Returns a map of SSL settings found in the config
func GetNginxSSLSettings(configPath string) (map[string]string, error) {
	sslSettings := make(map[string]string)
	
	// Try to find nginx binary
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		return sslSettings, fmt.Errorf("Nginx binary not found in PATH")
	}
	
	// Use nginx -T to dump the full configuration with includes
	cmd := exec.Command(nginxBin, "-T")
	outputBuf := &bytes.Buffer{}
	cmd.Stdout = outputBuf
	cmd.Stderr = outputBuf // nginx -T writes to stderr in some builds
	
	if err := cmd.Run(); err != nil {
		// If nginx -T fails, try to read the config file directly
		if configPath != "" {
			content, err := os.ReadFile(configPath)
			if err != nil {
				return sslSettings, fmt.Errorf("Failed to read Nginx config: %v", err)
			}
			parseNginxConfigForSSL(string(content), sslSettings)
		}
		return sslSettings, fmt.Errorf("Failed to run nginx -T: %v", err)
	}
	
	// Parse the full config output for SSL settings
	parseNginxConfigForSSL(outputBuf.String(), sslSettings)
	
	return sslSettings, nil
}

// parseNginxConfigForSSL extracts SSL-related settings from Nginx config content
func parseNginxConfigForSSL(configContent string, settings map[string]string) {
	// Look for SSL-related directives
	sslDirectives := []string{
		"ssl_protocols",
		"ssl_ciphers",
		"ssl_conf_command",
		"ssl_certificate",
		"ssl_certificate_key",
		"ssl_dhparam",
	}
	
	lines := strings.Split(configContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip commented lines
		if strings.HasPrefix(line, "#") {
			continue
		}
		
		for _, directive := range sslDirectives {
			if strings.HasPrefix(line, directive+" ") {
				settings[directive] = line
				
				// Special handling for ssl_protocols to extract individual TLS versions
				if directive == "ssl_protocols" {
					// Extract protocols from the line (e.g., "ssl_protocols TLSv1.2 TLSv1.3;")
					parts := strings.Fields(line)
					if len(parts) > 1 {
						// Join all protocol parts (skip "ssl_protocols" and remove semicolon)
						protocolsPart := strings.Join(parts[1:], " ")
						protocols := strings.TrimSuffix(protocolsPart, ";")
						settings["SSL Protocols"] = protocols
						
						// Check for specific TLS versions
						if strings.Contains(protocols, "TLSv1.3") {
							settings["TLS 1.3"] = "Enabled"
						} else {
							settings["TLS 1.3"] = "Not configured"
						}
						
						if strings.Contains(protocols, "TLSv1.2") {
							settings["TLS 1.2"] = "Enabled"
						}
						if strings.Contains(protocols, "TLSv1.1") {
							settings["TLS 1.1"] = "Enabled"
						}
						if strings.Contains(protocols, "TLSv1") && !strings.Contains(protocols, "TLSv1.") {
							settings["TLS 1.0"] = "Enabled"
						}
						if strings.Contains(protocols, "SSLv3") {
							settings["SSL 3.0"] = "Enabled"
						}
						if strings.Contains(protocols, "SSLv2") {
							settings["SSL 2.0"] = "Enabled"
						}
					}
				}
				break
			}
		}
		
		// Look for PQC-specific settings
		if strings.Contains(line, "kyber") || strings.Contains(line, "oqsprovider") {
			settings["PQC Settings"] = "Found"
		}
	}
}

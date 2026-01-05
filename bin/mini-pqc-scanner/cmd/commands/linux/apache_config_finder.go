package linux

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// FindApacheConfigFile attempts to locate the Apache configuration file using multiple methods
// Returns the path to the config file and an error if not found
func FindApacheConfigFile() (string, error) {
	// Method 1: Try apachectl or httpd -V
	if configPath, err := findApacheConfViaApachectl(); err == nil {
		return configPath, nil
	}

	// Method 2: Check common paths
	if configPath := findApacheConfFallbackPaths(); configPath != "" {
		return configPath, nil
	}

	// Method 3: Use find command as a last resort
	if configPath := findApacheConfWithFind(); configPath != "" {
		return configPath, nil
	}

	return "", fmt.Errorf("Apache configuration file not found")
}

// Try apachectl or httpd -V to find the config file
func findApacheConfViaApachectl() (string, error) {
	commands := [][]string{
		{"apachectl", "-V"},
		{"httpd", "-V"}, // RHEL/CentOS
	}

	re := regexp.MustCompile(`SERVER_CONFIG_FILE="(.*?)"`)

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1])
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue // Try next
		}

		matches := re.FindStringSubmatch(string(output))
		if len(matches) > 1 {
			configFile := matches[1]
			// Try to find full path (might be relative to ServerRoot)
			serverRoot := extractServerRoot(string(output))
			if !strings.HasPrefix(configFile, "/") && serverRoot != "" {
				configFile = serverRoot + "/" + configFile
			}
			return configFile, nil
		}
	}

	return "", fmt.Errorf("Apache config not found using apachectl/httpd -V")
}

// Extract SERVER_ROOT from Apache output
func extractServerRoot(output string) string {
	re := regexp.MustCompile(`-D SERVER_ROOT="(.*?)"`)
	match := re.FindStringSubmatch(output)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// Check common Apache config file paths
func findApacheConfFallbackPaths() string {
	paths := []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
		"/usr/local/apache2/conf/httpd.conf",
		"/usr/local/etc/apache24/httpd.conf",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// Use find command to search for Apache config files
func findApacheConfWithFind() string {
	cmd := exec.Command("find", "/", "-type", "f", "-name", "httpd.conf", "-o", "-name", "apache2.conf")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil // silence permission errors

	if err := cmd.Run(); err != nil {
		return ""
	}

	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	return ""
}

// FindApacheSSLConfigFiles attempts to locate Apache SSL configuration files
// Returns a slice of paths to SSL config files
func FindApacheSSLConfigFiles() []string {
	sslConfPaths := []string{
		"/etc/apache2/mods-enabled/ssl.conf",
		"/etc/apache2/mods-available/ssl.conf",
		"/etc/httpd/conf.d/ssl.conf",
		"/usr/local/apache2/conf/extra/httpd-ssl.conf",
	}

	var foundPaths []string
	for _, path := range sslConfPaths {
		if _, err := os.Stat(path); err == nil {
			foundPaths = append(foundPaths, path)
		}
	}

	return foundPaths
}

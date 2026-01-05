package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"mini-pqc/scan"
	"strings"
	"time"
)

// NginxAWSReport represents the structure of the JSON report for AWS Nginx inspection
type NginxAWSReport struct {
	ServerIP        string                 `json:"server_ip"`
	ReportTime      string                 `json:"report_time"`
	InstanceID      string                 `json:"instance_id"`
	NginxConfig     NginxAWSConfig         `json:"nginx_config"`
	LoadBalancers   []LoadBalancerInfo     `json:"load_balancers"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// NginxAWSConfig contains Nginx configuration analysis specific to AWS environments
type NginxAWSConfig struct {
	Version              string            `json:"version"`
	OpenSSLVersion       string            `json:"openssl_version"`
	ConfigPath           string            `json:"config_path"`
	RealIPConfiguration  bool              `json:"real_ip_configuration"`
	ProxyProtocol        bool              `json:"proxy_protocol"`
	SSLConfiguration     SSLConfig         `json:"ssl_configuration"`
	UpstreamConfiguration []UpstreamConfig `json:"upstream_configuration"`
}

// SSLConfig contains SSL/TLS configuration details
type SSLConfig struct {
	Enabled           bool     `json:"enabled"`
	Protocols         []string `json:"protocols"`
	Ciphers           []string `json:"ciphers"`
	CertificatePath   string   `json:"certificate_path"`
	PrivateKeyPath    string   `json:"private_key_path"`
	PQCReady          bool     `json:"pqc_ready"`
}

// UpstreamConfig contains upstream server configuration
type UpstreamConfig struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
	Method  string   `json:"method"`
}

// TestNginxAWS analyzes Nginx configuration in AWS environment with load balancer context
func TestNginxAWS(jsonOutput bool) []scan.Recommendation {
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Check if we're running in AWS environment
	if !isAWSEnvironment() {
		rm.AddStatus(22, 1, 1, "AWS Environment Detection: Not running in AWS environment", scan.InfoRecommendation, "AWS-specific Nginx analysis skipped", 1)
		return rm.GetRecommendations()
	}

	// Get instance ID
	instanceID := getInstanceID()
	if instanceID == "" {
		rm.AddStatus(22, 1, 2, "Instance ID Detection Failed", scan.WarningRecommendation, "Could not retrieve EC2 instance ID from metadata service", 3)
		return rm.GetRecommendations()
	}

	// Check if Nginx is installed
	nginxConfig := analyzeNginxAWSConfig(rm)
	if nginxConfig.Version == "" {
		rm.AddStatus(22, 1, 3, "Nginx Not Installed", scan.InfoRecommendation, "Nginx is not installed on this instance - AWS load balancer handles TLS termination", 1)
		return rm.GetRecommendations()
	}

	// Discover load balancers (reuse from aws_elb.go)
	loadBalancers := discoverLoadBalancers(instanceID, rm)

	// Analyze Nginx configuration in AWS context
	analyzeNginxAWSConfiguration(nginxConfig, loadBalancers, rm)

	// Generate recommendations for AWS-specific Nginx optimizations
	generateNginxAWSRecommendations(nginxConfig, loadBalancers, rm)

	// Generate JSON report if requested
	if jsonOutput {
		generateNginxAWSReport(instanceID, nginxConfig, loadBalancers, rm.GetRecommendations())
	}

	return rm.GetRecommendations()
}

// analyzeNginxAWSConfig analyzes Nginx configuration with AWS-specific considerations
func analyzeNginxAWSConfig(rm *scan.RecommendationManager) NginxAWSConfig {
	var config NginxAWSConfig

	// Get Nginx version
	cmd := exec.Command("nginx", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return config // Nginx not installed
	}

	versionLine := string(output)
	if strings.Contains(versionLine, "nginx/") {
		parts := strings.Split(versionLine, "nginx/")
		if len(parts) > 1 {
			config.Version = strings.TrimSpace(parts[1])
		}
	}

	// Get OpenSSL version used by Nginx
	cmd = exec.Command("nginx", "-V")
	output, err = cmd.CombinedOutput()
	if err == nil {
		if strings.Contains(string(output), "built with OpenSSL") {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "built with OpenSSL") {
					parts := strings.Split(line, "built with OpenSSL ")
					if len(parts) > 1 {
						versionPart := strings.Fields(parts[1])
						if len(versionPart) > 0 {
							config.OpenSSLVersion = "built with OpenSSL " + versionPart[0]
						}
					}
					break
				}
			}
		}
	}

	// Find Nginx configuration file
	config.ConfigPath = findNginxConfigPath()

	// Analyze configuration file
	if config.ConfigPath != "" {
		analyzeNginxConfigFile(config.ConfigPath, &config, rm)
	}

	return config
}

// findNginxConfigPath finds the main Nginx configuration file
func findNginxConfigPath() string {
	// Common paths for Nginx configuration
	paths := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Try to get from nginx -t
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "configuration file") && strings.Contains(line, "test is successful") {
				parts := strings.Split(line, " ")
				for i, part := range parts {
					if strings.HasSuffix(part, "nginx.conf") {
						return part
					}
					if part == "file" && i+1 < len(parts) {
						return parts[i+1]
					}
				}
			}
		}
	}

	return ""
}

// analyzeNginxConfigFile analyzes the Nginx configuration file for AWS-specific settings
func analyzeNginxConfigFile(configPath string, config *NginxAWSConfig, rm *scan.RecommendationManager) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		rm.AddStatus(22, 2, 1, "Nginx Configuration Read Failed", scan.WarningRecommendation, fmt.Sprintf("Failed to read Nginx configuration from %s: %v", configPath, err), 3)
		return
	}

	configText := string(content)

	// Check for real IP configuration (important for AWS load balancers)
	config.RealIPConfiguration = checkRealIPConfiguration(configText, rm)

	// Check for proxy protocol support
	config.ProxyProtocol = checkProxyProtocolConfiguration(configText, rm)

	// Analyze SSL configuration
	config.SSLConfiguration = analyzeSSLConfiguration(configText, rm)

	// Analyze upstream configuration
	config.UpstreamConfiguration = analyzeUpstreamConfiguration(configText, rm)
}

// checkRealIPConfiguration checks for proper real IP configuration for AWS load balancers
func checkRealIPConfiguration(configText string, rm *scan.RecommendationManager) bool {
	hasRealIPModule := strings.Contains(configText, "real_ip_header") || strings.Contains(configText, "set_real_ip_from")
	
	if hasRealIPModule {
		// Check for AWS-specific real IP configuration
		hasAWSConfig := strings.Contains(configText, "X-Forwarded-For") || strings.Contains(configText, "X-Real-IP")
		
		rm.AddStatus(22, 2, 2, "Real IP Configuration Detected", scan.InfoRecommendation, fmt.Sprintf("Nginx real IP module configured. AWS-compatible headers: %t", hasAWSConfig), 1)
		
		return hasAWSConfig
	}

	recommendation := scan.Recommendation{
		ModuleID:    22,
		SectionID:   2,
		ItemID:      3,
		Text:        "Missing Real IP Configuration",
		Type:        scan.WarningRecommendation,
		Kind:        scan.KindRecommendation,
		Severity:    4,
		Details:     "Nginx is missing real IP configuration for AWS load balancers. Client IPs will show as load balancer IPs.",
		FixScript:   generateRealIPConfigScript(),
	}
	rm.AppendRecommendations([]scan.Recommendation{recommendation})

	return false
}

// checkProxyProtocolConfiguration checks for proxy protocol support
func checkProxyProtocolConfiguration(configText string, rm *scan.RecommendationManager) bool {
	hasProxyProtocol := strings.Contains(configText, "proxy_protocol")
	
	if hasProxyProtocol {
		rm.AddStatus(22, 2, 4, "Proxy Protocol Configuration Detected", scan.InfoRecommendation, "Nginx is configured to handle proxy protocol from load balancers", 1)
	} else {
		rm.AddStatus(22, 2, 5, "No Proxy Protocol Configuration", scan.InfoRecommendation, "Nginx is not configured for proxy protocol. This may be intentional if using HTTP headers for client IP detection.", 2)
	}

	return hasProxyProtocol
}

// analyzeSSLConfiguration analyzes SSL/TLS configuration
func analyzeSSLConfiguration(configText string, rm *scan.RecommendationManager) SSLConfig {
	var sslConfig SSLConfig

	// Check if SSL is enabled
	sslConfig.Enabled = strings.Contains(configText, "ssl_certificate") || strings.Contains(configText, "listen 443")

	if !sslConfig.Enabled {
		rm.AddStatus(22, 3, 1, "SSL Not Configured in Nginx", scan.InfoRecommendation, "Nginx is not configured for SSL/TLS. This is expected if AWS load balancer handles TLS termination.", 1)
		return sslConfig
	}

	// Extract SSL protocols
	if strings.Contains(configText, "ssl_protocols") {
		// Simple extraction - in production, would use proper config parser
		lines := strings.Split(configText, "\n")
		for _, line := range lines {
			if strings.Contains(line, "ssl_protocols") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				protocolLine := strings.TrimSpace(line)
				parts := strings.Fields(protocolLine)
				for i, part := range parts {
					if part == "ssl_protocols" && i+1 < len(parts) {
						for j := i + 1; j < len(parts); j++ {
							protocol := strings.TrimSuffix(parts[j], ";")
							if protocol != "" {
								sslConfig.Protocols = append(sslConfig.Protocols, protocol)
							}
						}
						break
					}
				}
				break
			}
		}
	}

	// Extract SSL ciphers
	if strings.Contains(configText, "ssl_ciphers") {
		lines := strings.Split(configText, "\n")
		for _, line := range lines {
			if strings.Contains(line, "ssl_ciphers") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				// Extract cipher list (simplified)
				if strings.Contains(line, "ECDHE") || strings.Contains(line, "AES") {
					sslConfig.Ciphers = []string{"Modern cipher suite detected"}
				}
				break
			}
		}
	}

	// Check for PQC readiness
	sslConfig.PQCReady = checkNginxPQCReadiness(sslConfig.Protocols, sslConfig.Ciphers)

	// Add status item
	rm.AddStatus(22, 3, 2, "Nginx SSL Configuration", scan.InfoRecommendation, fmt.Sprintf("SSL enabled with %d protocols and %d cipher configurations. PQC ready: %t", len(sslConfig.Protocols), len(sslConfig.Ciphers), sslConfig.PQCReady), 1)

	return sslConfig
}

// analyzeUpstreamConfiguration analyzes upstream server configuration
func analyzeUpstreamConfiguration(configText string, rm *scan.RecommendationManager) []UpstreamConfig {
	var upstreams []UpstreamConfig

	// Simple upstream detection (in production, would use proper config parser)
	lines := strings.Split(configText, "\n")
	var currentUpstream *UpstreamConfig
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		if strings.HasPrefix(trimmed, "upstream ") {
			if currentUpstream != nil {
				upstreams = append(upstreams, *currentUpstream)
			}
			
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[1], " {")
				name = strings.TrimSuffix(name, "{")
				currentUpstream = &UpstreamConfig{Name: name}
			}
		} else if currentUpstream != nil && strings.HasPrefix(trimmed, "server ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				server := strings.TrimSuffix(parts[1], ";")
				currentUpstream.Servers = append(currentUpstream.Servers, server)
			}
		} else if currentUpstream != nil && trimmed == "}" {
			upstreams = append(upstreams, *currentUpstream)
			currentUpstream = nil
		}
	}

	if len(upstreams) > 0 {
		rm.AddStatus(22, 3, 3, "Upstream Configuration Detected", scan.InfoRecommendation, fmt.Sprintf("Found %d upstream configurations in Nginx", len(upstreams)), 1)
	}

	return upstreams
}

// checkNginxPQCReadiness checks if Nginx SSL configuration is PQC-ready
func checkNginxPQCReadiness(protocols []string, ciphers []string) bool {
	// Check for TLS 1.3 support
	hasTLS13 := false
	for _, protocol := range protocols {
		if strings.Contains(protocol, "TLSv1.3") {
			hasTLS13 = true
			break
		}
	}

	// For now, consider it PQC-ready if TLS 1.3 is supported
	// In the future, would check for specific PQC cipher suites
	return hasTLS13
}

// analyzeNginxAWSConfiguration analyzes Nginx configuration in the context of AWS load balancers
func analyzeNginxAWSConfiguration(nginxConfig NginxAWSConfig, loadBalancers []LoadBalancerInfo, rm *scan.RecommendationManager) {
	// Check if there are load balancers terminating SSL
	hasHTTPSLoadBalancer := false
	for _, lb := range loadBalancers {
		for _, listener := range lb.Listeners {
			if listener.Protocol == "HTTPS" || listener.Protocol == "SSL" {
				hasHTTPSLoadBalancer = true
				break
			}
		}
		if hasHTTPSLoadBalancer {
			break
		}
	}

	if hasHTTPSLoadBalancer && nginxConfig.SSLConfiguration.Enabled {
		recommendation := scan.Recommendation{
			ModuleID:    22,
			SectionID:   4,
			ItemID:      1,
			Text:        "Potential SSL Double Termination",
			Type:        scan.WarningRecommendation,
			Kind:        scan.KindRecommendation,
			Severity:    3,
			Details:     "Both AWS load balancer and Nginx are configured for SSL/TLS. Consider terminating SSL at load balancer only for better performance.",
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
	} else if hasHTTPSLoadBalancer && !nginxConfig.SSLConfiguration.Enabled {
		rm.AddStatus(22, 4, 2, "Optimal SSL Termination Configuration", scan.InfoRecommendation, "SSL/TLS is terminated at AWS load balancer level. Nginx handles HTTP traffic internally.", 1)
	}
}

// generateNginxAWSRecommendations generates AWS-specific recommendations for Nginx
func generateNginxAWSRecommendations(nginxConfig NginxAWSConfig, loadBalancers []LoadBalancerInfo, rm *scan.RecommendationManager) {
	// Recommend real IP configuration if missing
	if !nginxConfig.RealIPConfiguration {
		recommendation := scan.Recommendation{
			ModuleID:    22,
			SectionID:   5,
			ItemID:      1,
			Text:        "Configure Real IP Module for AWS Load Balancers",
			Type:        scan.WarningRecommendation,
			Kind:        scan.KindRecommendation,
			Severity:    4,
			Details:     "Configure Nginx real_ip module to properly handle client IPs from AWS load balancers",
			FixScript:   generateRealIPConfigScript(),
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
	}

	// Recommend security headers for AWS environment
	recommendation2 := scan.Recommendation{
		ModuleID:    22,
		SectionID:   5,
		ItemID:      2,
		Text:        "Add AWS-Specific Security Headers",
		Type:        scan.InfoRecommendation,
		Kind:        scan.KindRecommendation,
		Severity:    2,
		Details:     "Configure security headers optimized for AWS load balancer environment",
		FixScript:   generateAWSSecurityHeadersScript(),
	}
	rm.AppendRecommendations([]scan.Recommendation{recommendation2})

	// Recommend health check optimization
	recommendation3 := scan.Recommendation{
		ModuleID:    22,
		SectionID:   5,
		ItemID:      3,
		Text:        "Optimize Health Check Endpoint",
		Type:        scan.InfoRecommendation,
		Kind:        scan.KindRecommendation,
		Severity:    2,
		Details:     "Configure optimized health check endpoint for AWS load balancer health checks",
		FixScript:   generateHealthCheckScript(),
	}
	rm.AppendRecommendations([]scan.Recommendation{recommendation3})
}

// generateRealIPConfigScript generates script to configure real IP module
func generateRealIPConfigScript() string {
	return `#!/bin/bash
# Configure Nginx real_ip module for AWS load balancers

# Backup current configuration
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.$(date +%Y%m%d-%H%M%S)

# Add real IP configuration to http block
sudo tee -a /etc/nginx/conf.d/real-ip.conf << 'EOF'
# Real IP configuration for AWS load balancers
# AWS Classic Load Balancer IP ranges (update as needed)
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;

# AWS ALB/NLB IP ranges (update as needed)
set_real_ip_from 10.0.0.0/8;

# Use X-Forwarded-For header from load balancer
real_ip_header X-Forwarded-For;
real_ip_recursive on;
EOF

# Test configuration
sudo nginx -t

if [ $? -eq 0 ]; then
    echo "Configuration test passed. Reloading Nginx..."
    sudo systemctl reload nginx
    echo "Real IP configuration applied successfully"
else
    echo "Configuration test failed. Restoring backup..."
    sudo cp /etc/nginx/nginx.conf.backup.$(date +%Y%m%d-%H%M%S) /etc/nginx/nginx.conf
    exit 1
fi`
}

// generateAWSSecurityHeadersScript generates script for AWS-specific security headers
func generateAWSSecurityHeadersScript() string {
	return `#!/bin/bash
# Add AWS-optimized security headers to Nginx

sudo tee /etc/nginx/conf.d/security-headers.conf << 'EOF'
# Security headers optimized for AWS environment
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;

# AWS-specific headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Remove server version
server_tokens off;
EOF

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
echo "Security headers configured for AWS environment"`
}

// generateHealthCheckScript generates script for health check optimization
func generateHealthCheckScript() string {
	return `#!/bin/bash
# Configure optimized health check endpoint for AWS load balancers

sudo tee /etc/nginx/conf.d/health-check.conf << 'EOF'
# Health check endpoint for AWS load balancers
location /health {
    access_log off;
    return 200 "healthy\n";
    add_header Content-Type text/plain;
}

# Detailed health check with system info
location /health/detailed {
    access_log off;
    return 200 "healthy - nginx $(nginx -v 2>&1 | cut -d' ' -f3)\n";
    add_header Content-Type text/plain;
}
EOF

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
echo "Health check endpoints configured"`
}

// generateNginxAWSReport generates a JSON report for Nginx AWS inspection
func generateNginxAWSReport(instanceID string, nginxConfig NginxAWSConfig, loadBalancers []LoadBalancerInfo, recommendations []scan.Recommendation) {
	// Get server IP address
	serverIP := getServerIP()
	
	// Create report structure
	report := NginxAWSReport{
		ServerIP:        serverIP,
		ReportTime:      time.Now().Format(time.RFC3339),
		InstanceID:      instanceID,
		NginxConfig:     nginxConfig,
		LoadBalancers:   loadBalancers,
		Recommendations: recommendations,
	}
	
	// Create report directory if it doesn't exist
	reportDir := "./report"
	if _, err := os.Stat(reportDir); os.IsNotExist(err) {
		os.Mkdir(reportDir, 0755)
	}
	
	// Marshal to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Println("Error creating Nginx AWS JSON report:", err)
		return
	}
	
	// Write to file
	filename := fmt.Sprintf("%s/nginx-aws-report.json", reportDir)
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing Nginx AWS JSON report:", err)
		return
	}
	
	fmt.Printf("Nginx AWS report saved to: %s\n", filename)
}

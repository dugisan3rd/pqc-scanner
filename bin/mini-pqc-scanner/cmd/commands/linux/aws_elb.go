package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"mini-pqc/scan"
	"strings"
	"time"
)

// AWSELBReport represents the structure of the JSON report for AWS ELB inspection
type AWSELBReport struct {
	ServerIP        string                 `json:"server_ip"`
	ReportTime      string                 `json:"report_time"`
	InstanceID      string                 `json:"instance_id"`
	LoadBalancers   []LoadBalancerInfo     `json:"load_balancers"`
	Recommendations []scan.Recommendation  `json:"recommendations"`
}

// LoadBalancerInfo contains information about a discovered load balancer
type LoadBalancerInfo struct {
	Name        string              `json:"name"`
	ARN         string              `json:"arn,omitempty"`
	Type        string              `json:"type"` // classic, application, network
	Listeners   []ListenerInfo      `json:"listeners"`
	SSLPolicies []SSLPolicyInfo     `json:"ssl_policies"`
}

// ListenerInfo contains information about a load balancer listener
type ListenerInfo struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	ListenerARN string `json:"listener_arn,omitempty"`
	SSLPolicy   string `json:"ssl_policy,omitempty"`
}

// SSLPolicyInfo contains detailed SSL policy information
type SSLPolicyInfo struct {
	Name                string   `json:"name"`
	Protocols           []string `json:"protocols"`
	Ciphers             []string `json:"ciphers"`
	PQCReady            bool     `json:"pqc_ready"`
	RecommendedUpgrade  string   `json:"recommended_upgrade,omitempty"`
}

// TestAWSELB discovers and analyzes AWS load balancers for PQC readiness
func TestAWSELB(jsonOutput bool) []scan.Recommendation {
	// Create a recommendation manager to hold both status items and recommendations
	rm := scan.NewRecommendationManager()

	// Check if we're running in AWS environment
	if !isAWSEnvironment() {
		// Add status item indicating non-AWS environment
		rm.AddStatus(21, 1, 1, "AWS Environment Detection: Not running in AWS environment", scan.InfoRecommendation, "Load balancer inspection skipped", 1)
		return rm.GetRecommendations()
	}

	// Get instance ID
	instanceID := getInstanceID()
	if instanceID == "" {
		rm.AddStatus(21, 1, 2, "Instance ID Detection Failed", scan.WarningRecommendation, "Could not retrieve EC2 instance ID from metadata service", 3)
		return rm.GetRecommendations()
	}

	// Add status item with instance ID
	rm.AddStatus(21, 1, 3, fmt.Sprintf("EC2 Instance ID: %s", instanceID), scan.InfoRecommendation, "", 1)

	// Discover load balancers
	loadBalancers := discoverLoadBalancers(instanceID, rm)

	// Analyze each load balancer for PQC readiness
	for _, lb := range loadBalancers {
		analyzeLoadBalancerPQC(lb, rm)
	}

	// Generate JSON report if requested
	if jsonOutput {
		generateAWSELBReport(instanceID, loadBalancers, rm.GetRecommendations())
	}

	return rm.GetRecommendations()
}

// isAWSEnvironment checks if we're running in AWS
func isAWSEnvironment() bool {
	// Check for EC2 metadata service availability (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", "-s", "--max-time", "1", 
		"http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	
	if err != nil {
		return false
	}

	// Check if output looks like an instance ID
	instanceID := strings.TrimSpace(string(output))
	return len(instanceID) > 0 && strings.HasPrefix(instanceID, "i-")
}

// getInstanceID retrieves the EC2 instance ID from metadata service
func getInstanceID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", "-s", "--max-time", "1",
		"http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// discoverLoadBalancers discovers load balancers associated with the instance
func discoverLoadBalancers(instanceID string, rm *scan.RecommendationManager) []LoadBalancerInfo {
	var loadBalancers []LoadBalancerInfo

	// Check for Classic Load Balancers
	classicLBs := discoverClassicLoadBalancers(instanceID, rm)
	loadBalancers = append(loadBalancers, classicLBs...)

	// Check for Application/Network Load Balancers
	modernLBs := discoverModernLoadBalancers(instanceID, rm)
	loadBalancers = append(loadBalancers, modernLBs...)

	return loadBalancers
}

// discoverClassicLoadBalancers discovers Classic Load Balancers (ELB)
func discoverClassicLoadBalancers(instanceID string, rm *scan.RecommendationManager) []LoadBalancerInfo {
	var loadBalancers []LoadBalancerInfo

	// Check if AWS CLI is available
	if !isAWSCLIAvailable() {
		recommendation := scan.Recommendation{
			ModuleID:    21,
			SectionID:   2,
			ItemID:      1,
			Text:        "AWS CLI Not Available",
			Type:        scan.WarningRecommendation,
			Kind:        scan.KindRecommendation,
			Severity:    4,
			Details:     "AWS CLI is required for load balancer discovery. Install with: apt-get install awscli",
			FixScript:   generateAWSCLIInstallScript(),
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
		return loadBalancers
	}

	// Query for Classic Load Balancers
	cmd := exec.Command("aws", "elb", "describe-load-balancers",
		"--query", fmt.Sprintf("LoadBalancerDescriptions[?contains(Instances[].InstanceId, `%s`)].{Name:LoadBalancerName,Listeners:ListenerDescriptions}", instanceID),
		"--output", "json")
	
	output, err := cmd.Output()
	if err != nil {
		rm.AddStatus(21, 2, 2, "Classic Load Balancer Discovery Failed", scan.WarningRecommendation, fmt.Sprintf("Failed to query Classic Load Balancers: %v", err), 3)
		return loadBalancers
	}

	// Parse the JSON output
	var elbData []map[string]interface{}
	if err := json.Unmarshal(output, &elbData); err != nil {
		return loadBalancers
	}

	// Process each Classic Load Balancer
	for _, lb := range elbData {
		lbInfo := LoadBalancerInfo{
			Name: lb["Name"].(string),
			Type: "classic",
		}

		// Process listeners
		if listeners, ok := lb["Listeners"].([]interface{}); ok {
			for _, listener := range listeners {
				if listenerMap, ok := listener.(map[string]interface{}); ok {
					if listenerData, ok := listenerMap["Listener"].(map[string]interface{}); ok {
						port := int(listenerData["LoadBalancerPort"].(float64))
						protocol := listenerData["Protocol"].(string)
						
						listenerInfo := ListenerInfo{
							Port:     port,
							Protocol: protocol,
						}

						// Get SSL policy if it's an HTTPS/SSL listener
						if protocol == "HTTPS" || protocol == "SSL" {
							if sslPolicy, exists := listenerData["SSLCertificateId"]; exists {
								listenerInfo.SSLPolicy = fmt.Sprintf("Certificate: %v", sslPolicy)
							}
						}

						lbInfo.Listeners = append(lbInfo.Listeners, listenerInfo)
					}
				}
			}
		}

		loadBalancers = append(loadBalancers, lbInfo)

		// Add status item for discovered load balancer
		rm.AddStatus(21, 2, len(loadBalancers)+2, "Classic Load Balancer Discovered", scan.InfoRecommendation, fmt.Sprintf("Found Classic Load Balancer: %s with %d listeners", lbInfo.Name, len(lbInfo.Listeners)), 1)
	}

	return loadBalancers
}

// discoverModernLoadBalancers discovers Application/Network Load Balancers (ELBv2)
func discoverModernLoadBalancers(instanceID string, rm *scan.RecommendationManager) []LoadBalancerInfo {
	var loadBalancers []LoadBalancerInfo

	// Get target groups that contain this instance
	cmd := exec.Command("aws", "elbv2", "describe-target-groups",
		"--query", "TargetGroups[].TargetGroupArn",
		"--output", "text")
	
	output, err := cmd.Output()
	if err != nil {
		rm.AddStatus(21, 3, 1, "Target Group Discovery Failed", scan.WarningRecommendation, fmt.Sprintf("Failed to query target groups: %v", err), 3)
		return loadBalancers
	}

	targetGroups := strings.Fields(strings.TrimSpace(string(output)))

	// Check each target group for our instance
	for _, tgArn := range targetGroups {
		if strings.TrimSpace(tgArn) == "" {
			continue
		}

		// Check if this target group contains our instance
		cmd := exec.Command("aws", "elbv2", "describe-target-health",
			"--target-group-arn", tgArn,
			"--query", fmt.Sprintf("TargetHealthDescriptions[?Target.Id=='%s'].Target.Id", instanceID),
			"--output", "text")
		
		healthOutput, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(healthOutput)) == "" {
			continue // This target group doesn't contain our instance
		}

		// Get the load balancer for this target group
		cmd = exec.Command("aws", "elbv2", "describe-target-groups",
			"--target-group-arns", tgArn,
			"--query", "TargetGroups[0].LoadBalancerArns[0]",
			"--output", "text")
		
		lbArnOutput, err := cmd.Output()
		if err != nil {
			continue
		}

		lbArn := strings.TrimSpace(string(lbArnOutput))
		if lbArn == "" || lbArn == "None" {
			continue
		}

		// Get load balancer details
		lbInfo := getLoadBalancerDetails(lbArn, rm)
		if lbInfo.Name != "" {
			loadBalancers = append(loadBalancers, lbInfo)
		}
	}

	return loadBalancers
}

// getLoadBalancerDetails retrieves detailed information about a load balancer
func getLoadBalancerDetails(lbArn string, rm *scan.RecommendationManager) LoadBalancerInfo {
	var lbInfo LoadBalancerInfo

	// Get load balancer basic info
	cmd := exec.Command("aws", "elbv2", "describe-load-balancers",
		"--load-balancer-arns", lbArn,
		"--query", "LoadBalancers[0].{Name:LoadBalancerName,Type:Type}",
		"--output", "json")
	
	output, err := cmd.Output()
	if err != nil {
		return lbInfo
	}

	var lbData map[string]interface{}
	if err := json.Unmarshal(output, &lbData); err != nil {
		return lbInfo
	}

	lbInfo.Name = lbData["Name"].(string)
	lbInfo.ARN = lbArn
	lbInfo.Type = lbData["Type"].(string)

	// Get listeners
	cmd = exec.Command("aws", "elbv2", "describe-listeners",
		"--load-balancer-arn", lbArn,
		"--query", "Listeners[].{Port:Port,Protocol:Protocol,ListenerArn:ListenerArn,SslPolicy:SslPolicy}",
		"--output", "json")
	
	listenerOutput, err := cmd.Output()
	if err != nil {
		return lbInfo
	}

	var listenersData []map[string]interface{}
	if err := json.Unmarshal(listenerOutput, &listenersData); err != nil {
		return lbInfo
	}

	// Process listeners
	for _, listener := range listenersData {
		listenerInfo := ListenerInfo{
			Port:        int(listener["Port"].(float64)),
			Protocol:    listener["Protocol"].(string),
			ListenerARN: listener["ListenerArn"].(string),
		}

		if sslPolicy, exists := listener["SslPolicy"]; exists && sslPolicy != nil {
			listenerInfo.SSLPolicy = sslPolicy.(string)
		}

		lbInfo.Listeners = append(lbInfo.Listeners, listenerInfo)
	}

	// Add status item for discovered load balancer
	rm.AddStatus(21, 3, 2, fmt.Sprintf("%s Load Balancer Discovered", strings.Title(lbInfo.Type)), scan.InfoRecommendation, fmt.Sprintf("Found %s Load Balancer: %s with %d listeners", lbInfo.Type, lbInfo.Name, len(lbInfo.Listeners)), 1)

	return lbInfo
}

// analyzeLoadBalancerPQC analyzes a load balancer for PQC readiness
func analyzeLoadBalancerPQC(lb LoadBalancerInfo, rm *scan.RecommendationManager) {
	for _, listener := range lb.Listeners {
		if listener.Protocol == "HTTPS" || listener.Protocol == "SSL" || listener.Protocol == "TLS" {
			if listener.SSLPolicy != "" {
				analyzePolicyPQC(lb.Name, listener, rm)
			} else {
				// No SSL policy found for HTTPS listener
				recommendation := scan.Recommendation{
					ModuleID:    21,
					SectionID:   3,
					ItemID:      1,
					Text:        "Upgrade SSL Policy for PQC Readiness",
					Type:        scan.WarningRecommendation,
					Kind:        scan.KindRecommendation,
					Severity:    4,
					Details:     fmt.Sprintf("Load balancer %s listener on port %d has no SSL policy configured", lb.Name, listener.Port),
				}
				rm.AppendRecommendations([]scan.Recommendation{recommendation})
			}
		}
	}
}

// analyzePolicyPQC analyzes an SSL policy for PQC readiness
func analyzePolicyPQC(lbName string, listener ListenerInfo, rm *scan.RecommendationManager) {
	// Get SSL policy details
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies",
		"--names", listener.SSLPolicy,
		"--query", "SslPolicies[0].{Protocols:SupportedProtocols,Ciphers:Ciphers[].Name}",
		"--output", "json")
	
	output, err := cmd.Output()
	if err != nil {
		recommendation := scan.Recommendation{
			ModuleID:    21,
			SectionID:   3,
			ItemID:      2,
			Text:        "SSL Policy Analysis Failed",
			Type:        scan.WarningRecommendation,
			Kind:        scan.KindStatus,
			Severity:    3,
			Details:     fmt.Sprintf("Failed to analyze SSL policy %s: %v", listener.SSLPolicy, err),
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
		return
	}

	var policyData map[string]interface{}
	if err := json.Unmarshal(output, &policyData); err != nil {
		return
	}

	// Extract protocols and ciphers
	var protocols []string
	if prots, ok := policyData["Protocols"].([]interface{}); ok {
		for _, prot := range prots {
			protocols = append(protocols, prot.(string))
		}
	}

	var ciphers []string
	if ciphs, ok := policyData["Ciphers"].([]interface{}); ok {
		for _, ciph := range ciphs {
			ciphers = append(ciphers, ciph.(string))
		}
	}

	// Analyze for PQC readiness
	pqcReady := isELBPQCReady(protocols, ciphers)
	recommendedPolicy := getRecommendedPQCPolicy(listener.SSLPolicy)

	// Add status item for current policy
	recommendation := scan.Recommendation{
		ModuleID:    21,
		SectionID:   4,
		ItemID:      3,
		Text:        "SSL Policy Analysis",
		Type:        scan.InfoRecommendation,
		Kind:        scan.KindStatus,
		Severity:    1,
		Details:     fmt.Sprintf("Load balancer %s port %d uses policy %s with %d protocols and %d ciphers", lbName, listener.Port, listener.SSLPolicy, len(protocols), len(ciphers)),
	}
	rm.AppendRecommendations([]scan.Recommendation{recommendation})

	if !pqcReady {
		// Add recommendation for PQC upgrade
		recommendation := scan.Recommendation{
			ModuleID:    21,
			SectionID:   4,
			ItemID:      4,
			Text:        "Consider Certificate Rotation Strategy",
			Type:        scan.InfoRecommendation,
			Kind:        scan.KindRecommendation,
			Severity:    2,
			Details:     "Plan for certificate rotation to quantum-safe algorithms when available.",
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})

		recommendation = scan.Recommendation{
			ModuleID:    21,
			SectionID:   4,
			ItemID:      1,
			Text:        "Load Balancer SSL Policy Upgrade Required",
			Type:        scan.WarningRecommendation,
			Kind:        scan.KindRecommendation,
			Severity:    4,
			Details:     fmt.Sprintf("Load balancer %s requires SSL policy upgrade for PQC readiness. Current: %s, Recommended: %s", lbName, listener.SSLPolicy, recommendedPolicy),
			FixScript:   generatePolicyUpgradeScript(lbName, listener.ListenerARN, recommendedPolicy),
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
	} else {
		// Add status item for PQC-ready policy
		recommendation := scan.Recommendation{
			ModuleID:    21,
			SectionID:   4,
			ItemID:      5,
			Text:        "PQC-Ready SSL Policy",
			Type:        scan.InfoRecommendation,
			Kind:        scan.KindStatus,
			Severity:    1,
			Details:     fmt.Sprintf("Load balancer %s policy %s supports PQC-compatible protocols and ciphers", lbName, listener.SSLPolicy),
		}
		rm.AppendRecommendations([]scan.Recommendation{recommendation})
	}
}

// isELBPQCReady checks if an SSL policy supports PQC algorithms
func isELBPQCReady(protocols []string, ciphers []string) bool {
	// Check for TLS 1.3 support (required for PQC)
	hasTLS13 := false
	for _, protocol := range protocols {
		if protocol == "TLSv1.3" {
			hasTLS13 = true
			break
		}
	}

	if !hasTLS13 {
		return false
	}

	// Check for modern cipher suites that will support PQC
	modernCiphers := []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256",
	}

	hasModernCipher := false
	for _, cipher := range ciphers {
		for _, modern := range modernCiphers {
			if strings.Contains(cipher, modern) {
				hasModernCipher = true
				break
			}
		}
		if hasModernCipher {
			break
		}
	}

	return hasModernCipher
}

// getRecommendedPQCPolicy returns the recommended SSL policy for PQC readiness
func getRecommendedPQCPolicy(currentPolicy string) string {
	// AWS SSL policy recommendations for PQC readiness
	pqcPolicies := map[string]string{
		"ELBSecurityPolicy-2016-08":     "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS-1-0-2015-04": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS-1-1-2017-01": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS-1-2-2017-01": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		"ELBSecurityPolicy-TLS-1-2-Ext-2018-06": "ELBSecurityPolicy-TLS13-1-2-2021-06",
	}

	if recommended, exists := pqcPolicies[currentPolicy]; exists {
		return recommended
	}

	// Default recommendation
	return "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

// isAWSCLIAvailable checks if AWS CLI is available
func isAWSCLIAvailable() bool {
	_, err := exec.LookPath("aws")
	return err == nil
}

// generateAWSCLIInstallScript generates a script to install AWS CLI
func generateAWSCLIInstallScript() string {
	return `#!/bin/bash
# Install AWS CLI for load balancer discovery

# Detect OS and install AWS CLI
if command -v apt-get >/dev/null 2>&1; then
    # Ubuntu/Debian
    sudo apt-get update
    sudo apt-get install -y awscli
elif command -v yum >/dev/null 2>&1; then
    # RHEL/CentOS/Amazon Linux
    sudo yum install -y awscli
elif command -v dnf >/dev/null 2>&1; then
    # Fedora/newer RHEL
    sudo dnf install -y awscli
else
    echo "Unsupported package manager. Please install AWS CLI manually."
    echo "Visit: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Verify installation
if aws --version; then
    echo "AWS CLI installed successfully"
    echo "Configure with: aws configure"
else
    echo "AWS CLI installation failed"
    exit 1
fi`
}

// generatePolicyUpgradeScript generates a script to upgrade SSL policy
func generatePolicyUpgradeScript(lbName, listenerARN, recommendedPolicy string) string {
	return fmt.Sprintf(`#!/bin/bash
# Upgrade SSL policy for load balancer %s

# Backup current configuration
echo "Backing up current listener configuration..."
aws elbv2 describe-listeners --listener-arns %s > /tmp/listener-backup-$(date +%%Y%%m%%d-%%H%%M%%S).json

# Update SSL policy
echo "Updating SSL policy to %s..."
aws elbv2 modify-listener \
    --listener-arn %s \
    --ssl-policy %s

if [ $? -eq 0 ]; then
    echo "SSL policy updated successfully"
    echo "New policy: %s"
    echo "Load balancer: %s"
else
    echo "Failed to update SSL policy"
    echo "Check AWS CLI configuration and permissions"
    exit 1
fi

# Verify the change
echo "Verifying SSL policy change..."
aws elbv2 describe-listeners --listener-arns %s --query "Listeners[0].SslPolicy"`,
		lbName, listenerARN, recommendedPolicy, listenerARN, recommendedPolicy, recommendedPolicy, lbName, listenerARN)
}

// generateAWSELBReport generates a JSON report for AWS ELB inspection
func generateAWSELBReport(instanceID string, loadBalancers []LoadBalancerInfo, recommendations []scan.Recommendation) {
	// Get server IP address
	serverIP := getServerIP()
	
	// Create report structure
	report := AWSELBReport{
		ServerIP:        serverIP,
		ReportTime:      time.Now().Format(time.RFC3339),
		InstanceID:      instanceID,
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
		fmt.Println("Error creating AWS ELB JSON report:", err)
		return
	}
	
	// Write to file
	filename := fmt.Sprintf("%s/aws-elb-report.json", reportDir)
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing AWS ELB JSON report:", err)
		return
	}
	
	fmt.Printf("AWS ELB report saved to: %s\n", filename)
}

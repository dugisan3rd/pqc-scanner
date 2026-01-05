package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// checkAWSEnvironmentForApache checks AWS environment and load balancers for Apache context
func checkAWSEnvironmentForApache(results map[string]string) {
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
	
	// Discover load balancers associated with this instance
	discoverAWSLoadBalancersForApache(instanceID, results)
	
	fmt.Println("\nAWS LOAD BALANCER CONTEXT:")
	fmt.Printf("Apache running on AWS environment (EC2 Instance: %s)\n", instanceID)
	fmt.Println("Note: Apache configuration analysis shows instance-level settings.")
	fmt.Println("If Apache is behind an AWS Load Balancer, internet-facing crypto")
	fmt.Println("configuration may differ from local Apache SSL settings.")
	fmt.Println("---------------------------------------------------------------------")
}

// discoverAWSLoadBalancersForApache discovers load balancers associated with the Apache instance
func discoverAWSLoadBalancersForApache(instanceID string, results map[string]string) {
	// Try to find Classic Load Balancers
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--query", 
		"LoadBalancerDescriptions[?Instances[?InstanceId=='"+instanceID+"']].LoadBalancerName", 
		"--output", "text")
	output, err := cmd.Output()
	if err == nil {
		clbNames := strings.TrimSpace(string(output))
		if clbNames != "" && clbNames != "None" {
			results["Classic Load Balancer"] = clbNames
			analyzeClassicLoadBalancerSSLForApache(clbNames, results)
		}
	}
	
	// Try to find Application/Network Load Balancers via target groups
	cmd = exec.Command("aws", "elbv2", "describe-target-health", "--query", 
		"TargetHealthDescriptions[?Target.Id=='"+instanceID+"'].Target.Id", 
		"--output", "text")
	output, err = cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		// Instance is registered with target groups, find the load balancers
		cmd = exec.Command("aws", "elbv2", "describe-target-groups", "--query", 
			"TargetGroups[?Targets[?Id=='"+instanceID+"']].LoadBalancerArns[]", 
			"--output", "text")
		output, err = cmd.Output()
		if err == nil {
			lbArns := strings.TrimSpace(string(output))
			if lbArns != "" && lbArns != "None" {
				// Extract load balancer name from ARN
				for _, arn := range strings.Fields(lbArns) {
					parts := strings.Split(arn, "/")
					if len(parts) >= 2 {
						lbName := parts[1]
						results["Application Load Balancer"] = lbName
						results["Load Balancer ARN"] = arn
						analyzeApplicationLoadBalancerSSLForApache(arn, results)
						break // Use first load balancer found
					}
				}
			}
		}
	}
}

// analyzeClassicLoadBalancerSSLForApache analyzes Classic Load Balancer SSL configuration
func analyzeClassicLoadBalancerSSLForApache(clbName string, results map[string]string) {
	// Get Classic Load Balancer listeners
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--load-balancer-names", clbName, 
		"--query", "LoadBalancerDescriptions[0].ListenerDescriptions[?Listener.Protocol=='HTTPS']", 
		"--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	var listeners []map[string]interface{}
	err = json.Unmarshal(output, &listeners)
	if err != nil || len(listeners) == 0 {
		return
	}
	
	results["LB HTTPS Listeners"] = fmt.Sprintf("%d", len(listeners))
	results["LB Primary Port"] = "443"
	results["LB SSL Policy"] = "Classic-ELB-Policy" // Classic ELBs use predefined policies
	results["LB PQC Ready"] = "false" // Classic ELBs typically not PQC-ready
}

// analyzeApplicationLoadBalancerSSLForApache analyzes Application Load Balancer SSL configuration
func analyzeApplicationLoadBalancerSSLForApache(lbArn string, results map[string]string) {
	// Get ALB listeners
	cmd := exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", lbArn, 
		"--query", "Listeners[?Protocol=='HTTPS']", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	var listeners []map[string]interface{}
	err = json.Unmarshal(output, &listeners)
	if err != nil || len(listeners) == 0 {
		return
	}
	
	results["LB HTTPS Listeners"] = fmt.Sprintf("%d", len(listeners))
	
	// Analyze first HTTPS listener
	if len(listeners) > 0 {
		listener := listeners[0]
		if port, ok := listener["Port"].(float64); ok {
			results["LB Primary Port"] = fmt.Sprintf("%.0f", port)
		}
		
		// Get SSL policy
		if sslPolicy, ok := listener["SslPolicy"].(string); ok {
			results["LB SSL Policy"] = sslPolicy
			
			// Analyze SSL policy for PQC readiness
			analyzeSSLPolicyForPQCApache(sslPolicy, results)
		}
	}
}

// analyzeSSLPolicyForPQCApache analyzes SSL policy for PQC readiness
func analyzeSSLPolicyForPQCApache(sslPolicy string, results map[string]string) {
	// Get SSL policy details
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", sslPolicy, 
		"--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results["LB PQC Ready"] = "unknown"
		return
	}
	
	var policyResponse map[string]interface{}
	err = json.Unmarshal(output, &policyResponse)
	if err != nil {
		results["LB PQC Ready"] = "unknown"
		return
	}
	
	policies, ok := policyResponse["SslPolicies"].([]interface{})
	if !ok || len(policies) == 0 {
		results["LB PQC Ready"] = "unknown"
		return
	}
	
	policy := policies[0].(map[string]interface{})
	
	// Count ciphers and check for modern cipher suites
	ciphers, ok := policy["Ciphers"].([]interface{})
	if ok {
		results["LB Cipher Count"] = fmt.Sprintf("%d", len(ciphers))
		
		// Count modern cipher suites (simplified check)
		modernCount := 0
		for _, cipher := range ciphers {
			if cipherMap, ok := cipher.(map[string]interface{}); ok {
				if name, ok := cipherMap["Name"].(string); ok {
					if strings.Contains(name, "ECDHE") || strings.Contains(name, "CHACHA20") || 
					   strings.Contains(name, "AES-GCM") {
						modernCount++
					}
				}
			}
		}
		results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCount)
	}
	
	// Check supported protocols
	protocols, ok := policy["SupportedProtocols"].([]interface{})
	if ok {
		protocolList := make([]string, len(protocols))
		for i, proto := range protocols {
			protocolList[i] = proto.(string)
		}
		results["Listener 1 Protocols"] = strings.Join(protocolList, ", ")
		
		// Check for TLS 1.3 support (key for PQC readiness)
		hasTLS13 := false
		for _, proto := range protocolList {
			if proto == "TLSv1.3" {
				hasTLS13 = true
				break
			}
		}
		
		// Determine PQC readiness based on TLS 1.3 support and modern ciphers
		// Get modernCount from results if available
		modernCount := 0
		if modernCipherStr, ok := results["LB Modern Ciphers"]; ok {
			if count, err := fmt.Sscanf(modernCipherStr, "%d", &modernCount); err != nil || count != 1 {
				modernCount = 0
			}
		}
		
		if hasTLS13 && modernCount > 5 {
			results["LB PQC Ready"] = "true"
		} else {
			results["LB PQC Ready"] = "false"
		}
	} else {
		results["LB PQC Ready"] = "unknown"
	}
}

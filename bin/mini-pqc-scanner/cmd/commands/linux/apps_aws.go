package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// inspectAWSLoadBalancerForApps discovers AWS load balancers associated with the instance
// and analyzes their SSL/TLS configuration for application-level crypto inspection
func inspectAWSLoadBalancerForApps() map[string]string {
	results := make(map[string]string)

	// Check if we're running in AWS environment
	instanceID := getEC2InstanceIDForApps()
	if instanceID == "" {
		return results
	}

	results["AWS Environment"] = "EC2"
	results["AWS Instance ID"] = instanceID

	// Discover load balancers associated with this instance
	discoverAWSLoadBalancersForApps(instanceID, results)

	return results
}

// getEC2InstanceIDForApps retrieves the EC2 instance ID from metadata service
func getEC2InstanceIDForApps() string {
	// Try to get instance ID from EC2 metadata service
	cmd := exec.Command("curl", "-s", "--connect-timeout", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	instanceID := strings.TrimSpace(string(output))
	if instanceID == "" || strings.Contains(instanceID, "404") {
		return ""
	}

	return instanceID
}

// discoverAWSLoadBalancersForApps discovers both Classic and Application/Network Load Balancers
func discoverAWSLoadBalancersForApps(instanceID string, results map[string]string) {
	// Check if AWS CLI is available
	if !isAWSCLIAvailableForApps() {
		results["AWS CLI Status"] = "Not Available"
		return
	}
	results["AWS CLI Status"] = "Available"

	// Discover Classic Load Balancers (ELB)
	discoverClassicLoadBalancersForApps(instanceID, results)

	// Discover Application/Network Load Balancers (ALB/NLB)
	discoverApplicationLoadBalancersForApps(instanceID, results)
}

// isAWSCLIAvailableForApps checks if AWS CLI is installed and configured
func isAWSCLIAvailableForApps() bool {
	cmd := exec.Command("aws", "--version")
	return cmd.Run() == nil
}

// discoverClassicLoadBalancersForApps discovers Classic Load Balancers (ELB)
func discoverClassicLoadBalancersForApps(instanceID string, results map[string]string) {
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var elbResponse struct {
		LoadBalancerDescriptions []struct {
			LoadBalancerName string `json:"LoadBalancerName"`
			Instances        []struct {
				InstanceId string `json:"InstanceId"`
			} `json:"Instances"`
			ListenerDescriptions []struct {
				Listener struct {
					Protocol         string `json:"Protocol"`
					LoadBalancerPort int    `json:"LoadBalancerPort"`
					InstancePort     int    `json:"InstancePort"`
					SSLCertificateId string `json:"SSLCertificateId"`
				} `json:"Listener"`
				PolicyNames []string `json:"PolicyNames"`
			} `json:"ListenerDescriptions"`
		} `json:"LoadBalancerDescriptions"`
	}

	if err := json.Unmarshal(output, &elbResponse); err != nil {
		return
	}

	for _, elb := range elbResponse.LoadBalancerDescriptions {
		// Check if this instance is registered with this ELB
		for _, instance := range elb.Instances {
			if instance.InstanceId == instanceID {
				results["Load Balancer Type"] = "Classic Load Balancer (ELB)"
				results["Load Balancer Name"] = elb.LoadBalancerName

				// Analyze listeners for application-relevant ports
				analyzeELBListenersForApps(elb.LoadBalancerName, elb.ListenerDescriptions, results)
				return
			}
		}
	}
}

// discoverApplicationLoadBalancersForApps discovers Application/Network Load Balancers (ALB/NLB)
func discoverApplicationLoadBalancersForApps(instanceID string, results map[string]string) {
	// First, find target groups that contain this instance
	cmd := exec.Command("aws", "elbv2", "describe-target-groups", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var tgResponse struct {
		TargetGroups []struct {
			TargetGroupArn  string `json:"TargetGroupArn"`
			TargetGroupName string `json:"TargetGroupName"`
			Port            int    `json:"Port"`
			Protocol        string `json:"Protocol"`
		} `json:"TargetGroups"`
	}

	if err := json.Unmarshal(output, &tgResponse); err != nil {
		return
	}

	var relevantTargetGroups []string

	// Check each target group for this instance
	for _, tg := range tgResponse.TargetGroups {
		cmd := exec.Command("aws", "elbv2", "describe-target-health",
			"--target-group-arn", tg.TargetGroupArn, "--output", "json")
		healthOutput, err := cmd.Output()
		if err != nil {
			continue
		}

		var healthResponse struct {
			TargetHealthDescriptions []struct {
				Target struct {
					Id   string `json:"Id"`
					Port int    `json:"Port"`
				} `json:"Target"`
			} `json:"TargetHealthDescriptions"`
		}

		if err := json.Unmarshal(healthOutput, &healthResponse); err != nil {
			continue
		}

		// Check if this instance is in this target group
		for _, target := range healthResponse.TargetHealthDescriptions {
			if target.Target.Id == instanceID {
				relevantTargetGroups = append(relevantTargetGroups, tg.TargetGroupArn)
				break
			}
		}
	}

	if len(relevantTargetGroups) == 0 {
		return
	}

	// Find load balancers associated with these target groups
	cmd = exec.Command("aws", "elbv2", "describe-load-balancers", "--output", "json")
	output, err = cmd.Output()
	if err != nil {
		return
	}

	var lbResponse struct {
		LoadBalancers []struct {
			LoadBalancerArn  string `json:"LoadBalancerArn"`
			LoadBalancerName string `json:"LoadBalancerName"`
			Type             string `json:"Type"`
		} `json:"LoadBalancers"`
	}

	if err := json.Unmarshal(output, &lbResponse); err != nil {
		return
	}

	for _, lb := range lbResponse.LoadBalancers {
		// Get listeners for this load balancer
		cmd := exec.Command("aws", "elbv2", "describe-listeners",
			"--load-balancer-arn", lb.LoadBalancerArn, "--output", "json")
		listenerOutput, err := cmd.Output()
		if err != nil {
			continue
		}

		var listenerResponse struct {
			Listeners []struct {
				ListenerArn     string `json:"ListenerArn"`
				Port            int    `json:"Port"`
				Protocol        string `json:"Protocol"`
				SslPolicy       string `json:"SslPolicy"`
				DefaultActions  []struct {
					TargetGroupArn string `json:"TargetGroupArn"`
				} `json:"DefaultActions"`
			} `json:"Listeners"`
		}

		if err := json.Unmarshal(listenerOutput, &listenerResponse); err != nil {
			continue
		}

		// Check if any listener targets our target groups
		for _, listener := range listenerResponse.Listeners {
			for _, action := range listener.DefaultActions {
				for _, tgArn := range relevantTargetGroups {
					if action.TargetGroupArn == tgArn {
						results["Load Balancer Type"] = fmt.Sprintf("%s Load Balancer", strings.ToUpper(lb.Type))
						results["Load Balancer Name"] = lb.LoadBalancerName

						// Analyze this listener for application-relevant configuration
						analyzeALBListenerForApps(listener.Port, listener.Protocol, listener.SslPolicy, results)
						return
					}
				}
			}
		}
	}
}

// analyzeELBListenersForApps analyzes Classic Load Balancer listeners for application crypto configuration
func analyzeELBListenersForApps(elbName string, listeners []struct {
	Listener struct {
		Protocol         string `json:"Protocol"`
		LoadBalancerPort int    `json:"LoadBalancerPort"`
		InstancePort     int    `json:"InstancePort"`
		SSLCertificateId string `json:"SSLCertificateId"`
	} `json:"Listener"`
	PolicyNames []string `json:"PolicyNames"`
}, results map[string]string) {

	var appPorts []string
	var sslPolicies []string

	for _, listenerDesc := range listeners {
		listener := listenerDesc.Listener
		
		// Focus on application-relevant ports (HTTP, HTTPS, custom app ports)
		if listener.Protocol == "HTTP" || listener.Protocol == "HTTPS" || 
		   listener.LoadBalancerPort == 80 || listener.LoadBalancerPort == 443 ||
		   (listener.LoadBalancerPort >= 8000 && listener.LoadBalancerPort <= 9000) {
			
			appPorts = append(appPorts, fmt.Sprintf("%d (%s)", listener.LoadBalancerPort, listener.Protocol))

			if listener.Protocol == "HTTPS" || listener.Protocol == "SSL" {
				// Get SSL policy details for HTTPS listeners
				for _, policyName := range listenerDesc.PolicyNames {
					if strings.Contains(policyName, "SSL") || strings.Contains(policyName, "TLS") {
						sslPolicies = append(sslPolicies, policyName)
						analyzeELBSSLPolicyForApps(elbName, policyName, results)
					}
				}
			}
		}
	}

	if len(appPorts) > 0 {
		results["Application Ports"] = strings.Join(appPorts, ", ")
	}
	if len(sslPolicies) > 0 {
		results["SSL Policies"] = strings.Join(sslPolicies, ", ")
	}
}

// analyzeALBListenerForApps analyzes ALB/NLB listener for application crypto configuration
func analyzeALBListenerForApps(port int, protocol, sslPolicy string, results map[string]string) {
	// Focus on application-relevant ports
	if protocol == "HTTP" || protocol == "HTTPS" || 
	   port == 80 || port == 443 ||
	   (port >= 8000 && port <= 9000) {
		
		results["Application Ports"] = fmt.Sprintf("%d (%s)", port, protocol)

		if protocol == "HTTPS" || protocol == "TLS" {
			if sslPolicy != "" {
				results["SSL Policy"] = sslPolicy
				analyzeSSLPolicyForApps(sslPolicy, results)
			}
		}
	}
}

// analyzeELBSSLPolicyForApps analyzes Classic Load Balancer SSL policy
func analyzeELBSSLPolicyForApps(elbName, policyName string, results map[string]string) {
	cmd := exec.Command("aws", "elb", "describe-load-balancer-policies",
		"--load-balancer-name", elbName,
		"--policy-names", policyName,
		"--output", "json")
	
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var policyResponse struct {
		PolicyDescriptions []struct {
			PolicyName       string `json:"PolicyName"`
			PolicyTypeName   string `json:"PolicyTypeName"`
			PolicyAttributes []struct {
				AttributeName  string `json:"AttributeName"`
				AttributeValue string `json:"AttributeValue"`
			} `json:"PolicyAttributes"`
		} `json:"PolicyDescriptions"`
	}

	if err := json.Unmarshal(output, &policyResponse); err != nil {
		return
	}

	for _, policy := range policyResponse.PolicyDescriptions {
		if policy.PolicyName == policyName {
			// Analyze SSL policy attributes for PQC readiness
			analyzePolicyAttributesForApps(policy.PolicyAttributes, results)
			break
		}
	}
}

// analyzeSSLPolicyForApps analyzes ALB/NLB SSL policy for PQC readiness
func analyzeSSLPolicyForApps(sslPolicy string, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies",
		"--names", sslPolicy, "--output", "json")
	
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var policyResponse struct {
		SslPolicies []struct {
			Name                     string   `json:"Name"`
			SslProtocols             []string `json:"SslProtocols"`
			Ciphers                  []struct {
				Name     string `json:"Name"`
				Priority int    `json:"Priority"`
			} `json:"Ciphers"`
			SupportedLoadBalancerTypes []string `json:"SupportedLoadBalancerTypes"`
		} `json:"SslPolicies"`
	}

	if err := json.Unmarshal(output, &policyResponse); err != nil {
		return
	}

	for _, policy := range policyResponse.SslPolicies {
		if policy.Name == sslPolicy {
			// Analyze protocols
			results["TLS Protocols"] = strings.Join(policy.SslProtocols, ", ")
			
			// Check for TLS 1.3 support (important for PQC readiness)
			hasTLS13 := false
			for _, protocol := range policy.SslProtocols {
				if protocol == "TLSv1.3" {
					hasTLS13 = true
					break
				}
			}

			// Analyze cipher suites
			cipherCount := len(policy.Ciphers)
			results["Cipher Suite Count"] = strconv.Itoa(cipherCount)

			// Assess PQC readiness based on TLS 1.3 support and modern ciphers
			pqcScore := calculatePQCReadinessForApps(hasTLS13, cipherCount, policy.Ciphers)
			results["PQC Readiness Score"] = fmt.Sprintf("%.1f/10", pqcScore)
			
			if pqcScore >= 7.0 {
				results["PQC Assessment"] = "Good - TLS 1.3 supported with modern cipher suites"
			} else if pqcScore >= 5.0 {
				results["PQC Assessment"] = "Moderate - Some modern crypto support, upgrade recommended"
			} else {
				results["PQC Assessment"] = "Poor - Legacy crypto configuration, upgrade required"
			}

			break
		}
	}
}

// analyzePolicyAttributesForApps analyzes Classic Load Balancer policy attributes
func analyzePolicyAttributesForApps(attributes []struct {
	AttributeName  string `json:"AttributeName"`
	AttributeValue string `json:"AttributeValue"`
}, results map[string]string) {
	
	var enabledProtocols []string
	var enabledCiphers []string

	for _, attr := range attributes {
		if attr.AttributeValue == "true" {
			if strings.Contains(attr.AttributeName, "Protocol-") {
				protocol := strings.TrimPrefix(attr.AttributeName, "Protocol-")
				enabledProtocols = append(enabledProtocols, protocol)
			} else if strings.Contains(attr.AttributeName, "ECDHE") || 
					  strings.Contains(attr.AttributeName, "AES") ||
					  strings.Contains(attr.AttributeName, "DES") {
				enabledCiphers = append(enabledCiphers, attr.AttributeName)
			}
		}
	}

	if len(enabledProtocols) > 0 {
		results["TLS Protocols"] = strings.Join(enabledProtocols, ", ")
	}
	if len(enabledCiphers) > 0 {
		results["Cipher Suite Count"] = strconv.Itoa(len(enabledCiphers))
	}

	// Basic PQC readiness assessment for Classic Load Balancer
	hasTLS12 := false
	for _, protocol := range enabledProtocols {
		if strings.Contains(protocol, "TLSv1.2") {
			hasTLS12 = true
			break
		}
	}

	if hasTLS12 && len(enabledCiphers) > 10 {
		results["PQC Assessment"] = "Moderate - TLS 1.2 with multiple cipher suites, consider ALB upgrade"
		results["PQC Readiness Score"] = "5.0/10"
	} else {
		results["PQC Assessment"] = "Poor - Legacy configuration, ALB upgrade recommended"
		results["PQC Readiness Score"] = "3.0/10"
	}
}

// calculatePQCReadinessForApps calculates a PQC readiness score for application load balancers
func calculatePQCReadinessForApps(hasTLS13 bool, cipherCount int, ciphers []struct {
	Name     string `json:"Name"`
	Priority int    `json:"Priority"`
}) float64 {
	score := 0.0

	// TLS 1.3 support is crucial for PQC readiness
	if hasTLS13 {
		score += 4.0
	}

	// Modern cipher suite diversity
	if cipherCount >= 20 {
		score += 3.0
	} else if cipherCount >= 10 {
		score += 2.0
	} else if cipherCount >= 5 {
		score += 1.0
	}

	// Check for modern cipher algorithms
	modernCipherCount := 0
	for _, cipher := range ciphers {
		cipherName := strings.ToUpper(cipher.Name)
		if strings.Contains(cipherName, "AES256-GCM") ||
		   strings.Contains(cipherName, "CHACHA20") ||
		   strings.Contains(cipherName, "ECDHE") {
			modernCipherCount++
		}
	}

	if modernCipherCount >= 5 {
		score += 2.0
	} else if modernCipherCount >= 2 {
		score += 1.0
	}

	// Bonus for having a good variety of modern algorithms
	if hasTLS13 && modernCipherCount >= 3 && cipherCount >= 15 {
		score += 1.0
	}

	// Cap at 10.0
	if score > 10.0 {
		score = 10.0
	}

	return score
}

package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"mini-pqc/scan"
)

// checkAWSEnvironmentForOpenSSH detects AWS environment and analyzes load balancer configuration for OpenSSH
func checkAWSEnvironmentForOpenSSH(results map[string]string) {
	// Check if we're in AWS environment
	if !isAWSEnvironment() {
		return
	}

	results["AWS Environment"] = "Detected"

	// Get EC2 instance ID
	instanceID := getInstanceID()
	if instanceID != "" {
		results["EC2 Instance ID"] = instanceID
	}

	// Check AWS CLI availability
	if !isAWSCLIAvailable() {
		results["AWS CLI"] = "Not available"
		return
	}
	results["AWS CLI"] = "Available"

	// Discover load balancers for this instance
	discoverOpenSSHLoadBalancers(results, instanceID)
}

// discoverOpenSSHLoadBalancers discovers and analyzes load balancers for OpenSSH service
func discoverOpenSSHLoadBalancers(results map[string]string, instanceID string) {
	// Use existing load balancer discovery from AWS ELB module
	// Create a temporary recommendation manager for discovery
	tempRM := scan.NewRecommendationManager()
	loadBalancers := discoverLoadBalancers(instanceID, tempRM)
	
	if len(loadBalancers) > 0 {
		for _, lb := range loadBalancers {
			if lb.Type == "classic" {
				results["Classic Load Balancer"] = lb.Name
				analyzeOpenSSHClassicLoadBalancer(results, lb.Name)
			} else {
				results["Application Load Balancer"] = "Found"
				results["Load Balancer ARN"] = lb.ARN
				analyzeOpenSSHApplicationLoadBalancer(results, lb.ARN)
			}
			break // Use first load balancer found
		}
	}
}

// analyzeOpenSSHClassicLoadBalancer analyzes Classic Load Balancer configuration for SSH traffic
func analyzeOpenSSHClassicLoadBalancer(results map[string]string, clbName string) {
	// Get Classic Load Balancer details
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--load-balancer-names", clbName, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var clbResponse struct {
		LoadBalancerDescriptions []struct {
			LoadBalancerName string `json:"LoadBalancerName"`
			Listeners        []struct {
				Protocol         string `json:"Protocol"`
				LoadBalancerPort int    `json:"LoadBalancerPort"`
				InstancePort     int    `json:"InstancePort"`
				SSLCertificateId string `json:"SSLCertificateId,omitempty"`
			} `json:"Listeners"`
		} `json:"LoadBalancerDescriptions"`
	}

	if err := json.Unmarshal(output, &clbResponse); err != nil {
		return
	}

	if len(clbResponse.LoadBalancerDescriptions) > 0 {
		lb := clbResponse.LoadBalancerDescriptions[0]
		
		// Analyze listeners for SSH-relevant protocols
		var tcpListeners, sslListeners int
		var primaryPort string
		var sshPorts []string
		
		for _, listener := range lb.Listeners {
			switch listener.Protocol {
			case "TCP":
				tcpListeners++
				if listener.LoadBalancerPort == 22 || listener.InstancePort == 22 {
					sshPorts = append(sshPorts, fmt.Sprintf("%d", listener.LoadBalancerPort))
				}
				if primaryPort == "" {
					primaryPort = fmt.Sprintf("%d/TCP", listener.LoadBalancerPort)
				}
			case "SSL":
				sslListeners++
				if listener.LoadBalancerPort == 22 || listener.InstancePort == 22 {
					sshPorts = append(sshPorts, fmt.Sprintf("%d", listener.LoadBalancerPort))
				}
				if primaryPort == "" {
					primaryPort = fmt.Sprintf("%d/SSL", listener.LoadBalancerPort)
				}
			}
		}
		
		results["LB TCP Listeners"] = fmt.Sprintf("%d", tcpListeners)
		results["LB SSL Listeners"] = fmt.Sprintf("%d", sslListeners)
		if primaryPort != "" {
			results["LB Primary Port"] = primaryPort
		}
		
		// SSH-specific analysis
		if len(sshPorts) > 0 {
			results["LB SSH Ports"] = strings.Join(sshPorts, ", ")
			results["LB SSH Protocol"] = "TCP (Standard SSH)"
		}
		
		// Note: SSH uses its own crypto (not SSL/TLS termination at load balancer)
		results["LB SSH Context"] = "TCP passthrough (SSH crypto handled by sshd)"
	}
}

// analyzeOpenSSHApplicationLoadBalancer analyzes Application/Network Load Balancer for SSH traffic
func analyzeOpenSSHApplicationLoadBalancer(results map[string]string, albArn string) {
	// Get ALB/NLB details
	cmd := exec.Command("aws", "elbv2", "describe-load-balancers", "--load-balancer-arns", albArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var albResponse struct {
		LoadBalancers []struct {
			LoadBalancerArn  string `json:"LoadBalancerArn"`
			LoadBalancerName string `json:"LoadBalancerName"`
			Type             string `json:"Type"`
			Scheme           string `json:"Scheme"`
		} `json:"LoadBalancers"`
	}

	if err := json.Unmarshal(output, &albResponse); err != nil {
		return
	}

	if len(albResponse.LoadBalancers) > 0 {
		lb := albResponse.LoadBalancers[0]
		results["LB Type"] = lb.Type
		results["LB Scheme"] = lb.Scheme
		
		// Get listeners for this load balancer
		analyzeOpenSSHLoadBalancerListeners(results, albArn)
	}
}

// analyzeOpenSSHLoadBalancerListeners analyzes listeners for SSH traffic patterns
func analyzeOpenSSHLoadBalancerListeners(results map[string]string, albArn string) {
	cmd := exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", albArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var listenersResponse struct {
		Listeners []struct {
			ListenerArn string `json:"ListenerArn"`
			Protocol    string `json:"Protocol"`
			Port        int    `json:"Port"`
			SSLPolicy   string `json:"SslPolicy,omitempty"`
		} `json:"Listeners"`
	}

	if err := json.Unmarshal(output, &listenersResponse); err != nil {
		return
	}

	var tcpListeners, tlsListeners int
	var primaryPort string
	var sshPorts []string
	var sslPolicy string

	for _, listener := range listenersResponse.Listeners {
		switch listener.Protocol {
		case "TCP":
			tcpListeners++
			if listener.Port == 22 {
				sshPorts = append(sshPorts, fmt.Sprintf("%d", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/TCP", listener.Port)
			}
		case "TLS":
			// Network Load Balancer TLS termination (uncommon for SSH)
			tlsListeners++
			if listener.Port == 22 {
				sshPorts = append(sshPorts, fmt.Sprintf("%d", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/TLS", listener.Port)
			}
			if listener.SSLPolicy != "" {
				sslPolicy = listener.SSLPolicy
			}
		}
	}

	results["LB TCP Listeners"] = fmt.Sprintf("%d", tcpListeners)
	results["LB TLS Listeners"] = fmt.Sprintf("%d", tlsListeners)
	
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}

	// SSH-specific analysis
	if len(sshPorts) > 0 {
		results["LB SSH Ports"] = strings.Join(sshPorts, ", ")
		if tlsListeners > 0 {
			results["LB SSH Protocol"] = "TLS (Uncommon SSH setup)"
		} else {
			results["LB SSH Protocol"] = "TCP (Standard SSH passthrough)"
		}
	}

	// If there are TLS listeners (rare for SSH), analyze SSL policy
	if sslPolicy != "" {
		results["LB SSL Policy"] = sslPolicy
		analyzeOpenSSHSSLPolicy(results, sslPolicy)
	} else {
		// Standard SSH setup - no SSL/TLS termination at load balancer
		results["LB SSH Context"] = "TCP passthrough (SSH crypto handled by OpenSSH)"
		results["LB PQC Ready"] = "N/A (SSH uses own crypto)"
	}
}

// analyzeOpenSSHSSLPolicy analyzes SSL policy for rare TLS-terminated SSH setups
func analyzeOpenSSHSSLPolicy(results map[string]string, policyName string) {
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", policyName, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	var policyResponse struct {
		SslPolicies []struct {
			SslPolicyName string `json:"SslPolicyName"`
			Ciphers       []struct {
				Name     string `json:"Name"`
				Priority int    `json:"Priority"`
			} `json:"Ciphers"`
			SupportedProtocols []string `json:"SupportedProtocols"`
		} `json:"SslPolicies"`
	}

	if err := json.Unmarshal(output, &policyResponse); err != nil {
		return
	}

	if len(policyResponse.SslPolicies) > 0 {
		policy := policyResponse.SslPolicies[0]
		
		// Count total and modern ciphers
		totalCiphers := len(policy.Ciphers)
		modernCount := 0
		
		// Count modern cipher suites (ECDHE, ChaCha20, AES-GCM)
		for _, cipher := range policy.Ciphers {
			cipherName := strings.ToUpper(cipher.Name)
			if strings.Contains(cipherName, "ECDHE") || 
			   strings.Contains(cipherName, "CHACHA20") || 
			   strings.Contains(cipherName, "AES128-GCM") || 
			   strings.Contains(cipherName, "AES256-GCM") {
				modernCount++
			}
		}
		
		results["LB Cipher Count"] = fmt.Sprintf("%d", totalCiphers)
		results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCount)
		
		// Check for TLS 1.3 support
		hasTLS13 := false
		for _, protocol := range policy.SupportedProtocols {
			if protocol == "TLSv1.3" {
				hasTLS13 = true
				break
			}
		}
		
		// Determine PQC readiness for TLS-terminated SSH (rare setup)
		modernCountFromResults := 0
		if modernCipherStr, ok := results["LB Modern Ciphers"]; ok {
			if count, err := fmt.Sscanf(modernCipherStr, "%d", &modernCountFromResults); err != nil || count != 1 {
				modernCountFromResults = 0
			}
		}
		
		if hasTLS13 && modernCountFromResults > 5 {
			results["LB PQC Ready"] = "true"
		} else {
			results["LB PQC Ready"] = "false"
		}
		
		// Note: This is an unusual SSH setup with TLS termination at load balancer
		results["LB SSH Context"] = "TLS termination (unusual SSH setup - check SSH crypto separately)"
	}
}

package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"mini-pqc/scan"
)

// checkAWSEnvironmentForOpenVPN detects AWS environment and analyzes load balancer configuration for OpenVPN
func checkAWSEnvironmentForOpenVPN(results map[string]string) {
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
	discoverOpenVPNLoadBalancers(results, instanceID)
}

// discoverOpenVPNLoadBalancers discovers and analyzes load balancers for OpenVPN service
func discoverOpenVPNLoadBalancers(results map[string]string, instanceID string) {
	// Use existing load balancer discovery from AWS ELB module
	// Create a temporary recommendation manager for discovery
	tempRM := scan.NewRecommendationManager()
	loadBalancers := discoverLoadBalancers(instanceID, tempRM)
	
	if len(loadBalancers) > 0 {
		for _, lb := range loadBalancers {
			if lb.Type == "classic" {
				results["Classic Load Balancer"] = lb.Name
				analyzeOpenVPNClassicLoadBalancer(results, lb.Name)
			} else {
				results["Application Load Balancer"] = "Found"
				results["Load Balancer ARN"] = lb.ARN
				analyzeOpenVPNApplicationLoadBalancer(results, lb.ARN)
			}
			break // Use first load balancer found
		}
	}
}

// analyzeOpenVPNClassicLoadBalancer analyzes Classic Load Balancer configuration for OpenVPN traffic
func analyzeOpenVPNClassicLoadBalancer(results map[string]string, clbName string) {
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
		
		// Analyze listeners for OpenVPN-relevant protocols
		var udpListeners, tcpListeners, sslListeners int
		var primaryPort string
		var vpnPorts []string
		
		for _, listener := range lb.Listeners {
			switch listener.Protocol {
			case "UDP":
				udpListeners++
				// OpenVPN commonly uses UDP 1194
				if listener.LoadBalancerPort == 1194 || listener.InstancePort == 1194 {
					vpnPorts = append(vpnPorts, fmt.Sprintf("%d/UDP", listener.LoadBalancerPort))
				}
				if primaryPort == "" {
					primaryPort = fmt.Sprintf("%d/UDP", listener.LoadBalancerPort)
				}
			case "TCP":
				tcpListeners++
				// OpenVPN can also use TCP 1194 or 443
				if listener.LoadBalancerPort == 1194 || listener.InstancePort == 1194 || 
				   listener.LoadBalancerPort == 443 || listener.InstancePort == 443 {
					vpnPorts = append(vpnPorts, fmt.Sprintf("%d/TCP", listener.LoadBalancerPort))
				}
				if primaryPort == "" {
					primaryPort = fmt.Sprintf("%d/TCP", listener.LoadBalancerPort)
				}
			case "SSL":
				sslListeners++
				// OpenVPN over SSL/TLS (less common)
				if listener.LoadBalancerPort == 443 || listener.InstancePort == 443 {
					vpnPorts = append(vpnPorts, fmt.Sprintf("%d/SSL", listener.LoadBalancerPort))
				}
				if primaryPort == "" {
					primaryPort = fmt.Sprintf("%d/SSL", listener.LoadBalancerPort)
				}
			}
		}
		
		results["LB UDP Listeners"] = fmt.Sprintf("%d", udpListeners)
		results["LB TCP Listeners"] = fmt.Sprintf("%d", tcpListeners)
		results["LB SSL Listeners"] = fmt.Sprintf("%d", sslListeners)
		if primaryPort != "" {
			results["LB Primary Port"] = primaryPort
		}
		
		// OpenVPN-specific analysis
		if len(vpnPorts) > 0 {
			results["LB VPN Ports"] = strings.Join(vpnPorts, ", ")
			if udpListeners > 0 {
				results["LB VPN Protocol"] = "UDP (OpenVPN preferred)"
			} else if tcpListeners > 0 {
				results["LB VPN Protocol"] = "TCP (OpenVPN fallback)"
			}
		}
		
		// Note: OpenVPN uses its own TLS crypto (not SSL/TLS termination at load balancer)
		results["LB VPN Context"] = "Passthrough (OpenVPN TLS handled by server)"
	}
}

// analyzeOpenVPNApplicationLoadBalancer analyzes Application/Network Load Balancer for OpenVPN traffic
func analyzeOpenVPNApplicationLoadBalancer(results map[string]string, albArn string) {
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
		analyzeOpenVPNLoadBalancerListeners(results, albArn)
	}
}

// analyzeOpenVPNLoadBalancerListeners analyzes listeners for OpenVPN traffic patterns
func analyzeOpenVPNLoadBalancerListeners(results map[string]string, albArn string) {
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

	var udpListeners, tcpListeners, httpsListeners, tlsListeners int
	var primaryPort string
	var vpnPorts []string
	var sslPolicy string

	for _, listener := range listenersResponse.Listeners {
		switch listener.Protocol {
		case "UDP":
			udpListeners++
			// OpenVPN commonly uses UDP 1194
			if listener.Port == 1194 {
				vpnPorts = append(vpnPorts, fmt.Sprintf("%d/UDP", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/UDP", listener.Port)
			}
		case "TCP":
			tcpListeners++
			// OpenVPN can use TCP 1194 or 443
			if listener.Port == 1194 || listener.Port == 443 {
				vpnPorts = append(vpnPorts, fmt.Sprintf("%d/TCP", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/TCP", listener.Port)
			}
		case "HTTPS":
			httpsListeners++
			// OpenVPN web interface or HTTPS tunneling
			if listener.Port == 443 {
				vpnPorts = append(vpnPorts, fmt.Sprintf("%d/HTTPS", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/HTTPS", listener.Port)
			}
			if listener.SSLPolicy != "" {
				sslPolicy = listener.SSLPolicy
			}
		case "TLS":
			// Network Load Balancer TLS termination (uncommon for OpenVPN)
			tlsListeners++
			if listener.Port == 443 || listener.Port == 1194 {
				vpnPorts = append(vpnPorts, fmt.Sprintf("%d/TLS", listener.Port))
			}
			if primaryPort == "" {
				primaryPort = fmt.Sprintf("%d/TLS", listener.Port)
			}
			if listener.SSLPolicy != "" {
				sslPolicy = listener.SSLPolicy
			}
		}
	}

	results["LB UDP Listeners"] = fmt.Sprintf("%d", udpListeners)
	results["LB TCP Listeners"] = fmt.Sprintf("%d", tcpListeners)
	results["LB HTTPS Listeners"] = fmt.Sprintf("%d", httpsListeners)
	results["LB TLS Listeners"] = fmt.Sprintf("%d", tlsListeners)
	
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}

	// OpenVPN-specific analysis
	if len(vpnPorts) > 0 {
		results["LB VPN Ports"] = strings.Join(vpnPorts, ", ")
		if udpListeners > 0 {
			results["LB VPN Protocol"] = "UDP (OpenVPN native)"
		} else if tcpListeners > 0 {
			results["LB VPN Protocol"] = "TCP (OpenVPN over TCP)"
		} else if httpsListeners > 0 || tlsListeners > 0 {
			results["LB VPN Protocol"] = "HTTPS/TLS (OpenVPN web or tunneling)"
		}
	}

	// If there are HTTPS/TLS listeners, analyze SSL policy for web interfaces
	if sslPolicy != "" {
		results["LB SSL Policy"] = sslPolicy
		analyzeOpenVPNSSLPolicy(results, sslPolicy)
	} else {
		// Standard OpenVPN setup - no SSL/TLS termination at load balancer
		results["LB VPN Context"] = "Passthrough (OpenVPN handles own TLS crypto)"
		results["LB PQC Ready"] = "N/A (OpenVPN uses own TLS)"
	}
}

// analyzeOpenVPNSSLPolicy analyzes SSL policy for OpenVPN web interfaces or HTTPS tunneling
func analyzeOpenVPNSSLPolicy(results map[string]string, policyName string) {
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
		
		// Determine PQC readiness for web interfaces
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
		
		// Note: This applies to web interfaces, not OpenVPN tunnel crypto
		results["LB VPN Context"] = "Web interface SSL (OpenVPN tunnel crypto separate)"
	}
}

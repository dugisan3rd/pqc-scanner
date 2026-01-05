package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// inspectAWSLoadBalancerForIPsec performs AWS load balancer crypto inspection for IPsec command
func inspectAWSLoadBalancerForIPsec() map[string]string {
	results := make(map[string]string)
	
	// Check if we're running in AWS environment
	if !isAWSEnvironment() {
		return results
	}
	
	results["AWS Environment"] = "EC2"
	
	// Get EC2 instance ID
	instanceID := getInstanceID()
	if instanceID == "" {
		return results
	}
	results["EC2 Instance ID"] = instanceID
	
	// Check AWS CLI availability
	if !isAWSCLIAvailable() {
		results["AWS CLI"] = "Not available"
		return results
	}
	results["AWS CLI"] = "Available"
	
	// Discover load balancers associated with this instance
	discoverAWSLoadBalancersForIPsec(instanceID, results)
	
	fmt.Println("\nAWS LOAD BALANCER CONTEXT:")
	fmt.Printf("IPsec running on AWS environment (EC2 Instance: %s)\n", instanceID)
	fmt.Println("Note: IPsec configuration analysis shows instance-level settings.")
	fmt.Println("If IPsec VPN is behind an AWS Load Balancer, internet-facing crypto")
	fmt.Println("configuration may differ from instance-level IPsec settings.")
	
	return results
}

// discoverAWSLoadBalancersForIPsec discovers load balancers associated with the instance for IPsec analysis
func discoverAWSLoadBalancersForIPsec(instanceID string, results map[string]string) {
	// Discover Classic Load Balancers
	discoverClassicLoadBalancersForIPsec(instanceID, results)
	
	// Discover Application/Network Load Balancers
	discoverApplicationLoadBalancersForIPsec(instanceID, results)
}

// discoverClassicLoadBalancersForIPsec discovers Classic Load Balancers for IPsec
func discoverClassicLoadBalancersForIPsec(instanceID string, results map[string]string) {
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	var elbResponse struct {
		LoadBalancerDescriptions []struct {
			LoadBalancerName string `json:"LoadBalancerName"`
			Scheme           string `json:"Scheme"`
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
	
	for _, lb := range elbResponse.LoadBalancerDescriptions {
		// Check if this instance is registered with this load balancer
		for _, instance := range lb.Instances {
			if instance.InstanceId == instanceID {
				results["Classic Load Balancer"] = lb.LoadBalancerName
				results["LB Type"] = "Classic"
				results["LB Scheme"] = lb.Scheme
				
				// Analyze listeners for VPN-relevant protocols
				analyzeClassicLoadBalancerListenersForIPsec(lb.LoadBalancerName, lb.ListenerDescriptions, results)
				return
			}
		}
	}
}

// discoverApplicationLoadBalancersForIPsec discovers Application/Network Load Balancers for IPsec
func discoverApplicationLoadBalancersForIPsec(instanceID string, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-load-balancers", "--output", "json")
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
	
	for _, lb := range albResponse.LoadBalancers {
		// Check if this instance is registered with this load balancer
		if isInstanceRegisteredWithELBv2(lb.LoadBalancerArn, instanceID) {
			results["Application Load Balancer"] = lb.LoadBalancerName
			results["Load Balancer ARN"] = lb.LoadBalancerArn
			results["LB Type"] = strings.Title(lb.Type)
			results["LB Scheme"] = lb.Scheme
			
			// Analyze listeners for VPN-relevant protocols
			analyzeApplicationLoadBalancerListenersForIPsec(lb.LoadBalancerArn, results)
			return
		}
	}
}

// analyzeClassicLoadBalancerListenersForIPsec analyzes Classic Load Balancer listeners for IPsec VPN
func analyzeClassicLoadBalancerListenersForIPsec(lbName string, listeners []struct {
	Listener struct {
		Protocol         string `json:"Protocol"`
		LoadBalancerPort int    `json:"LoadBalancerPort"`
		InstancePort     int    `json:"InstancePort"`
		SSLCertificateId string `json:"SSLCertificateId"`
	} `json:"Listener"`
	PolicyNames []string `json:"PolicyNames"`
}, results map[string]string) {
	
	var udpListeners, tcpListeners, httpsListeners []string
	var sslPolicies []string
	var primaryPort string
	
	for _, listenerDesc := range listeners {
		listener := listenerDesc.Listener
		port := fmt.Sprintf("%d", listener.LoadBalancerPort)
		
		switch listener.Protocol {
		case "UDP":
			udpListeners = append(udpListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
		case "TCP":
			tcpListeners = append(tcpListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
		case "HTTPS":
			httpsListeners = append(httpsListeners, port)
			if listener.SSLCertificateId != "" {
				// Get SSL policy for HTTPS listeners (for management interfaces)
				for _, policyName := range listenerDesc.PolicyNames {
					if strings.Contains(policyName, "SSL") {
						sslPolicies = append(sslPolicies, policyName)
					}
				}
			}
		}
	}
	
	// Set VPN protocol context
	if len(udpListeners) > 0 || len(tcpListeners) > 0 {
		results["LB VPN Protocol"] = "IPsec passthrough"
		results["LB VPN Context"] = "Load balancer passes IPsec traffic transparently"
	}
	
	if len(udpListeners) > 0 {
		results["LB UDP Listeners"] = strings.Join(udpListeners, ", ")
	}
	if len(tcpListeners) > 0 {
		results["LB TCP Listeners"] = strings.Join(tcpListeners, ", ")
	}
	if len(httpsListeners) > 0 {
		results["LB HTTPS Listeners"] = strings.Join(httpsListeners, ", ")
	}
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}
	
	// Analyze SSL policies for management interfaces only
	if len(sslPolicies) > 0 {
		results["LB SSL Policy"] = strings.Join(sslPolicies, ", ")
		results["LB SSL Context"] = "SSL policy applies to management interfaces only, IPsec tunnel uses own cryptography"
		
		// Determine PQC readiness for management interfaces
		pqcReady := false
		for _, policy := range sslPolicies {
			if isSSLPolicyPQCReady(policy) {
				pqcReady = true
				break
			}
		}
		if pqcReady {
			results["LB PQC Ready"] = "true"
		} else {
			results["LB PQC Ready"] = "false"
		}
	} else {
		results["LB PQC Ready"] = "n/a"
	}
}

// analyzeApplicationLoadBalancerListenersForIPsec analyzes Application/Network Load Balancer listeners for IPsec VPN
func analyzeApplicationLoadBalancerListenersForIPsec(lbArn string, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", lbArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	var listenersResponse struct {
		Listeners []struct {
			Protocol string `json:"Protocol"`
			Port     int    `json:"Port"`
			SslPolicy string `json:"SslPolicy"`
		} `json:"Listeners"`
	}
	
	if err := json.Unmarshal(output, &listenersResponse); err != nil {
		return
	}
	
	var udpListeners, tcpListeners, httpsListeners, tlsListeners []string
	var sslPolicies []string
	var primaryPort string
	
	for _, listener := range listenersResponse.Listeners {
		port := fmt.Sprintf("%d", listener.Port)
		
		switch listener.Protocol {
		case "UDP":
			udpListeners = append(udpListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
		case "TCP":
			tcpListeners = append(tcpListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
		case "HTTPS":
			httpsListeners = append(httpsListeners, port)
			if listener.SslPolicy != "" {
				sslPolicies = append(sslPolicies, listener.SslPolicy)
			}
		case "TLS":
			tlsListeners = append(tlsListeners, port)
			if listener.SslPolicy != "" {
				sslPolicies = append(sslPolicies, listener.SslPolicy)
			}
		}
	}
	
	// Set VPN protocol context
	if len(udpListeners) > 0 || len(tcpListeners) > 0 {
		results["LB VPN Protocol"] = "IPsec passthrough"
		results["LB VPN Context"] = "Load balancer passes IPsec traffic transparently"
	}
	
	if len(udpListeners) > 0 {
		results["LB UDP Listeners"] = strings.Join(udpListeners, ", ")
	}
	if len(tcpListeners) > 0 {
		results["LB TCP Listeners"] = strings.Join(tcpListeners, ", ")
	}
	if len(httpsListeners) > 0 {
		results["LB HTTPS Listeners"] = strings.Join(httpsListeners, ", ")
	}
	if len(tlsListeners) > 0 {
		results["LB TLS Listeners"] = strings.Join(tlsListeners, ", ")
	}
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}
	
	// Analyze SSL policies for management interfaces only
	if len(sslPolicies) > 0 {
		// Use the first SSL policy found
		sslPolicy := sslPolicies[0]
		results["LB SSL Policy"] = sslPolicy
		results["LB SSL Context"] = "SSL policy applies to management interfaces only, IPsec tunnel uses own cryptography"
		
		// Get detailed SSL policy information
		analyzeSSLPolicyForIPsec(sslPolicy, results)
	} else {
		results["LB PQC Ready"] = "n/a"
	}
}

// analyzeSSLPolicyForIPsec analyzes SSL policy details for IPsec management interfaces
func analyzeSSLPolicyForIPsec(sslPolicy string, results map[string]string) {
	cmd := exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", sslPolicy, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		results["LB PQC Ready"] = "unknown"
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
		results["LB PQC Ready"] = "unknown"
		return
	}
	
	if len(policyResponse.SslPolicies) == 0 {
		results["LB PQC Ready"] = "unknown"
		return
	}
	
	policy := policyResponse.SslPolicies[0]
	
	// Count total and modern ciphers
	totalCiphers := len(policy.Ciphers)
	modernCount := 0
	
	for _, cipher := range policy.Ciphers {
		if isModernCipherForPQC(cipher.Name) {
			modernCount++
		}
	}
	
	results["LB Cipher Count"] = fmt.Sprintf("%d", totalCiphers)
	results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCount)
	
	// Check for TLS 1.3 support and modern ciphers for PQC readiness
	supportsTLS13 := false
	for _, protocol := range policy.SupportedProtocols {
		if protocol == "TLSv1.3" {
			supportsTLS13 = true
			break
		}
	}
	
	// Determine PQC readiness based on TLS 1.3 support and modern cipher ratio
	pqcReady := supportsTLS13 && (float64(modernCount)/float64(totalCiphers) >= 0.5)
	
	if pqcReady {
		results["LB PQC Ready"] = "true"
	} else {
		results["LB PQC Ready"] = "false"
	}
}

// isInstanceRegisteredWithELBv2 checks if an instance is registered with an ELBv2 load balancer
func isInstanceRegisteredWithELBv2(lbArn, instanceID string) bool {
	cmd := exec.Command("aws", "elbv2", "describe-target-groups", "--load-balancer-arn", lbArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	var tgResponse struct {
		TargetGroups []struct {
			TargetGroupArn string `json:"TargetGroupArn"`
		} `json:"TargetGroups"`
	}
	
	if err := json.Unmarshal(output, &tgResponse); err != nil {
		return false
	}
	
	// Check each target group for the instance
	for _, tg := range tgResponse.TargetGroups {
		cmd := exec.Command("aws", "elbv2", "describe-target-health", "--target-group-arn", tg.TargetGroupArn, "--output", "json")
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		
		var healthResponse struct {
			TargetHealthDescriptions []struct {
				Target struct {
					Id string `json:"Id"`
				} `json:"Target"`
			} `json:"TargetHealthDescriptions"`
		}
		
		if err := json.Unmarshal(output, &healthResponse); err != nil {
			continue
		}
		
		for _, target := range healthResponse.TargetHealthDescriptions {
			if target.Target.Id == instanceID {
				return true
			}
		}
	}
	
	return false
}

// isModernCipherForPQC checks if a cipher suite is considered modern for PQC readiness
func isModernCipherForPQC(cipherName string) bool {
	// Modern cipher suites that support or are compatible with PQC transition
	modernCiphers := []string{
		"ECDHE-ECDSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"DHE-RSA-AES128-GCM-SHA256",
		"DHE-RSA-AES256-GCM-SHA384",
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	}
	
	for _, modern := range modernCiphers {
		if strings.Contains(cipherName, modern) {
			return true
		}
	}
	
	return false
}


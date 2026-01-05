package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// inspectAWSLoadBalancerForPostfix performs AWS load balancer crypto inspection for Postfix command
func inspectAWSLoadBalancerForPostfix() map[string]string {
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
	discoverAWSLoadBalancersForPostfix(instanceID, results)
	
	fmt.Println("\nAWS LOAD BALANCER CONTEXT:")
	fmt.Printf("Postfix mail server running on AWS environment (EC2 Instance: %s)\n", instanceID)
	fmt.Println("Note: Postfix configuration analysis shows instance-level settings.")
	fmt.Println("Internet-facing mail traffic may be processed by AWS load balancer with different crypto configuration.")
	
	return results
}

// discoverAWSLoadBalancersForPostfix discovers load balancers for Postfix mail analysis
func discoverAWSLoadBalancersForPostfix(instanceID string, results map[string]string) {
	// Try Classic Load Balancers first
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--output", "json")
	output, err := cmd.Output()
	if err == nil {
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
						SSLCertificateId string `json:"SSLCertificateId"`
					} `json:"Listener"`
					PolicyNames []string `json:"PolicyNames"`
				} `json:"ListenerDescriptions"`
			} `json:"LoadBalancerDescriptions"`
		}
		
		if json.Unmarshal(output, &elbResponse) == nil {
			for _, lb := range elbResponse.LoadBalancerDescriptions {
				for _, instance := range lb.Instances {
					if instance.InstanceId == instanceID {
						results["LB Type"] = "Classic Load Balancer (ELB)"
						results["LB Name"] = lb.LoadBalancerName
						
						// Analyze mail-related listeners (SMTP: 25, 587, 465, IMAP: 993, POP3: 995)
						analyzePostfixLoadBalancerListeners(lb.ListenerDescriptions, results)
						return
					}
				}
			}
		}
	}
	
	// Try Application/Network Load Balancers
	cmd = exec.Command("aws", "elbv2", "describe-target-groups", "--output", "json")
	output, err = cmd.Output()
	if err == nil {
		var tgResponse struct {
			TargetGroups []struct {
				TargetGroupArn     string `json:"TargetGroupArn"`
				LoadBalancerArns   []string `json:"LoadBalancerArns"`
			} `json:"TargetGroups"`
		}
		
		if json.Unmarshal(output, &tgResponse) == nil {
			for _, tg := range tgResponse.TargetGroups {
				// Check if this instance is in the target group
				cmd = exec.Command("aws", "elbv2", "describe-target-health", "--target-group-arn", tg.TargetGroupArn, "--output", "json")
				healthOutput, err := cmd.Output()
				if err == nil {
					var healthResponse struct {
						TargetHealthDescriptions []struct {
							Target struct {
								Id string `json:"Id"`
							} `json:"Target"`
						} `json:"TargetHealthDescriptions"`
					}
					
					if json.Unmarshal(healthOutput, &healthResponse) == nil {
						for _, target := range healthResponse.TargetHealthDescriptions {
							if target.Target.Id == instanceID {
								for _, lbArn := range tg.LoadBalancerArns {
									analyzePostfixApplicationLoadBalancer(lbArn, results)
									return
								}
							}
						}
					}
				}
			}
		}
	}
	
	results["LB Status"] = "No load balancer found for this instance"
}

// analyzePostfixLoadBalancerListeners analyzes listeners for mail services
func analyzePostfixLoadBalancerListeners(listeners []struct {
	Listener struct {
		Protocol         string `json:"Protocol"`
		LoadBalancerPort int    `json:"LoadBalancerPort"`
		SSLCertificateId string `json:"SSLCertificateId"`
	} `json:"Listener"`
	PolicyNames []string `json:"PolicyNames"`
}, results map[string]string) {
	
	var mailPorts []string
	var sslPolicies []string
	
	for _, listener := range listeners {
		port := listener.Listener.LoadBalancerPort
		protocol := listener.Listener.Protocol
		
		// Check for mail-related ports (SMTP: 25, 587, 465, IMAP: 993, POP3: 995)
		if port == 25 || port == 587 || port == 465 || port == 993 || port == 995 {
			mailPorts = append(mailPorts, fmt.Sprintf("%d/%s", port, protocol))
			
			if protocol == "HTTPS" || protocol == "SSL" {
				for _, policyName := range listener.PolicyNames {
					sslPolicies = append(sslPolicies, policyName)
				}
			}
		}
	}
	
	if len(mailPorts) > 0 {
		results["LB Mail Ports"] = strings.Join(mailPorts, ", ")
		results["LB Primary Port"] = mailPorts[0]
		
		if len(sslPolicies) > 0 {
			results["LB SSL Policy"] = sslPolicies[0]
			analyzeSSLPolicyForPostfix(sslPolicies[0], results)
		} else {
			results["LB SSL Context"] = "No SSL termination"
			results["LB PQC Ready"] = "N/A"
		}
	} else {
		results["LB Mail Ports"] = "No mail ports found"
		results["LB SSL Context"] = "No mail services"
		results["LB PQC Ready"] = "N/A"
	}
}

// analyzePostfixApplicationLoadBalancer analyzes ALB/NLB for mail services
func analyzePostfixApplicationLoadBalancer(lbArn string, results map[string]string) {
	// Get load balancer details
	cmd := exec.Command("aws", "elbv2", "describe-load-balancers", "--load-balancer-arns", lbArn, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	var lbResponse struct {
		LoadBalancers []struct {
			LoadBalancerName string `json:"LoadBalancerName"`
			Type             string `json:"Type"`
		} `json:"LoadBalancers"`
	}
	
	if json.Unmarshal(output, &lbResponse) != nil || len(lbResponse.LoadBalancers) == 0 {
		return
	}
	
	lb := lbResponse.LoadBalancers[0]
	results["LB Type"] = fmt.Sprintf("%s (%s)", strings.ToUpper(lb.Type), lb.Type)
	results["LB Name"] = lb.LoadBalancerName
	
	// Get listeners
	cmd = exec.Command("aws", "elbv2", "describe-listeners", "--load-balancer-arn", lbArn, "--output", "json")
	output, err = cmd.Output()
	if err != nil {
		return
	}
	
	var listenersResponse struct {
		Listeners []struct {
			Port     int    `json:"Port"`
			Protocol string `json:"Protocol"`
			SslPolicy string `json:"SslPolicy"`
		} `json:"Listeners"`
	}
	
	if json.Unmarshal(output, &listenersResponse) != nil {
		return
	}
	
	var mailPorts []string
	var sslPolicy string
	
	for _, listener := range listenersResponse.Listeners {
		// Check for mail-related ports
		if listener.Port == 25 || listener.Port == 587 || listener.Port == 465 || listener.Port == 993 || listener.Port == 995 {
			mailPorts = append(mailPorts, fmt.Sprintf("%d/%s", listener.Port, listener.Protocol))
			
			if listener.Protocol == "HTTPS" || listener.Protocol == "TLS" {
				if sslPolicy == "" {
					sslPolicy = listener.SslPolicy
				}
			}
		}
	}
	
	if len(mailPorts) > 0 {
		results["LB Mail Ports"] = strings.Join(mailPorts, ", ")
		results["LB Primary Port"] = mailPorts[0]
		
		if sslPolicy != "" {
			results["LB SSL Policy"] = sslPolicy
			analyzeSSLPolicyForPostfix(sslPolicy, results)
		} else {
			results["LB SSL Context"] = "No SSL termination"
			results["LB PQC Ready"] = "N/A"
		}
	} else {
		results["LB Mail Ports"] = "No mail ports found"
		results["LB SSL Context"] = "No mail services"
		results["LB PQC Ready"] = "N/A"
	}
}

// analyzeSSLPolicyForPostfix analyzes SSL policy for mail services
func analyzeSSLPolicyForPostfix(sslPolicy string, results map[string]string) {
	if sslPolicy == "" {
		return
	}
	
	// Get SSL policy details
	cmd := exec.Command("aws", "elb", "describe-load-balancer-policies", "--policy-names", sslPolicy, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		// Try ELBv2 format
		cmd = exec.Command("aws", "elbv2", "describe-ssl-policies", "--names", sslPolicy, "--output", "json")
		output, err = cmd.Output()
		if err != nil {
			results["LB SSL Context"] = "Policy details unavailable"
			return
		}
		
		var policyResponse struct {
			SslPolicies []struct {
				SslProtocols []string `json:"SslProtocols"`
				Ciphers      []struct {
					Name string `json:"Name"`
				} `json:"Ciphers"`
			} `json:"SslPolicies"`
		}
		
		if json.Unmarshal(output, &policyResponse) == nil && len(policyResponse.SslPolicies) > 0 {
			policy := policyResponse.SslPolicies[0]
			
			// Check for TLS 1.3 support (important for PQC readiness)
			supportsTLS13 := false
			for _, protocol := range policy.SslProtocols {
				if strings.Contains(protocol, "TLSv1.3") {
					supportsTLS13 = true
					break
				}
			}
			
			cipherCount := len(policy.Ciphers)
			modernCipherCount := 0
			
			// Count modern ciphers (ECDHE, ChaCha20, AES-GCM)
			for _, cipher := range policy.Ciphers {
				if strings.Contains(cipher.Name, "ECDHE") || 
				   strings.Contains(cipher.Name, "CHACHA20") || 
				   strings.Contains(cipher.Name, "AES-GCM") {
					modernCipherCount++
				}
			}
			
			results["LB SSL Context"] = fmt.Sprintf("SSL Policy: %s", sslPolicy)
			results["LB Cipher Count"] = fmt.Sprintf("%d", cipherCount)
			results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCipherCount)
			
			// Assess PQC readiness based on TLS 1.3 support and modern ciphers
			if supportsTLS13 && modernCipherCount > 5 {
				results["LB PQC Ready"] = "true"
			} else if supportsTLS13 || modernCipherCount > 3 {
				results["LB PQC Ready"] = "partial"
			} else {
				results["LB PQC Ready"] = "false"
			}
		}
	}
}

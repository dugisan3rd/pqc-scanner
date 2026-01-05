package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// inspectAWSLoadBalancerForCA performs AWS load balancer crypto inspection for CA command
func inspectAWSLoadBalancerForCA() map[string]string {
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
	discoverAWSLoadBalancersForCA(instanceID, results)
	
	fmt.Println("\nAWS LOAD BALANCER CONTEXT:")
	fmt.Printf("CA services running on AWS environment (EC2 Instance: %s)\n", instanceID)
	fmt.Println("Note: CA configuration analysis shows instance-level settings.")
	
	return results
}

// discoverAWSLoadBalancersForCA discovers load balancers for CA analysis
func discoverAWSLoadBalancersForCA(instanceID string, results map[string]string) {
	// Try Classic Load Balancers first
	cmd := exec.Command("aws", "elb", "describe-load-balancers", "--output", "json")
	output, err := cmd.Output()
	if err == nil {
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
						results["Classic Load Balancer"] = lb.LoadBalancerName
						results["LB Type"] = "Classic"
						results["LB Scheme"] = lb.Scheme
						analyzeCALoadBalancerListeners(lb.ListenerDescriptions, results)
						return
					}
				}
			}
		}
	}
	
	// Try Application/Network Load Balancers
	cmd = exec.Command("aws", "elbv2", "describe-load-balancers", "--output", "json")
	output, err = cmd.Output()
	if err == nil {
		var albResponse struct {
			LoadBalancers []struct {
				LoadBalancerArn  string `json:"LoadBalancerArn"`
				LoadBalancerName string `json:"LoadBalancerName"`
				Type             string `json:"Type"`
				Scheme           string `json:"Scheme"`
			} `json:"LoadBalancers"`
		}
		
		if json.Unmarshal(output, &albResponse) == nil {
			for _, lb := range albResponse.LoadBalancers {
				if isInstanceRegisteredWithELBv2(lb.LoadBalancerArn, instanceID) {
					results["Application Load Balancer"] = lb.LoadBalancerName
					results["Load Balancer ARN"] = lb.LoadBalancerArn
					results["LB Type"] = strings.Title(lb.Type)
					results["LB Scheme"] = lb.Scheme
					analyzeCAApplicationLoadBalancer(lb.LoadBalancerArn, results)
					return
				}
			}
		}
	}
}

// analyzeCALoadBalancerListeners analyzes listeners for CA services
func analyzeCALoadBalancerListeners(listeners []struct {
	Listener struct {
		Protocol         string `json:"Protocol"`
		LoadBalancerPort int    `json:"LoadBalancerPort"`
		SSLCertificateId string `json:"SSLCertificateId"`
	} `json:"Listener"`
	PolicyNames []string `json:"PolicyNames"`
}, results map[string]string) {
	
	var httpsListeners []string
	var sslPolicies []string
	var primaryPort string
	
	for _, listenerDesc := range listeners {
		listener := listenerDesc.Listener
		port := fmt.Sprintf("%d", listener.LoadBalancerPort)
		
		if listener.Protocol == "HTTPS" {
			httpsListeners = append(httpsListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
			if listener.SSLCertificateId != "" {
				for _, policyName := range listenerDesc.PolicyNames {
					if strings.Contains(policyName, "SSL") {
						sslPolicies = append(sslPolicies, policyName)
					}
				}
			}
		}
	}
	
	results["LB CA Context"] = "Load balancer terminates SSL/TLS for CA web interfaces"
	
	if len(httpsListeners) > 0 {
		results["LB HTTPS Listeners"] = strings.Join(httpsListeners, ", ")
	}
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}
	
	if len(sslPolicies) > 0 {
		results["LB SSL Policy"] = strings.Join(sslPolicies, ", ")
		results["LB SSL Context"] = "SSL policy applies to CA web interfaces and certificate distribution"
		
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

// analyzeCAApplicationLoadBalancer analyzes ALB/NLB for CA services
func analyzeCAApplicationLoadBalancer(lbArn string, results map[string]string) {
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
	
	var httpsListeners []string
	var sslPolicies []string
	var primaryPort string
	
	for _, listener := range listenersResponse.Listeners {
		port := fmt.Sprintf("%d", listener.Port)
		
		if listener.Protocol == "HTTPS" {
			httpsListeners = append(httpsListeners, port)
			if primaryPort == "" {
				primaryPort = port
			}
			if listener.SslPolicy != "" {
				sslPolicies = append(sslPolicies, listener.SslPolicy)
			}
		}
	}
	
	results["LB CA Context"] = "Load balancer terminates SSL/TLS for CA web interfaces"
	
	if len(httpsListeners) > 0 {
		results["LB HTTPS Listeners"] = strings.Join(httpsListeners, ", ")
	}
	if primaryPort != "" {
		results["LB Primary Port"] = primaryPort
	}
	
	if len(sslPolicies) > 0 {
		sslPolicy := sslPolicies[0]
		results["LB SSL Policy"] = sslPolicy
		results["LB SSL Context"] = "SSL policy applies to CA web interfaces and certificate distribution"
		
		analyzeSSLPolicyForCA(sslPolicy, results)
	} else {
		results["LB PQC Ready"] = "n/a"
	}
}

// analyzeSSLPolicyForCA analyzes SSL policy for CA services
func analyzeSSLPolicyForCA(sslPolicy string, results map[string]string) {
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
	
	totalCiphers := len(policy.Ciphers)
	modernCount := 0
	
	for _, cipher := range policy.Ciphers {
		if isModernCipherForPQC(cipher.Name) {
			modernCount++
		}
	}
	
	results["LB Cipher Count"] = fmt.Sprintf("%d", totalCiphers)
	results["LB Modern Ciphers"] = fmt.Sprintf("%d", modernCount)
	
	supportsTLS13 := false
	for _, protocol := range policy.SupportedProtocols {
		if protocol == "TLSv1.3" {
			supportsTLS13 = true
			break
		}
	}
	
	pqcReady := supportsTLS13 && (float64(modernCount)/float64(totalCiphers) >= 0.5)
	
	if pqcReady {
		results["LB PQC Ready"] = "true"
	} else {
		results["LB PQC Ready"] = "false"
	}
}

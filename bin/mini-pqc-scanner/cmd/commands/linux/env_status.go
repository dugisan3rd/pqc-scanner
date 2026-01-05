package linux

import (
	"strings"
	"mini-pqc/scan"
)

// generateEnvStatus creates structured status items from environment information
func generateEnvStatus(results map[string]string, rm *scan.RecommendationManager) {
	moduleID := scan.CommandModules["env"] // Should be 1
	sectionID := 1
	itemID := 1
	
	// Linux Distribution status (prominently displayed first for Docker context)
	if distro, ok := results["Linux Distribution"]; ok {
		rm.AddStatus(moduleID, sectionID, itemID, "Linux Distribution: "+distro, scan.InfoRecommendation, "", 0)
		itemID++
	} else {
		rm.AddStatus(moduleID, sectionID, itemID, "Linux Distribution: Unknown", scan.WarningRecommendation, "Unable to detect Linux distribution. This information is crucial for Docker containerization.", 2)
		itemID++
	}
	
	// Cloud environment status
	hasCloudIndicators := false
	cloudKeys := []string{"DMI", "Hypervisor", "MAC OUI", "Cloud-Init", "EC2 Metadata", "EC2 Instance ID"}
	detectedIndicators := []string{}
	cloudType := "Unknown"
	
	// Check for specific cloud provider indicators
	if dmi, exists := results["DMI"]; exists {
		hasCloudIndicators = true
		detectedIndicators = append(detectedIndicators, "DMI: "+dmi)
		
		// Extract cloud type from DMI if possible
		if strings.Contains(dmi, "AWS") {
			cloudType = "AWS"
		} else if strings.Contains(dmi, "Google Cloud") {
			cloudType = "Google Cloud"
		} else if strings.Contains(dmi, "Azure") {
			cloudType = "Azure"
		}
	}
	
	// Check MAC OUI if DMI didn't provide a clear cloud type
	if cloudType == "Unknown" {
		if macOUI, exists := results["MAC OUI"]; exists {
			hasCloudIndicators = true
			detectedIndicators = append(detectedIndicators, "MAC OUI: "+macOUI)
			
			if strings.Contains(macOUI, "AWS") {
				cloudType = "AWS"
			} else if strings.Contains(macOUI, "Google Cloud") {
				cloudType = "Google Cloud"
			} else if strings.Contains(macOUI, "Azure") {
				cloudType = "Azure"
			}
		}
	}
	
	// Check EC2 Metadata as a strong indicator for AWS
	if _, exists := results["EC2 Instance ID"]; exists {
		cloudType = "AWS"
	}
	
	// Add other indicators to the details
	for _, key := range cloudKeys {
		if key != "DMI" && key != "MAC OUI" { // Already processed above
			if value, exists := results[key]; exists {
				hasCloudIndicators = true
				detectedIndicators = append(detectedIndicators, key+": "+value)
			}
		}
	}
	
	// If we have hypervisor info but no specific cloud type
	if cloudType == "Unknown" && hasCloudIndicators {
		if hypervisor, exists := results["Hypervisor"]; exists {
			if strings.Contains(hypervisor, "KVM") {
				cloudType = "KVM-based"
			} else if strings.Contains(hypervisor, "Xen") {
				cloudType = "Xen-based"
			} else if strings.Contains(hypervisor, "VMware") {
				cloudType = "VMware"
			} else if strings.Contains(hypervisor, "Hyper-V") {
				cloudType = "Hyper-V"
			}
		}
	}
	
	details := ""
	if len(detectedIndicators) > 0 {
		details = "Detected indicators:\n- " + strings.Join(detectedIndicators, "\n- ")
	}
	
	if hasCloudIndicators {
		statusTitle := "Cloud Environment: "
		if cloudType != "Unknown" {
			statusTitle += cloudType + " Detected"
		} else {
			statusTitle += "Detected"
		}
		rm.AddStatus(moduleID, sectionID, itemID, statusTitle, scan.InfoRecommendation, details, 0)
	} else {
		rm.AddStatus(moduleID, sectionID, itemID, "Cloud Environment: Not detected", scan.InfoRecommendation, "", 0)
	}
	itemID++
	
	// AWS Load Balancer Crypto Configuration (if in AWS environment)
	if cloudType == "AWS" {
		// Check if we discovered any load balancers
		hasLoadBalancer := false
		if clb, ok := results["Classic Load Balancer"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "AWS Load Balancer Discovery: Classic ELB Found", scan.InfoRecommendation, "Classic Load Balancer: "+clb+" (Internet-facing crypto configuration differs from instance-level)", 1)
			itemID++
			hasLoadBalancer = true
		}
		if alb, ok := results["Application Load Balancer"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "AWS Load Balancer Discovery: ALB/NLB Found", scan.InfoRecommendation, "Application/Network Load Balancer: "+alb+" (Internet-facing crypto configuration differs from instance-level)", 1)
			itemID++
			hasLoadBalancer = true
		}
		if lbArn, ok := results["Load Balancer ARN"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "Load Balancer ARN: "+lbArn, scan.InfoRecommendation, "ARN used for querying actual internet-facing SSL/TLS configuration", 1)
			itemID++
		}
		if awsCli, ok := results["AWS CLI"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "AWS CLI: "+awsCli, scan.InfoRecommendation, "AWS CLI used for load balancer crypto inspection (non-disruptive queries)", 1)
			itemID++
		}
		
		// Internet-Facing SSL/TLS Configuration Analysis
		if hasLoadBalancer {
			rm.AddStatus(moduleID, sectionID, itemID, "Internet-Facing Crypto Analysis: Load Balancer Configuration", scan.InfoRecommendation, "The following SSL/TLS settings represent what external clients see (not instance-level configuration)", 1)
			itemID++
		}
		
		if httpsListeners, ok := results["HTTPS Listeners"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "LB HTTPS Listeners: "+httpsListeners, scan.InfoRecommendation, "HTTPS listeners on load balancer (internet-facing SSL termination)", 1)
			itemID++
		}
		if sslPolicy, ok := results["Listener 1 SSL Policy"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "LB SSL Policy: "+sslPolicy, scan.InfoRecommendation, "AWS-managed SSL policy determining cipher suites and protocols for internet traffic", 1)
			itemID++
		}
		if pqcReady, ok := results["Listener 1 PQC Ready"]; ok {
			if pqcReady == "true" {
				rm.AddStatus(moduleID, sectionID, itemID, "LB PQC Readiness: Ready", scan.InfoRecommendation, "Load balancer SSL policy supports modern cipher suites and TLS 1.3 for PQC transition", 1)
			} else {
				rm.AddStatus(moduleID, sectionID, itemID, "LB PQC Readiness: Needs Upgrade", scan.WarningRecommendation, "Load balancer SSL policy requires upgrade to support PQC algorithms", 3)
			}
			itemID++
		}
		if protocols, ok := results["Listener 1 Protocols"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "LB TLS Protocols: "+protocols, scan.InfoRecommendation, "TLS protocol versions supported by load balancer for internet-facing connections", 1)
			itemID++
		}
	}
	
	// OpenSSL status
	if openssl, ok := results["OpenSSL"]; ok {
		rm.AddStatus(moduleID, sectionID, itemID, "OpenSSL: "+openssl, scan.InfoRecommendation, "", 1)
		itemID++
		if oqsProvider, ok := results["OQS Provider"]; ok {
			rm.AddStatus(moduleID, sectionID, itemID, "OQS Provider: "+oqsProvider, scan.InfoRecommendation, "", 1)
			itemID++
		}
	}
	
	// Web servers
	if nginx, ok := results["Nginx"]; ok && nginx != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "Nginx: "+nginx, scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	if apache, ok := results["Apache"]; ok && apache != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "Apache: "+apache, scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	// OpenVPN
	if openvpn, ok := results["OpenVPN"]; ok && openvpn != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "OpenVPN: "+openvpn, scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	// IPsec
	if ipsec, ok := results["IPsec"]; ok && ipsec != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "IPsec: "+ipsec, scan.InfoRecommendation, "", 1)
		itemID++
	}
	
	// tcpdump
	if tcpdump, ok := results["tcpdump"]; ok && tcpdump != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "tcpdump: "+tcpdump, scan.InfoRecommendation, "", 0)
		itemID++
	}
	
	// tshark
	if tshark, ok := results["tshark"]; ok && tshark != "Not installed" {
		rm.AddStatus(moduleID, sectionID, itemID, "tshark: "+tshark, scan.InfoRecommendation, "", 0)
		itemID++
	}
}

package linux

import (
	"fmt"
	"mini-pqc/scan"
	"sort"
	"strings"
)

// GenerateKernelRecommendationsFromInfo creates evidence-backed recommendations from KernelInfo
func GenerateKernelRecommendationsFromInfo(info KernelInfo, awsResults map[string]string) []scan.Recommendation {
	moduleID := scan.CommandModules["kernel"]
	recommendations := make([]scan.Recommendation, 0, 8)

	// Section 2: Update Status and PQC Readiness
	sectionID := 2

	// 2.1 Kernel update status
	recommendations = append(recommendations, generateUpdateRecommendation(moduleID, sectionID, 1, info))

	// 2.2 PQC crypto availability in kernel
	recommendations = append(recommendations, generatePQCCryptoRecommendation(moduleID, sectionID, 2, info))

	// 2.3 CNSA 2.0 monitoring guidance
	recommendations = append(recommendations, generateCNSARecommendation(moduleID, sectionID, 3, info))

	// 2.4 Lifecycle/EOL warnings
	if info.LifecyclePhase == PhaseEOL || info.LifecyclePhase == PhaseMaintenance {
		recommendations = append(recommendations, generateLifecycleRecommendation(moduleID, sectionID, 4, info))
	}

	// Section 3: Security Hardening (evidence-backed)
	sectionID = 3

	// 3.1 ASLR configuration
	if val, ok := info.Sysctl["kernel.randomize_va_space"]; !ok || val != "2" {
		recommendations = append(recommendations, generateASLRRecommendation(moduleID, sectionID, 1, info, val))
	}

	// 3.2 Kernel pointer restrictions
	if val, ok := info.Sysctl["kernel.kptr_restrict"]; !ok || (val != "1" && val != "2") {
		recommendations = append(recommendations, generateKptrRecommendation(moduleID, sectionID, 2, info, val))
	}

	// 3.3 Network security settings
	recommendations = append(recommendations, generateNetworkSecurityRecommendations(moduleID, sectionID, info)...)

	// Add AWS-specific recommendations if in AWS environment
	if len(awsResults) > 0 {
		recommendations = append(recommendations, generateAWSKernelRecommendations(moduleID, info, awsResults)...)
	}

	return recommendations
}

// generateUpdateRecommendation creates kernel update recommendation with evidence
func generateUpdateRecommendation(moduleID, sectionID, itemID int, info KernelInfo) scan.Recommendation {
	if compareKernelVersions(info.LatestInRepo, info.Version) > 0 {
		return scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Kernel update available via package manager",
			Type:      scan.InfoRecommendation,
			Severity:  3,
			Details: fmt.Sprintf(
				"Current: %s; available in repos: %s. Upgrading keeps you on a supported channel and brings security + crypto fixes.",
				info.Version, info.LatestInRepo),
			Evidence: []scan.Evidence{
				{Probe: "uname -r", Snippet: info.Version},
				{Probe: fmt.Sprintf("%s query kernel", info.PkgMgr), Snippet: truncateString(info.LatestInRepo, 120)},
			},
			Confidence: "high",
			References: []string{
				"https://www.kernel.org/category/releases.html",
			},
		}
	} else {
		return scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Kernel appears up-to-date in your repo channel",
			Type:      scan.InfoRecommendation,
			Severity:  2,
			Details:   "No newer kernel package detected in the configured repositories.",
			Evidence: []scan.Evidence{
				{Probe: "uname -r", Snippet: info.Version},
				{Probe: fmt.Sprintf("%s query kernel", info.PkgMgr), Snippet: truncateString(info.LatestInRepo, 120)},
			},
			Confidence: "high",
			References: []string{"https://www.kernel.org/category/releases.html"},
		}
	}
}

// generatePQCCryptoRecommendation checks for PQC algorithms in kernel crypto API
func generatePQCCryptoRecommendation(moduleID, sectionID, itemID int, info KernelInfo) scan.Recommendation {
	pqcAlgos := []string{"kyber", "ml-kem", "dilithium", "ml-dsa", "sphincs", "slh-dsa"}
	foundPQC := false
	
	for _, algo := range info.CryptoAlgos {
		algoLower := strings.ToLower(algo)
		for _, pqc := range pqcAlgos {
			if strings.Contains(algoLower, pqc) {
				foundPQC = true
				break
			}
		}
		if foundPQC {
			break
		}
	}

	if !foundPQC {
		return scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Kernel crypto API: no PQC primitives detected",
			Type:      scan.InfoRecommendation,
			Severity:  2,
			Details: "No ML-KEM/ML-DSA/Sphincs-like algorithms were listed by /proc/crypto. " +
				"That's common today; prioritize PQC in user space (e.g., OpenSSL 3.x with OQS provider) " +
				"and track protocol guidance (TLS, IPsec) for CNSA 2.0 adoption.",
			Evidence: []scan.Evidence{
				{Probe: "cat /proc/crypto | head -n 30", Snippet: strings.Join(info.CryptoAlgos[:min(10, len(info.CryptoAlgos))], ", ")},
			},
			Confidence: "high",
			References: []string{
				"https://man7.org/linux/man-pages/man5/proc_crypto.5.html",
			},
		}
	} else {
		return scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Kernel crypto API: PQC primitives detected",
			Type:      scan.SuccessRecommendation,
			Severity:  1,
			Details:   "Post-quantum cryptographic algorithms found in kernel crypto API. This indicates advanced PQC support.",
			Evidence: []scan.Evidence{
				{Probe: "cat /proc/crypto | grep -i 'kyber\\|ml-kem\\|dilithium\\|ml-dsa'", Snippet: "PQC algorithms found"},
			},
			Confidence: "high",
			References: []string{
				"https://man7.org/linux/man-pages/man5/proc_crypto.5.html",
			},
		}
	}
}

// generateCNSARecommendation provides CNSA 2.0 guidance
func generateCNSARecommendation(moduleID, sectionID, itemID int, info KernelInfo) scan.Recommendation {
	return scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Monitor CNSA 2.0 profiles for Linux protocol stacks",
		Type:      scan.InfoRecommendation,
		Severity:  2,
		Details: "Prefer ML-KEM-1024 for key establishment and ML-DSA-87 for signatures as they become " +
			"available in validated stacks; firmware/software signing can use LMS/XMSS. IPsec/IKEv2 is " +
			"expected to use a hybrid approach to accommodate ML-KEM sizes.",
		Confidence: "high",
		References: []string{
			"https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
		},
	}
}

// generateLifecycleRecommendation warns about EOL/maintenance kernels
func generateLifecycleRecommendation(moduleID, sectionID, itemID int, info KernelInfo) scan.Recommendation {
	severity := 3
	if info.LifecyclePhase == PhaseEOL {
		severity = 4
	}

	return scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Kernel channel is out of vendor security support",
		Type:      scan.WarningRecommendation,
		Severity:  severity,
		Details: fmt.Sprintf(
			"Distro: %s %s. Evidence shows %s phase. "+
				"Consider moving to a supported kernel channel for security updates.",
			info.Distro, info.DistroVersion, info.LifecyclePhase),
		Evidence: []scan.Evidence{
			{Probe: "cat /etc/os-release", Snippet: fmt.Sprintf("%s %s", info.Distro, info.DistroVersion)},
		},
		Confidence: "medium",
		References: getLifecycleReferences(info.Distro),
	}
}

// generateASLRRecommendation creates ASLR recommendation with evidence
func generateASLRRecommendation(moduleID, sectionID, itemID int, info KernelInfo, currentVal string) scan.Recommendation {
	return scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Enable full address space layout randomization (ASLR)",
		Type:      scan.WarningRecommendation,
		Severity:  3,
		Details: fmt.Sprintf(
			"Observed kernel.randomize_va_space=%s (expected 2). "+
				"ASLR is critical for mitigating buffer overflow attacks by randomizing memory addresses. "+
				"Verify with: sysctl kernel.randomize_va_space",
			currentVal),
		Evidence: []scan.Evidence{
			{Probe: "sysctl -n kernel.randomize_va_space", Snippet: currentVal},
		},
		Confidence: "high",
		References: []string{
			"https://www.kernel.org/doc/Documentation/admin-guide/sysctl/kernel.rst",
		},
	}
}

// generateKptrRecommendation creates kernel pointer restriction recommendation
func generateKptrRecommendation(moduleID, sectionID, itemID int, info KernelInfo, currentVal string) scan.Recommendation {
	return scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Restrict kernel pointer exposure",
		Type:      scan.WarningRecommendation,
		Severity:  2,
		Details: fmt.Sprintf(
			"Observed kernel.kptr_restrict=%s (expected ≥1). "+
				"Exposing kernel pointers can leak memory layout information. "+
				"Verify with: sysctl kernel.kptr_restrict",
			currentVal),
		Evidence: []scan.Evidence{
			{Probe: "sysctl -n kernel.kptr_restrict", Snippet: currentVal},
		},
		Confidence: "high",
		References: []string{
			"https://www.kernel.org/doc/Documentation/admin-guide/sysctl/kernel.rst",
		},
	}
}

// Helper functions
func compareKernelVersions(latest, current string) int {
	// Simplified version comparison - in production this would be more sophisticated
	if latest == "unknown" || current == "unknown" {
		return 0
	}
	if latest != current {
		return 1 // Assume newer available
	}
	return 0
}



func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getLifecycleReferences(distro string) []string {
	switch distro {
	case "ubuntu":
		return []string{
			"https://ubuntu.com/kernel/lifecycle",
			"https://wiki.ubuntu.com/Kernel/LTSEnablementStack",
		}
	case "debian":
		return []string{
			"https://www.debian.org/lts/",
			"https://endoflife.date/debian",
		}
	case "rhel", "centos", "almalinux", "rocky":
		return []string{
			"https://access.redhat.com/support/policy/updates/errata",
			"https://endoflife.date/rhel",
		}
	default:
		return []string{
			"https://www.kernel.org/category/releases.html",
		}
	}
}

// generateNetworkSecurityRecommendations creates network security recommendations
func generateNetworkSecurityRecommendations(moduleID, sectionID int, info KernelInfo) []scan.Recommendation {
	var recs []scan.Recommendation
	itemID := 3

	// TCP SYN cookies
	if val, ok := info.Sysctl["net.ipv4.tcp_syncookies"]; !ok || val != "1" {
		recs = append(recs, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Enable TCP SYN cookies",
			Type:      scan.WarningRecommendation,
			Severity:  2,
			Details: fmt.Sprintf(
				"Observed net.ipv4.tcp_syncookies=%s (expected 1). "+
					"SYN cookies help prevent SYN flood attacks.",
				val),
			Evidence: []scan.Evidence{
				{Probe: "sysctl -n net.ipv4.tcp_syncookies", Snippet: val},
			},
			Confidence: "high",
			References: []string{
				"https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt",
			},
		})
		itemID++
	}

	return recs
}

// generateAWSKernelRecommendations creates AWS-specific kernel recommendations
func generateAWSKernelRecommendations(moduleID int, info KernelInfo, awsResults map[string]string) []scan.Recommendation {
	var recs []scan.Recommendation
	sectionID := 4

	// AWS-specific kernel guidance
	recs = append(recs, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    1,
		Text:      "Monitor AWS kernel updates for PQC readiness",
		Type:      scan.InfoRecommendation,
		Severity:  2,
		Details: "AWS provides optimized kernels for EC2 instances. Monitor AWS security bulletins " +
			"for kernel updates that include post-quantum cryptography support.",
		Confidence: "medium",
		References: []string{
			"https://aws.amazon.com/security/security-bulletins/",
		},
	})

	return recs
}

// Legacy function for backward compatibility (will be deprecated)
func generateKernelRecommendations_LEGACY_DISABLED(secureCount, insecureCount, pqcRelevantCount int, insecureParams map[string]KernelParam,
	cryptoAlgos map[string]CryptoAlgorithm, pqcCompliantCount, nonPQCCompliantCount int, awsResults map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["kernel"] // Module ID for kernel

	// Section 1: Immediate Actions
	sectionID := 1

	// Add recommendations based on kernel security parameters
	if insecureCount > 0 {
		// ASLR recommendation
		details := "ASLR is critical for mitigating buffer overflow attacks by randomizing memory addresses. Without ASLR, attackers can more easily predict memory locations and execute exploits. Enable it by setting kernel.randomize_va_space=2 in /etc/sysctl.conf and applying with 'sysctl -p'."

		// Check if we have actual parameter value
		if param, ok := insecureParams["kernel.randomize_va_space"]; ok {
			details = fmt.Sprintf("ASLR is currently disabled or partially enabled (kernel.randomize_va_space=%s). "+
				"It should be set to 2 for full protection. ASLR is critical for mitigating buffer overflow attacks by randomizing memory addresses. "+
				"Without ASLR, attackers can more easily predict memory locations and execute exploits. "+
				"Fix: Set kernel.randomize_va_space=2 in /etc/sysctl.conf and apply with 'sysctl -p'.", param.value)
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1, // ASLR ID
			Text:      "Enable address space layout randomization (ASLR) (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   details,
			Severity:  2, // Medium severity - important for PQC readiness
		})

		// Kernel pointers recommendation
		pointersDetails := "Exposing kernel pointers can leak memory layout information that aids attackers in exploiting vulnerabilities. Set kernel.kptr_restrict=1 and kernel.dmesg_restrict=1 in /etc/sysctl.conf to prevent unprivileged users from accessing this sensitive information."

		// Check if we have actual parameter values
		var paramDetails []string
		if param, ok := insecureParams["kernel.kptr_restrict"]; ok {
			paramDetails = append(paramDetails, fmt.Sprintf("kernel.kptr_restrict=%s (should be 1 or 2)", param.value))
		}
		if param, ok := insecureParams["kernel.dmesg_restrict"]; ok {
			paramDetails = append(paramDetails, fmt.Sprintf("kernel.dmesg_restrict=%s (should be 1)", param.value))
		}

		if len(paramDetails) > 0 {
			pointersDetails = fmt.Sprintf("Insecure kernel pointer protection settings detected: %s. "+
				"Exposing kernel pointers can leak memory layout information that aids attackers in exploiting vulnerabilities. "+
				"Fix: Set kernel.kptr_restrict=1 and kernel.dmesg_restrict=1 in /etc/sysctl.conf to prevent unprivileged users from accessing this sensitive information.",
				strings.Join(paramDetails, ", "))
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    2, // Kernel pointers ID
			Text:      "Restrict access to kernel pointers and logs (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   pointersDetails,
			Severity:  2, // Medium severity - important for PQC readiness
		})

		// SysRq recommendation
		sysrqDetails := "The SysRq key provides direct hardware access that can bypass security restrictions. Set kernel.sysrq=0 in /etc/sysctl.conf to disable it completely, or use a limited value (e.g., 4 for SAK only, 16 for sync, or 176 for safe defaults) if you need specific functionality."

		// Check if we have actual parameter value
		if param, ok := insecureParams["kernel.sysrq"]; ok {
			sysrqDetails = fmt.Sprintf("SysRq is currently enabled or insufficiently restricted (kernel.sysrq=%s). "+
				"The SysRq key provides direct hardware access that can bypass security restrictions. "+
				"Fix: Set kernel.sysrq=0 in /etc/sysctl.conf to disable it completely, or use a limited value "+
				"(e.g., 4 for SAK only, 16 for sync, or 176 for safe defaults) if you need specific functionality.",
				param.value)
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    3, // SysRq ID
			Text:      "Disable or restrict SysRq key functions (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   sysrqDetails,
			Severity:  2, // Low-medium severity - informational but affects testing
		})

		// BPF recommendation
		bpfDetails := "Berkeley Packet Filter (BPF) capabilities can be abused to exploit the kernel if accessible by unprivileged users. This is increasingly important as BPF-based attacks become more sophisticated. Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.conf to restrict BPF usage to privileged users only."

		// Check if we have actual parameter value
		if param, ok := insecureParams["kernel.unprivileged_bpf_disabled"]; ok {
			bpfDetails = fmt.Sprintf("Unprivileged BPF is currently enabled (kernel.unprivileged_bpf_disabled=%s). "+
				"Berkeley Packet Filter (BPF) capabilities can be abused to exploit the kernel if accessible by unprivileged users. "+
				"This is increasingly important as BPF-based attacks become more sophisticated. "+
				"Fix: Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.conf to restrict BPF usage to privileged users only.",
				param.value)
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    4, // BPF ID
			Text:      "Disable unprivileged BPF (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   bpfDetails,
			Severity:  2, // Medium severity - important for PQC readiness
		})

		// SYN cookies recommendation
		synDetails := "SYN cookies protect against SYN flood attacks by validating connection requests without consuming resources. Source route validation prevents source routing attacks. Configure net.ipv4.tcp_syncookies=1 and net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.conf to implement these protections."

		// Check if we have actual parameter values
		var synParamDetails []string
		if param, ok := insecureParams["net.ipv4.tcp_syncookies"]; ok {
			synParamDetails = append(synParamDetails, fmt.Sprintf("net.ipv4.tcp_syncookies=%s (should be 1)", param.value))
		}
		if param, ok := insecureParams["net.ipv4.conf.all.accept_source_route"]; ok {
			synParamDetails = append(synParamDetails, fmt.Sprintf("net.ipv4.conf.all.accept_source_route=%s (should be 0)", param.value))
		}

		if len(synParamDetails) > 0 {
			synDetails = fmt.Sprintf("Network protection settings are insufficient: %s. "+
				"SYN cookies protect against SYN flood attacks by validating connection requests without consuming resources. "+
				"Source route validation prevents source routing attacks. "+
				"Fix: Configure net.ipv4.tcp_syncookies=1 and net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.conf.",
				strings.Join(synParamDetails, ", "))
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    5, // SYN cookies ID
			Text:      "Enable SYN cookies and source route validation (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   synDetails,
			Severity:  2, // Medium severity - important for PQC readiness
		})

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    6, // ICMP ID (fixed duplicate ID)
			Text:      "Disable ICMP redirects and source routing (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   "ICMP redirects can be exploited for man-in-the-middle attacks by redirecting traffic through malicious routers. Set net.ipv4.conf.all.accept_redirects=0 and net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.conf to prevent these attacks and improve network security.",
			Severity:  2, // Medium severity - important for PQC readiness
		})

		// IP spoofing protection recommendation
		rpFilterDetails := "IP spoofing is a common attack vector where attackers forge source addresses to bypass network filters. Enable rp_filter (reverse path filtering) by setting net.ipv4.conf.all.rp_filter=1 and net.ipv4.conf.default.rp_filter=1 in /etc/sysctl.conf to automatically drop spoofed packets."

		// Check if we have actual parameter values
		var rpFilterParams []string
		if param, ok := insecureParams["net.ipv4.conf.all.rp_filter"]; ok {
			rpFilterParams = append(rpFilterParams, fmt.Sprintf("net.ipv4.conf.all.rp_filter=%s (should be 1)", param.value))
		}
		if param, ok := insecureParams["net.ipv4.conf.default.rp_filter"]; ok {
			rpFilterParams = append(rpFilterParams, fmt.Sprintf("net.ipv4.conf.default.rp_filter=%s (should be 1)", param.value))
		}

		if len(rpFilterParams) > 0 {
			rpFilterDetails = fmt.Sprintf("IP spoofing protection is insufficient: %s. "+
				"IP spoofing is a common attack vector where attackers forge source addresses to bypass network filters. "+
				"Fix: Enable rp_filter (reverse path filtering) by setting net.ipv4.conf.all.rp_filter=1 and "+
				"net.ipv4.conf.default.rp_filter=1 in /etc/sysctl.conf to automatically drop spoofed packets.",
				strings.Join(rpFilterParams, ", "))
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    7, // IP spoofing ID (fixed duplicate ID)
			Text:      "Enable IP spoofing protection	 (non PQC)",
			Type:      scan.WarningRecommendation,
			Details:   rpFilterDetails,
			Severity:  2, // Medium severity - important for PQC readiness
		})
	}

	// Section 2: Future Preparation
	sectionID = 2

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    1, // Kernel updates ID
		Text:      "Keep your kernel updated to the latest version",
		Type:      scan.InfoRecommendation,
		Details:   "Newer kernel versions include important security patches, improved performance, and enhanced cryptographic capabilities. Regularly update your kernel using your distribution's package manager (apt, yum, etc.) to benefit from these improvements and protect against known vulnerabilities.",
		Severity:  3, // Medium severity - important for PQC readiness
	})

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    2, // PQC monitoring ID
		Text:      "Monitor for kernel PQC support in future updates",
		Type:      scan.InfoRecommendation,
		Details:   "Post-quantum cryptography support is gradually being integrated into the Linux kernel. Subscribe to your distribution's security announcements and periodically check for kernel updates that mention quantum-resistant algorithms or PQC. These will be crucial for maintaining security against quantum computing threats.",
		Severity:  2, // Low-medium severity - informational but affects testing
	})

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    3, // Hardened kernel ID
		Text:      "Consider using a hardened kernel like grsecurity if available",
		Type:      scan.InfoRecommendation,
		Details:   "Hardened kernels provide enhanced security through additional exploit mitigations, stricter access controls, and improved isolation mechanisms. Distributions like Arch Linux and Debian offer hardened kernel options. These kernels may provide stronger protection against both classical and quantum-based attack vectors.",
		Severity:  2, // Low-medium severity - informational but affects testing
	})

	// Section 3: Cryptographic Algorithm Recommendations
	sectionID = 3

	// Add recommendations based on cryptographic algorithm analysis
	{
		// Build categorized algorithm lists
		var (
			pqcAlgosList   []string
			cnsaAlgosList  []string
			vulnAlgosList  []string
			otherAlgosList []string
		)

		for name, algo := range cryptoAlgos {
			entry := fmt.Sprintf("%s (Type: %s)", name, algo.Type)
			switch strings.ToLower(algo.PQCStatus) {
			case "compliant":
				pqcAlgosList = append(pqcAlgosList, entry)
			case "cnsa-approved":
				cnsaAlgosList = append(cnsaAlgosList, entry)
			case "quantum-vulnerable":
				vulnAlgosList = append(vulnAlgosList, entry)
			default:
				otherAlgosList = append(otherAlgosList, entry)
			}
		}

		// Determine if we should emit this recommendation
		shouldRecommend := len(vulnAlgosList) > 0 || len(otherAlgosList) > 0 || pqcCompliantCount == 0
		if shouldRecommend {
			// Sort lists for consistent display
			sort.Strings(pqcAlgosList)
			sort.Strings(cnsaAlgosList)
			sort.Strings(vulnAlgosList)
			sort.Strings(otherAlgosList)

			// Compose details with clear separation of categories
			var b strings.Builder
			total := len(pqcAlgosList) + len(cnsaAlgosList) + len(vulnAlgosList) + len(otherAlgosList)
			fmt.Fprintf(&b, "\n\nKernel crypto algorithms summary: %d total | %d PQC | %d CNSA-approved symmetric/hash | %d quantum-vulnerable asymmetric | %d other\n",
				total, len(pqcAlgosList), len(cnsaAlgosList), len(vulnAlgosList), len(otherAlgosList))

			if len(pqcAlgosList) > 0 {
				b.WriteString("\nQuantum-Resistant Algorithms (PQC):\n")
				for _, s := range pqcAlgosList {
					b.WriteString(fmt.Sprintf("• %s\n", s))
				}
			}

			if len(cnsaAlgosList) > 0 {
				b.WriteString("\nCNSA-Approved Symmetric/Hash (quantum-safe):\n")
				// Limit verbosity for long lists
				max := len(cnsaAlgosList)
				if max > 15 { max = 15 }
				for i := 0; i < max; i++ {
					b.WriteString(fmt.Sprintf("• %s\n", cnsaAlgosList[i]))
				}
				if len(cnsaAlgosList) > 15 {
					b.WriteString(fmt.Sprintf("• ... and %d more CNSA-approved algorithms\n", len(cnsaAlgosList)-15))
				}
			}

			if len(vulnAlgosList) > 0 {
				b.WriteString("\nQuantum-Vulnerable Asymmetric Algorithms:\n")
				max := len(vulnAlgosList)
				if max > 15 { max = 15 }
				for i := 0; i < max; i++ {
					b.WriteString(fmt.Sprintf("• %s\n", vulnAlgosList[i]))
				}
				if len(vulnAlgosList) > 15 {
					b.WriteString(fmt.Sprintf("• ... and %d more quantum-vulnerable algorithms\n", len(vulnAlgosList)-15))
				}
			}

			if len(otherAlgosList) > 0 {
				b.WriteString("\nOther/Unclassified Algorithms:\n")
				max := len(otherAlgosList)
				if max > 10 { max = 10 }
				for i := 0; i < max; i++ {
					b.WriteString(fmt.Sprintf("• %s\n", otherAlgosList[i]))
				}
				if len(otherAlgosList) > 10 {
					b.WriteString(fmt.Sprintf("• ... and %d more other algorithms\n", len(otherAlgosList)-10))
				}
			}

			// General recommendation for crypto policy
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1, // Crypto policy ID
				Text:      "Enable post-quantum cryptography in kernel crypto policies",
				Type:      scan.WarningRecommendation,
				Details: fmt.Sprintf(
					"Only %d PQC algorithms are available today in mainline kernels. "+
						"Prefer PQC where supported; otherwise use TLS 1.3 with AEAD and CNSA-approved primitives while monitoring for kernel PQC integration. "+
						"Monitor vendor kernel releases for PQC module availability and enable them when available. "+
						"Target CNSA 2.0 modules: ML-KEM-1024 (KEM) and ML-DSA-87 (signatures). %s",
					pqcCompliantCount, b.String(),
				),
				Severity: 3, // Medium severity - important for PQC readiness
			})

			// Specific recommendation to load PQC modules
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    2, // Crypto modules ID
				Text:      "Enable quantum-resistant cryptographic kernel modules",
				Type:      scan.WarningRecommendation,
				Details: "Monitor kernel releases for PQC module availability. When PQC modules become available, "+
					"load ML-KEM-1024 and ML-DSA-87 modules and verify their presence via /proc/crypto. "+
					"Currently, most mainline kernels do not include these modules, but future releases may provide them. "+
					"Configure auto-loading via /etc/modules-load.d/pqc.conf when modules are available.",
				Severity: 3, // Medium severity - important for PQC readiness
			})

			// Phase out quantum-vulnerable algorithms
			if len(vulnAlgosList) > 0 {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    3, // Phase out quantum-vulnerable ID
					Text:      "Phase out kernel use of RSA/ECC for key exchange/signatures; retain AES-256/SHA-384/512",
					Type:      scan.WarningRecommendation,
					Details: fmt.Sprintf("Found %d quantum-vulnerable asymmetric algorithms in kernel crypto. "+
						"Plan migration away from RSA, ECDSA, ECDH, and DH-based key exchange and digital signatures. "+
						"Continue using CNSA-approved symmetric encryption (AES-256) and hash functions (SHA-384/512) as they remain quantum-safe. "+
						"Prioritize replacing asymmetric operations with hybrid approaches or PQC alternatives when available. "+
						"Focus migration efforts on kernel modules handling key exchange, certificate validation, and digital signatures.",
						len(vulnAlgosList)),
					Severity: 4, // High severity - requires migration planning
				})
			}

			// Ongoing monitoring
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    4, // Crypto monitoring ID (updated from 3 to 4)
				Text:      "Implement regular monitoring of cryptographic algorithms in use",
				Type:      scan.InfoRecommendation,
				Details: "Regularly check /proc/crypto to monitor which cryptographic algorithms are being used by your system. "+
					"Create a baseline of expected algorithms and alert on unexpected changes or use of deprecated/vulnerable algorithms. "+
					"This proactive monitoring helps ensure your system maintains compliance with PQC requirements over time.",
				Severity: 2, // Low-medium severity - informational but important for ongoing compliance
			})

		}
	}
	// Section 2: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 2
		itemID := 1

		// Kernel security and AWS load balancer coordination
		if _, ok := awsResults["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate kernel security hardening with AWS load balancer configurations",
				Type:      scan.InfoRecommendation,
				Details:   "Your kernel security configuration runs behind an AWS load balancer. Consider these security coordination strategies:\n\n" +
					"• Kernel provides system-level cryptographic modules and security hardening\n" +
					"• AWS load balancer handles internet-facing TLS termination and traffic distribution\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND enable kernel PQC crypto modules\n" +
					"• Kernel ASLR and security features protect against attacks that bypass load balancer security\n" +
					"• Monitor both AWS security updates and kernel crypto module availability\n" +
					"• Consider AWS-specific kernel optimizations (e.g., enhanced networking, SR-IOV)\n\n" +
					"This multi-layer approach ensures comprehensive security from network edge to system core.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific kernel deployment considerations
		if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy alongside kernel crypto improvements",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. While hardening your kernel crypto modules improves system-level security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites to complement kernel-level cryptographic improvements.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// AWS infrastructure recommendations for kernel security
		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS infrastructure for kernel security and PQC readiness",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For kernel security in AWS:\n\n" +
					"• Use AWS Systems Manager for secure kernel parameter management\n" +
					"• Enable AWS CloudTrail for auditing kernel configuration changes\n" +
					"• Use AWS Config to monitor kernel security compliance\n" +
					"• Consider AWS Nitro System benefits for enhanced cryptographic performance\n" +
					"• Implement AWS Security Groups as additional network-level protection\n" +
					"• Use AWS KMS for hardware-backed cryptographic operations when available\n" +
					"• Monitor AWS security bulletins for kernel and infrastructure updates\n\n" +
					"This AWS-integrated approach provides enterprise-grade kernel security with cloud-native monitoring and management.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

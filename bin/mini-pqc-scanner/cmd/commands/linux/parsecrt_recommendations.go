package linux

import (
    "fmt"
    "time"
    "mini-pqc/scan"
)

// CertInfo and ServiceReference are defined in parsecrt.go

// generateCertRecommendations creates recommendations based on certificate analysis
func generateCertRecommendations(stats map[string]int, highPriorityCerts []CertInfo) []scan.Recommendation {
    recommendations := []scan.Recommendation{}

    // Critical: certificates valid beyond 2030 with classical crypto
    if stats["expiring2030"] > 0 {
        recommendations = append(recommendations, scan.Recommendation{
            ModuleID:  scan.CommandModules["parsecrt"],
            SectionID: 1,
            ItemID:    1,
            Text:      fmt.Sprintf("Replace %d certificates valid beyond 2030 that use non-quantum-resistant algorithms", stats["expiring2030"]),
            Type:      scan.CriticalRecommendation,
            Details:   "The 2030 deadline is based on NIST and NSA CNSA (Commercial National Security Algorithm) guidance, which identifies 2030 as a critical transition point for quantum security.\n\n" +
                "Why 2030 is significant:\n" +
                "• NIST projects that by 2030, quantum computers may be capable of breaking RSA and ECC cryptography\n" +
                "• The NSA's CNSA suite mandates transition to quantum-resistant algorithms by 2030\n" +
                "• Certificates valid beyond 2030 that use classical algorithms (RSA, DSA, ECC) will be vulnerable\n" +
                "• Long-lived certificates issued today with classical algorithms may still be in use during the quantum threat period\n\n" +
                "Recommended actions:\n" +
                "• Identify and inventory all certificates with validity periods extending beyond 2030\n" +
                "• Develop a migration strategy to replace these certificates with quantum-resistant alternatives\n" +
                "• Consider implementing shorter validity periods (1-2 years) for all new certificates\n" +
                "• Monitor NIST standardization of post-quantum cryptography algorithms\n" +
                "• Plan to deploy hybrid certificates (classical + post-quantum) when available from your CA",
            Severity:  5, // CRITICAL - harvest-now/decrypt-later risk for long-lived certificates
        })
    }

    // High-priority certificates currently in use
    nonPqcHighPriority := 0
    for _, cert := range highPriorityCerts {
        if cert.keyType != "PQC" && cert.expiry.After(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
            nonPqcHighPriority++
        }
    }

    if nonPqcHighPriority > 0 {
        recommendations = append(recommendations, scan.Recommendation{
            ModuleID:  scan.CommandModules["parsecrt"],
            SectionID: 1,
            ItemID:    2,
            Text:      fmt.Sprintf("Prioritize replacing %d actively used certificates with quantum-resistant alternatives", nonPqcHighPriority),
            Type:      scan.CriticalRecommendation,
            Severity:  5, // CRITICAL - actively used certificates with PQC vulnerability
        })
    }

    // General strategy recommendation
    recommendations = append(recommendations, scan.Recommendation{
        ModuleID:  scan.CommandModules["parsecrt"],
        SectionID: 2,
        ItemID:    1,
        Text:      "Develop a certificate migration strategy to transition to quantum-resistant algorithms before 2030",
        Type:      scan.InfoRecommendation,
        Severity:  3, // MODERATE - strategic planning for PQC transition
    })

    return recommendations
}
func generateCertificateRecommendations(stats map[string]int, serviceUsage map[string][]ServiceReference) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["parsecrt"] // Should be the module ID for parsecrt

	// Section 1: Immediate Actions
	sectionID := 1
	itemID := 1

	// Recommendations for classical crypto certificates
	if stats["rsa"] > 0 || stats["ecdsa"] > 0 || stats["dsa"] > 0 {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Replace RSA, ECDSA, and DSA certificates with PQC or hybrid algorithms",
			Type:      scan.WarningRecommendation,
			Severity:  4, // High severity - critical for PQC implementation
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "For certificates that must use classical crypto, limit validity to before 2030",
			Type:      scan.WarningRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Consider using ephemeral certificates with shorter lifetimes",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	}

	// Recommendations for expired certificates
	if stats["expired"] > 0 {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Remove or replace expired certificates",
			Type:      scan.WarningRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	}

	// Recommendations for certificates in active use
	if stats["used"] > 0 {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Prioritize replacing certificates used by active services",
			Type:      scan.WarningRecommendation,
			Severity:  4, // High severity - critical for PQC implementation
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Update service configurations to use PQC-ready certificates",
			Type:      scan.WarningRecommendation,
			Severity:  4, // High severity - critical for PQC implementation
		})
		itemID++
	}

	// Section 2: Future Preparation
	sectionID = 2
	itemID = 1

	// General PQC recommendations
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Monitor NIST PQC standardization for approved algorithms",
		Type:      scan.InfoRecommendation,
		Severity:  1, // Low severity - informational
	})
	itemID++

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "When replacing certificates, use OpenSSL 3.2+ with PQC support",
		Type:      scan.InfoRecommendation,
		Severity:  2, // Low-medium severity - informational but affects testing
	})
	itemID++

	// If there are certificates valid beyond 2030
	if stats["expiring2030"] > 0 {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Develop a migration plan for certificates valid beyond 2030",
			Type:      scan.InfoRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++
	}

	return recommendations
}

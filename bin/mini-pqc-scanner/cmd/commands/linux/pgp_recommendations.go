package linux

import (
	"fmt"
	"os/exec"
	"mini-pqc/scan"
	"strconv"
	"strings"
	"time"
)

// generatePGPRecommendations creates structured recommendations for PGP keys
func generatePGPRecommendations(pqcKeys, classicKeys []PGPKeyInfo, awsResults map[string]string) []scan.Recommendation {
	recommendations := make([]scan.Recommendation, 0)
	moduleID := scan.CommandModules["testpgp"] // Module ID for testpgp

	// Section 1: Immediate Actions
	sectionID := 1
	itemID := 1

	// Recommendations for classic (non-PQC) keys
	if len(classicKeys) > 0 {
		// Analyze key types to provide specific recommendations
		keyDetails := analyzeClassicKeyTypes(classicKeys)
		
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "For standard GnuPG, use RSA-4096 as a temporary measure",
			Type:      scan.InfoRecommendation,
			Details:   keyDetails,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++

		// Check if any keys have no expiration or expiration > 2 years
		keysWithNoOrLongExpiration := findKeysWithNoOrLongExpiration(classicKeys)
		if len(keysWithNoOrLongExpiration) > 0 {
			// Format key IDs for display
			keyDetails := formatKeyIdsForDisplay(keysWithNoOrLongExpiration)
			
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Set reasonable expiration dates on all keys (1-2 years)",
				Type:      scan.WarningRecommendation,
				Details:   keyDetails,
				Severity:  3, // Medium severity - important for PQC readiness
			})
			itemID++
		}
	}

	// Section 2: Future Preparation
	sectionID = 2
	itemID = 1

	// Check if GnuPG is installed
	_, err := exec.LookPath("gpg")
	gnuPGInstalled := err == nil

	// Only show PQC recommendations if GnuPG is installed
	if gnuPGInstalled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "GnuPG 2.5.0+ offers experimental support for Kyber (ML-KEM-768) in hybrid mode (e.g., x25519+kyber768)",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Monitor NIST PQC standardization for approved algorithms",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Consider hybrid approaches (classical + PQC) when available",
			Type:      scan.InfoRecommendation,
			Severity:  3, // Medium severity - important for PQC readiness
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Keep your GnuPG software updated to the latest version",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	}

	// Section 3: Notes & Limitations
	sectionID = 3
	itemID = 1

	// Only show PQC notes & limitations if GnuPG is installed
	if gnuPGInstalled {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "FIPS 203 (ML-KEM, Kyber) has been finalized; ecosystem integration in PGP remains experimental",
			Type:      scan.InfoRecommendation,
			Severity:  1, // Low severity - informational
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "GnuPG 2.5.x is a testing release series, leading to a more stable 2.6.0 version",
			Type:      scan.InfoRecommendation,
			Severity:  1, // Low severity - informational
		})
		itemID++

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      "Compatibility with existing PGP implementations may be limited during transition",
			Type:      scan.InfoRecommendation,
			Severity:  2, // Low-medium severity - informational but affects testing
		})
		itemID++
	}

	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "PQC features are intended for testing, not for production use in security-critical contexts yet",
		Type:      scan.WarningRecommendation,
		Severity:  4, // High severity - critical for PQC implementation
	})
	itemID++

	// Section 3: AWS Load Balancer Recommendations (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
		sectionID = 3
		itemID = 1

		// PGP and AWS load balancer coordination
		if _, ok := awsResults["Load Balancer Name"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Coordinate PGP key management with AWS load balancer security",
				Type:      scan.InfoRecommendation,
				Details:   "Your PGP key infrastructure runs behind an AWS load balancer. Consider these cryptographic coordination strategies:\n\n" +
					"• PGP provides end-to-end encryption and digital signatures for data and communications\n" +
					"• AWS load balancer handles internet-facing TLS termination for web interfaces\n" +
					"• For comprehensive PQC readiness: upgrade load balancer SSL policies AND prepare PGP keys for post-quantum transition\n" +
					"• Consider separate security policies for transport layer (load balancer) and application layer (PGP) encryption\n" +
					"• Plan migration strategy for both TLS certificates and PGP keys to post-quantum algorithms\n" +
					"• Monitor both AWS SSL policy updates and PGP/GnuPG PQC developments\n\n" +
					"This multi-layer approach ensures comprehensive cryptographic protection during the PQC transition.",
				Severity:  2, // Low-medium severity - informational
			})
			itemID++
		}

		// AWS-specific PGP deployment considerations
		if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
			if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
				recommendations = append(recommendations, scan.Recommendation{
					ModuleID:  moduleID,
					SectionID: sectionID,
					ItemID:    itemID,
					Text:      "Upgrade AWS load balancer SSL policy alongside PGP key improvements",
					Type:      scan.WarningRecommendation,
					Details:   fmt.Sprintf("Current PQC readiness: %s. While upgrading your PGP keys improves end-to-end encryption security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites for transport layer protection of PGP-related web interfaces and key servers.", pqcReadiness),
					Severity:  3, // Medium severity
				})
				itemID++
			}
		}

		// Cryptographic infrastructure recommendations for AWS
		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Optimize AWS infrastructure for secure PGP key management",
				Type:      scan.InfoRecommendation,
				Details:   fmt.Sprintf("Load balancer type: %s. For PGP key management in AWS:\n\n" +
					"• Use Application Load Balancer (ALB) for HTTPS key server interfaces\n" +
					"• Store PGP private keys securely using AWS KMS or AWS CloudHSM\n" +
					"• Use AWS Secrets Manager for secure key storage and rotation\n" +
					"• Implement proper security groups for key server ports (typically 11371)\n" +
					"• Use AWS Certificate Manager for TLS certificates on key management interfaces\n" +
					"• Consider AWS CloudTrail for auditing key management operations\n" +
					"• Implement backup and disaster recovery for PGP keyrings using AWS services\n\n" +
					"This AWS-integrated approach provides enterprise-grade key management with PQC preparation.", lbType),
				Severity:  1, // Low severity - informational
			})
			itemID++
		}
	}

	return recommendations
}

// findKeysWithNoOrLongExpiration finds keys that have no expiration date or expiration > 2 years
func findKeysWithNoOrLongExpiration(keys []PGPKeyInfo) []PGPKeyInfo {
	var keysWithIssues []PGPKeyInfo
	
	for _, key := range keys {
		// Check if key has no expiration date
		if key.expires == "" {
			keysWithIssues = append(keysWithIssues, key)
			continue
		}
		
		// Parse expiration date
		expDate, err := time.Parse("2006-01-02", key.expires)
		if err != nil {
			// If we can't parse the date, consider it an issue
			keysWithIssues = append(keysWithIssues, key)
			continue
		}
		
		// Calculate time difference between creation and expiration
		createDate, err := time.Parse("2006-01-02", key.created)
		if err == nil { // Only if we can parse the creation date
			duration := expDate.Sub(createDate)
			
			// Check if expiration is more than 2 years (730 days) from creation
			if duration > 730*24*time.Hour {
				keysWithIssues = append(keysWithIssues, key)
			}
		}
	}
	
	return keysWithIssues
}

// analyzeClassicKeyTypes analyzes classic key types and provides specific recommendations
func analyzeClassicKeyTypes(keys []PGPKeyInfo) string {
	if len(keys) == 0 {
		return ""
	}
	
	// Count different key types
	keyTypeCounts := make(map[string]int)
	keyTypeExamples := make(map[string]PGPKeyInfo)
	rsaWeakCount := 0
	
	for _, key := range keys {
		// Store an example of each key type
		keyTypeCounts[key.keyType]++
		if _, exists := keyTypeExamples[key.keyType]; !exists {
			keyTypeExamples[key.keyType] = key
		}
		
		// Count RSA keys with less than 4096 bits
		if key.keyType == "rsa" {
			size, err := strconv.Atoi(key.size)
			if err == nil && size < 4096 {
				rsaWeakCount++
			}
		}
	}
	
	// Build recommendation details
	var sb strings.Builder
	sb.WriteString("Current key types in use:\n\n")
	
	for keyType, count := range keyTypeCounts {
		example := keyTypeExamples[keyType]
		algorithmName := example.algorithm
		if example.size != "" {
			algorithmName += " (" + example.size + " bits)"
		}
		
		sb.WriteString(fmt.Sprintf("• %s: %d key(s)\n", algorithmName, count))
	}
	
	sb.WriteString("\nRecommendations:\n\n")
	
	// Add specific recommendations based on key types
	if rsaWeakCount > 0 {
		sb.WriteString(fmt.Sprintf("• %d RSA key(s) with less than 4096 bits should be upgraded to RSA-4096.\n", rsaWeakCount))
	}
	
	// General recommendations for all classic keys
	sb.WriteString("• RSA-4096 is recommended as a temporary measure until PQC algorithms are standardized.\n")
	sb.WriteString("• For long-term security, consider upgrading to hybrid keys when available in stable GnuPG versions.\n")
	sb.WriteString("• Recommended hybrid options in GnuPG 2.5.0+: x25519+kyber768, ed25519+dilithium.\n")
	sb.WriteString("• Note that PQC algorithms in GnuPG are currently experimental and not recommended for production use.\n")
	
	return sb.String()
}

// formatKeyIdsForDisplay formats key IDs for display in recommendation details
func formatKeyIdsForDisplay(keys []PGPKeyInfo) string {
	if len(keys) == 0 {
		return ""
	}
	
	var sb strings.Builder
	sb.WriteString("The following keys need reasonable expiration dates (1-2 years):\n\n")
	
	for i, key := range keys {
		expiration := "No expiration set"
		if key.expires != "" {
			expiration = key.expires
		}
		
		sb.WriteString(fmt.Sprintf("%d. Key ID: %s\n   Algorithm: %s\n   Created: %s\n   Expiration: %s\n\n", 
			i+1, key.keyID, key.algorithm, key.created, expiration))
	}
	
	sb.WriteString("\nConsider updating these keys with: gpg --edit-key [KEY_ID] and using the 'expire' command.")
	return sb.String()
}

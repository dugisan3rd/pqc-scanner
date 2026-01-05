package linux

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"mini-pqc/pkg/config"
	"mini-pqc/scan"
)

// RunConfigCommand runs the config command from the CLI
func RunConfigCommand() {
	Config()
}

// Config prompts the user for configuration values and updates the config file
func Config(args ...string) []scan.Recommendation {
	var recommendations []scan.Recommendation

	reader := bufio.NewReader(os.Stdin)

	// Prompt for organization name
	fmt.Print("Organization name: ")
	orgName, err := reader.ReadString('\n')
	if err != nil {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  19, // Config module ID
			SectionID: 1,
			ItemID:    1,
			Text:      "Configuration Error",
			Type:      scan.CriticalRecommendation,
			Details:   fmt.Sprintf("Failed to read organization name: %v", err),
		})
		return recommendations
	}
	orgName = strings.TrimSpace(orgName)

	// Prompt for license key
	fmt.Print("License key: ")
	licenseKey, err := reader.ReadString('\n')
	if err != nil {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  19, // Config module ID
			SectionID: 1,
			ItemID:    2,
			Text:      "Configuration Error",
			Type:      scan.CriticalRecommendation,
			Details:   fmt.Sprintf("Failed to read license key: %v", err),
		})
		return recommendations
	}
	licenseKey = strings.TrimSpace(licenseKey)

	// Prompt for debug mode
	fmt.Print("Enable debug mode? (y/n): ")
	debugStr, err := reader.ReadString('\n')
	if err != nil {
		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  19, // Config module ID
			SectionID: 1,
			ItemID:    3,
			Text:      "Configuration Error",
			Type:      scan.CriticalRecommendation,
			Details:   fmt.Sprintf("Failed to read debug setting: %v", err),
		})
		return recommendations
	}
	debugStr = strings.TrimSpace(strings.ToLower(debugStr))
	debug := debugStr == "y" || debugStr == "yes"

	// Update configuration
	config.SetOrganization(orgName)
	config.SetLicenseKey(licenseKey)
	config.SetDebug(debug)

	// Add success recommendation
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  19, // Config module ID
		SectionID: 1,
		ItemID:    4,
		Text:      "Configuration Updated",
		Type:      scan.SuccessRecommendation,
		Details:   "Configuration has been updated successfully",
	})

	// Print confirmation
	fmt.Println("Configuration updated successfully.")
	fmt.Printf("Organization: %s\n", orgName)
	fmt.Printf("License Key: %s\n", licenseKey)
	fmt.Printf("Debug Mode: %v\n", debug)

	return recommendations
}

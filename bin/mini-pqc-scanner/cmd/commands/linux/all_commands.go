package linux

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
	"mini-pqc/scan"
)

// Version variable to store the application version
var Version string

// AllCommandsReport represents the JSON structure for comprehensive scan report
type AllCommandsReport struct {
	ServerIP        string                `json:"server_ip"`
	ReportTime      string                `json:"report_time"`
	ScannerVersion  string                `json:"scanner_version"`
	Recommendations []scan.Recommendation `json:"recommendations"`
}

// RunAllCommands executes all available scan commands and returns combined recommendations
func RunAllCommands(jsonOutput bool) []scan.Recommendation {
	var allRecommendations []scan.Recommendation

	// If JSON output is requested, suppress stdout during scan execution
	if jsonOutput {
		// Redirect stdout to discard output during scanning
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		
		// Capture output in a goroutine and discard it
		go func() {
			io.Copy(io.Discard, r)
		}()
		
		// Run all the core scanning modules (excluding Docker)
		allRecommendations = append(allRecommendations, Env(false)...)
		allRecommendations = append(allRecommendations, Firmware(false)...)
		allRecommendations = append(allRecommendations, TestKernel(false)...)
		allRecommendations = append(allRecommendations, TestLib(false)...)
		allRecommendations = append(allRecommendations, TestCA(false)...)
		allRecommendations = append(allRecommendations, TestRuntime(false)...)
		allRecommendations = append(allRecommendations, TestPGP(false)...)
		allRecommendations = append(allRecommendations, TestPostfix(false)...)
		allRecommendations = append(allRecommendations, TestNginx(false)...)
		allRecommendations = append(allRecommendations, TestApache(false)...)
		allRecommendations = append(allRecommendations, TestWireguard(false)...)
		allRecommendations = append(allRecommendations, TestOpenSSH(false)...)
		allRecommendations = append(allRecommendations, TestOpenVPN(false)...)
		allRecommendations = append(allRecommendations, TestIPsec(false)...)
		
		// Restore stdout
		w.Close()
		os.Stdout = oldStdout
		
		// Get server IP address (using the same function as env.go)
		serverIP := getServerIP()
		
		// Create consolidated report structure
		report := AllCommandsReport{
			ServerIP:        serverIP,
			ReportTime:      time.Now().Format(time.RFC3339),
			ScannerVersion:  Version,
			Recommendations: allRecommendations,
		}
		
		// Marshal to JSON and output to stdout
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating JSON report: %v\n", err)
		} else {
			fmt.Print(string(jsonData))
		}
	} else {
		// Run all the core scanning modules normally (with text output)
		allRecommendations = append(allRecommendations, Env(false)...)
		allRecommendations = append(allRecommendations, Firmware(false)...)
		allRecommendations = append(allRecommendations, TestKernel(false)...)
		allRecommendations = append(allRecommendations, TestLib(false)...)
		allRecommendations = append(allRecommendations, TestCA(false)...)
		allRecommendations = append(allRecommendations, TestRuntime(false)...)
		allRecommendations = append(allRecommendations, TestPGP(false)...)
		allRecommendations = append(allRecommendations, TestPostfix(false)...)
		allRecommendations = append(allRecommendations, TestNginx(false)...)
		allRecommendations = append(allRecommendations, TestApache(false)...)
		allRecommendations = append(allRecommendations, TestWireguard(false)...)
		allRecommendations = append(allRecommendations, TestOpenSSH(false)...)
		allRecommendations = append(allRecommendations, TestOpenVPN(false)...)
		allRecommendations = append(allRecommendations, TestIPsec(false)...)
	}

	return allRecommendations
}

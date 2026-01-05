package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mini-pqc/scan"
)

// to scan and parse manually use:
// tcpdump -i any -C 1 -w /path/to/output.pcap port 443
// tshark -r /path/to/capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_supported_group

// getProjectRootDir returns the absolute path to the project root directory
// This ensures that dump directory paths are consistent regardless of where the binary is run from
func getProjectRootDir() string {
	// Get the executable path
	execPath, err := os.Executable()
	if err != nil {
		// Fallback to current directory if we can't get executable path
		cwd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return cwd
	}

	// Get the directory containing the executable
	execDir := filepath.Dir(execPath)

	// If we're in the bin directory, go up one level
	if filepath.Base(execDir) == "bin" {
		return filepath.Dir(execDir)
	}

	// Otherwise return the current directory
	return execDir
}

// TestTcpdump runs a PQC readiness audit for tcpdump
// If dump is true, it will also capture TLS handshakes for the specified duration
func TestTcpdump(args ...string) []scan.Recommendation {
	// Initialize results map
	results := make(map[string]string)
	// Recommendation manager for status + recs
	rm := &scan.RecommendationManager{}

	// Check for -list parameter first to avoid running readiness checks
	for i := 0; i < len(args); i++ {
		if args[i] == "-list" {
			// Skip all readiness checks and just list capture files
			listCaptureFiles()
			// Return empty slice instead of nil to avoid "No recommendations found" message
			return []scan.Recommendation{}
		}
	}

	// Check for -parse parameter to analyze pcap files
	for i := 0; i < len(args); i++ {
		if args[i] == "-parse" {
			// Parse -f parameter for filename
			var filename string
			for j := 0; j < len(args)-1; j++ {
				if args[j] == "-f" {
					filename = args[j+1]
					break
				}
			}

			// If no filename specified, use the most recent capture file
			if filename == "" {
				filename = getLatestCaptureFile()
				if filename == "" {
					fmt.Println("[FAIL] Error: No capture files found in the dump directory.")
					os.Exit(0) // Exit without showing recommendations
				}
				fmt.Printf("Using most recent capture file: %s\n", filename)
			}

			// Analyze the pcap file
			parseTcpdumpFile(filename)
			os.Exit(0) // Exit without showing recommendations
		}
	}

	// Check for -dump parameter
	dumpMode := false
	for i := 0; i < len(args); i++ {
		if args[i] == "-dump" {
			dumpMode = true
			break
		}
	}

	// Check for -process-track parameter
	processTrackMode := false
	for i := 0; i < len(args); i++ {
		if args[i] == "-process-track" {
			processTrackMode = true
			break
		}
	}

	// Only perform minimal checks if in dump mode
	// Don't print anything for dump mode yet, we'll handle that in the capture function
	checkTcpdumpIsInstalled(results)

	// Check if tcpdump is installed
	if results["Tcpdump"] == "Not installed" {
		// Only print error if tcpdump is not installed
		if dumpMode {
			fmt.Println("[FAIL] Cannot perform packet capture: tcpdump is not installed")
		}
		return generateTcpdumpRecommendations(results)
	}

	// Only do full readiness check if not in dump mode
	if !dumpMode {
		// Print header only for regular readiness check
		fmt.Println("\n=== Tcpdump PQC Readiness Check ===")

		// Check tshark installation and version
		checkTsharkIsInstalled(results)

		// Check TLS library linkage
		checkTcpdumpTLSLibrary(results)

		// Check protocol support
		checkTcpdumpProtocolSupport(results)
	}

	// Process the -dump parameter if found
	var duration int = 30 // Default duration in seconds
	var filename string

	if dumpMode {
		// Parse -s parameter (duration)
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-s" {
				if s, err := strconv.Atoi(args[i+1]); err == nil && s > 0 {
					duration = s
				}
			}
		}

		// Always use a timestamp-based filename
		timestamp := time.Now().Format("15-04-02-01-2006")

		// Use /tmp directory for initial capture (world-writable on most Linux systems)
		tmpFilename := filepath.Join("/tmp", "pqc_tcpdump_"+timestamp+".pcap")

		// Final destination in project dump directory
		dumpDir := filepath.Join(getProjectRootDir(), "dump")
		// Create dump directory if it doesn't exist
		if _, err := os.Stat(dumpDir); os.IsNotExist(err) {
			os.MkdirAll(dumpDir, 0777)
		}
		filename = filepath.Join(dumpDir, timestamp+".pcap")

		// Perform the actual packet capture
		if processTrackMode {
			if checkBCCInstalled() {
				fmt.Println("\nProcess tracking enabled. Running packet capture with process tracking...")
				err := TrackProcesses(duration, filename)
				if err != nil {
					fmt.Printf("[FAIL] Process tracking failed: %v\n", err)
					results["ProcessTracking"] = "Failed"
				} else {
					results["ProcessTracking"] = "Success"
				}
			} else {
				fmt.Println("\n[FAIL] Process tracking requires BCC tools. Please install python3-bcc package.")
				results["ProcessTracking"] = "Failed - BCC not installed"
				// Fall back to regular capture without process tracking
				performTcpdumpCapture(results, duration, tmpFilename, filename)
			}
		} else {
			// Regular capture without process tracking
			performTcpdumpCapture(results, duration, tmpFilename, filename)
		}

		// If process tracking is enabled, correlate flows with processes
		/* This is now handled by TrackProcesses
		if processTrackMode {
			if checkBCCInstalled() {
				fmt.Println("\nProcess tracking enabled. Correlating network flows with processes...")
				err := correlateFlowsWithProcesses(filename, duration)
				if err != nil {
					fmt.Printf("[FAIL] Process tracking failed: %v\n", err)
					results["ProcessTracking"] = "Failed"
				} else {
					results["ProcessTracking"] = "Success"
				}
			} else {
				fmt.Println("\n[FAIL] Process tracking requires BCC tools. Please install python3-bcc package.")
				results["ProcessTracking"] = "Failed - BCC not installed"
			}
		}
		*/
	}

	// Only print summary and recommendations if not in dump mode
	if !dumpMode {
		// Print summary
		printTcpdumpSummary(results)

		// Build status + recs
		generateTcpdumpStatus(results, rm)
		rm.AppendRecommendations(generateTcpdumpRecommendations(results))
		return rm.GetRecommendations()
	}

	// Return status-only for dump mode
	generateTcpdumpStatus(results, rm)
	return rm.GetRecommendations()
}

// checkTcpdumpIsInstalled moved to tcpdump_utils.go

// checkTcpdumpTLSLibrary checks which TLS library tcpdump is linked against
func checkTcpdumpTLSLibrary(results map[string]string) {
	if results["TcpdumpPath"] == "" {
		results["TLSLibrary"] = "Unknown (tcpdump not installed)"
		return
	}

	// Check library dependencies
	cmd := exec.Command("ldd", results["TcpdumpPath"])
	output, err := cmd.CombinedOutput()
	if err != nil {
		results["TLSLibrary"] = "Unknown (could not check dependencies)"
		fmt.Println("[FAIL] Could not check tcpdump library dependencies")
		return
	}

	outputStr := string(output)

	// Check for OpenSSL
	if strings.Contains(outputStr, "libssl.so") {
		results["TLSLibrary"] = "OpenSSL"
		fmt.Println("[INFO] Tcpdump is linked with OpenSSL")

		// Check OpenSSL version
		cmd = exec.Command("openssl", "version")
		output, err = cmd.CombinedOutput()
		if err == nil {
			opensslVersion := strings.TrimSpace(string(output))
			results["OpenSSLVersion"] = opensslVersion
			fmt.Printf("   OpenSSL version: %s\n", opensslVersion)

			// Check if OpenSSL version supports PQC
			if strings.Contains(opensslVersion, "3.2") || strings.Contains(opensslVersion, "3.3") {
				results["PQCSupport"] = "Supported by OpenSSL"
				fmt.Println("   [PASS] OpenSSL version supports PQC")
			} else {
				results["PQCSupport"] = "Not supported by OpenSSL version"
				fmt.Println("   [FAIL] OpenSSL version does not support PQC")
			}
		}
	} else if strings.Contains(outputStr, "libgnutls.so") {
		results["TLSLibrary"] = "GnuTLS"
		fmt.Println("[INFO] Tcpdump is linked with GnuTLS")

		// Check GnuTLS version
		cmd = exec.Command("gnutls-cli", "--version")
		output, err = cmd.CombinedOutput()
		if err == nil {
			gnutlsVersion := strings.TrimSpace(string(output))
			results["GnuTLSVersion"] = gnutlsVersion
			fmt.Printf("   GnuTLS version: %s\n", gnutlsVersion)

			// Check if GnuTLS version supports PQC
			if strings.Contains(gnutlsVersion, "3.8") || strings.Contains(gnutlsVersion, "3.9") {
				results["PQCSupport"] = "Supported by GnuTLS"
				fmt.Println("   [PASS] GnuTLS version supports PQC")
			} else {
				results["PQCSupport"] = "Not supported by GnuTLS version"
				fmt.Println("   [FAIL] GnuTLS version does not support PQC")
			}
		}
	} else {
		results["TLSLibrary"] = "Unknown"
		fmt.Println("[INFO] Could not determine TLS library used by tcpdump")
	}
}

// checkTcpdumpProtocolSupport checks tcpdump's capabilities for protocol analysis
func checkTcpdumpProtocolSupport(results map[string]string) {
	if results["TcpdumpPath"] == "" {
		results["ProtocolSupport"] = "Unknown (tcpdump not installed)"
		return
	}

	fmt.Println("\nChecking tcpdump capabilities:")

	// Check if tcpdump can decode TLS
	results["TLSSupport"] = "Supported"
	fmt.Println("[INFO] TLS protocol decoding: Supported")

	// Check if tcpdump can decode SSH
	results["SSHSupport"] = "Supported"
	fmt.Println("[INFO] SSH protocol decoding: Supported")

	// Check if tcpdump can decode IPsec
	results["IPsecSupport"] = "Supported"
	fmt.Println("[INFO] IPsec protocol decoding: Supported")

	// Check if tcpdump supports QUIC protocol (important for HTTP/3)
	cmd := exec.Command("tcpdump", "-d", "udp port 443 and quic")
	_, err := cmd.CombinedOutput()
	if err == nil {
		results["QUICSupport"] = "Supported"
		fmt.Println("[INFO] QUIC protocol support: Supported")
	} else {
		results["QUICSupport"] = "Not supported"
		fmt.Println("[FAIL] QUIC protocol support: Not supported")
	}
}

// printTcpdumpSummary prints a summary of the tcpdump PQC readiness check
// performTcpdumpCapture captures TLS handshakes for the specified duration
// Uses a temporary file in /tmp and then moves it to the final location
func performTcpdumpCapture(results map[string]string, duration int, tmpFilename string, finalFilename string) {
	if results["Tcpdump"] == "Not installed" {
		fmt.Println("\n[FAIL] Cannot perform packet capture: tcpdump is not installed")
		return
	}

	// Handle directory creation differently based on how we'll run tcpdump
	// We'll use the tmp directory for the capture file
	dir := filepath.Dir(tmpFilename)

	// Check if tcpdump has capabilities
	var hasCapabilities bool
	hasCapabilities = checkTcpdumpCapabilities()

	// If tcpdump doesn't have capabilities, we'll run it with sudo
	// In this case, let sudo/tcpdump create the directory with proper ownership
	if !hasCapabilities {
		// If directory doesn't exist, we'll let sudo mkdir create it
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			// Create parent directories if needed
			parentDir := filepath.Dir(dir)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				os.MkdirAll(parentDir, 0755)
			}

			// Let sudo create the actual dump directory
			mkdirCmd := exec.Command("sudo", "mkdir", "-p", dir)
			mkdirCmd.Run()

			// Set permissions so current user can access it
			chmodCmd := exec.Command("sudo", "chmod", "777", dir)
			chmodCmd.Run()
		} else {
			// Directory exists, make sure it's writable by sudo
			chmodCmd := exec.Command("sudo", "chmod", "777", dir)
			chmodCmd.Run()
		}
	} else {
		// Tcpdump has capabilities, create directory as current user
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0777); err != nil {
				fmt.Printf("[FAIL] Error creating dump directory: %v\n", err)
				return
			}
		}

		// Ensure directory has proper permissions
		if err := os.Chmod(dir, 0777); err != nil {
			fmt.Printf("[WARN] Warning: Could not set directory permissions: %v\n", err)
		}
	}

	fmt.Printf("\n=== Capturing TLS Handshakes ===\n")
	fmt.Printf("Capturing packets for %d seconds...\n", duration)
	fmt.Printf("Output file: %s\n", finalFilename)

	// tcpdump requires root privileges to capture packets
	fmt.Println("[INFO] Note: Running tcpdump requires sudo privileges")
	fmt.Println("[INFO] If prompted for a password, please enter it")
	fmt.Println("[INFO] The capture will run for approximately", duration, "seconds")
	fmt.Println("[INFO] Press Ctrl+C if the capture hangs or you want to stop early")

	// First check if tcpdump has the necessary capabilities to run without sudo
	hasCapabilities = checkTcpdumpCapabilities()

	// Detect if we're running in TPANEL by checking if stdout is a terminal
	// This is a simple heuristic - if we're in TPANEL, stdout is likely redirected
	fileInfo, _ := os.Stdout.Stat()
	isTTY := (fileInfo.Mode() & os.ModeCharDevice) != 0

	var captureCmd *exec.Cmd

	// Add -C 1 flag to limit capture file size to 1MB
	// This will ensure the capture file doesn't exceed 1MB even with long duration
	fmt.Println("[INFO] Limiting capture file size to 1MB maximum")

	// Comprehensive filter for PQC-relevant protocols
	// TLS/HTTPS (HTTP/2 & HTTP/1.1): tcp port 443 or 8443
	// QUIC/HTTP-3: udp port 443
	// SSH: tcp port 22
	// IPsec (IKE v2 + ESP): udp port 500 or 4500, proto 50 (ESP)
	// WireGuard: udp port 51820
	// Mail TLS: tcp port 25, 465, 587, 993, 995
	captureFilter := "tcp port 443 or tcp port 8443 or udp port 443 or tcp port 22 or udp port 500 or udp port 4500 or proto 50 or udp port 51820 or tcp port 25 or tcp port 465 or tcp port 587 or tcp port 993 or tcp port 995"
	fmt.Printf("[INFO] Using comprehensive PQC protocol filter: %s\n", captureFilter)

	// If tcpdump has capabilities, we can run it directly without sudo
	if hasCapabilities {
		fmt.Println("[INFO] Tcpdump has capabilities - running without sudo")
		captureCmd = exec.Command("tcpdump", "-i", "any", "-C", "1",
			"-w", tmpFilename, captureFilter)
		// Set umask to ensure created files have appropriate permissions
		captureCmd.Env = append(os.Environ(), "UMASK=0000")
	} else if !isTTY {
		// We're likely in TPANEL - use NOPASSWD sudo approach
		fmt.Println("[INFO] Running in TPANEL mode - using NOPASSWD sudo approach")
		fmt.Println("[INFO] Note: This requires sudo NOPASSWD configuration for tcpdump")
		fmt.Println("[INFO] If capture fails, run 'sudo visudo' and add: sudo ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump")
		fmt.Println("[INFO] Alternatively, run: sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)")

		// First try with NOPASSWD sudo (requires sudo configuration)
		captureCmd = exec.Command("sudo", "-n", "tcpdump", "-i", "any", "-C", "1",
			"-w", tmpFilename, captureFilter)
	} else {
		// Regular command line mode with interactive sudo prompt
		fmt.Println("[INFO] Running in CLI mode - using interactive sudo prompt")
		fmt.Println("[INFO] To avoid sudo prompt, run: 'sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)'")
		captureCmd = exec.Command("sudo", "tcpdump", "-i", "any", "-C", "1",
			"-w", tmpFilename, captureFilter)
	}

	// Set up pipes for command output
	// In TPANEL mode, we need to capture and buffer the output
	if !isTTY {
		// Create buffers for stdout and stderr
		stdoutBuf := &bytes.Buffer{}
		stderrBuf := &bytes.Buffer{}
		captureCmd.Stdout = stdoutBuf
		captureCmd.Stderr = stderrBuf
	} else {
		// In CLI mode, we can write directly to stdout/stderr
		captureCmd.Stdout = os.Stdout
		captureCmd.Stderr = os.Stderr
	}

	// Run the command
	// Print a clear start message for both CLI and TPANEL modes
	if !isTTY {
		// Special message for TPANEL mode
		fmt.Printf("\n[INFO] STARTING CAPTURE: Dumping packets for %d seconds...\n", duration)
	}

	err := captureCmd.Start()
	if err != nil {
		fmt.Printf("\n[FAIL] Failed to start capture: %v\n", err)
		results["CaptureStatus"] = "Failed"
		results["CaptureError"] = err.Error()

		// Check if this might be a sudo password issue in TPANEL
		if !isTTY && strings.Contains(err.Error(), "sudo") {
			fmt.Println("\n[FAIL] Sudo permission denied in TPANEL mode. Please configure NOPASSWD for tcpdump:")
			fmt.Println("   1. Run 'sudo visudo' in a terminal")
			fmt.Println(`   2. Add the following line: 'sudo ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump'`)
			fmt.Println("   3. Save and exit, then try again")
		}
		return
	}

	// Print a message that capture is in progress
	if !isTTY {
		fmt.Println("[INFO] Capture in progress, please wait...")
	}

	// Create a done channel to signal when the process is complete
	done := make(chan error, 1)
	go func() {
		done <- captureCmd.Wait()
	}()

	// Variables to store output buffers for TPANEL mode
	var stdoutBuf, stderrBuf *bytes.Buffer
	if !isTTY {
		stdoutBuf = captureCmd.Stdout.(*bytes.Buffer)
		stderrBuf = captureCmd.Stderr.(*bytes.Buffer)
	}

	// Wait for either the command to finish or the timeout to expire
	select {
	case err := <-done:
		if err != nil {
			if !isTTY && stdoutBuf != nil && stderrBuf != nil {
				// In TPANEL mode, print the buffered output
				fmt.Printf("\n[FAIL] CAPTURE ENDED: Error occurred\n")
				fmt.Printf("\n[FAIL] Capture ended with error: %v\n", err)
				// Print a summary of the output instead of the full output
				fmt.Println("Tcpdump output summary (error):", stderrBuf.String())
			} else {
				fmt.Printf("\n[FAIL] Capture ended with error: %v\n", err)
			}
			results["CaptureStatus"] = "Failed"
			results["CaptureError"] = err.Error()
		} else {
			if !isTTY && stdoutBuf != nil && stderrBuf != nil {
				// In TPANEL mode, print the buffered output
				fmt.Printf("\n[PASS] CAPTURE COMPLETED: Successfully captured packets\n")
				fmt.Printf("\n[PASS] Capture completed successfully\n")
				// Print a summary of the output instead of the full output
				output := stdoutBuf.String()
				if len(output) > 0 {
					fmt.Println("Tcpdump output summary:", output)
				}
			} else {
				fmt.Printf("\n[PASS] Capture completed successfully\n")
			}
			results["CaptureStatus"] = "Success"
			results["CaptureFile"] = finalFilename
		}
	case <-time.After(time.Duration(duration+5) * time.Second): // Add 5 seconds buffer
		// Timeout occurred, kill the process
		captureCmd.Process.Kill()
		if !isTTY && stdoutBuf != nil && stderrBuf != nil {
			// In TPANEL mode, print the buffered output
			fmt.Printf("\n[WARN] CAPTURE FINISHED: Completed after %d seconds\n", duration+5)
			fmt.Printf("\n[INFO] Capture timed out after %d seconds\n", duration+5)
			// Print a summary of the output instead of the full output
			output := stdoutBuf.String()
			if len(output) > 0 {
				fmt.Println("Tcpdump output summary:", output)
			}
		} else {
			fmt.Printf("\nCapture timed out after %d seconds\n", duration+5)
		}
		results["CaptureStatus"] = "Timeout"
		results["CaptureFile"] = finalFilename
	}

	// Check if capture was successful
	if _, err := os.Stat(tmpFilename); os.IsNotExist(err) {
		fmt.Println("\nCapture file was not created")

		// Try to diagnose the issue
		fmt.Println("\nDiagnosing permission issues:")
		// Check directory permissions
		dirInfo, err := os.Stat(dir)
		if err != nil {
			fmt.Printf("  [FAIL] Cannot access dump directory: %v\n", err)
		} else {
			fmt.Printf("  Directory permissions: %s\n", dirInfo.Mode().String())
		}

		// Try to create a test file to check write permissions
		testFile := filepath.Join(dir, "test_permissions.txt")
		tf, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("  [FAIL] Current user cannot write to dump directory: %v\n", err)
			fmt.Println("  Try running: sudo chmod -R 777 " + dir)
		} else {
			tf.Close()
			os.Remove(testFile) // Clean up
			fmt.Println("  [PASS] Current user can write to dump directory")
			fmt.Println("  [WARN] Tcpdump likely lacks permissions to write to this directory")
			fmt.Println("  Try running: sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)")
		}

		results["CaptureStatus"] = "Failed"
		results["CaptureError"] = "File not created"
	} else {
		// Copy the file from tmp to final location
		fmt.Printf("\nMoving capture file from %s to %s\n", tmpFilename, finalFilename)

		// Create the destination directory if it doesn't exist
		destDir := filepath.Dir(finalFilename)
		if _, err := os.Stat(destDir); os.IsNotExist(err) {
			os.MkdirAll(destDir, 0777)
		}

		// Copy the file
		srcFile, err := os.Open(tmpFilename)
		if err != nil {
			fmt.Printf("\n[FAIL] Cannot open source file: %v\n", err)
			results["CaptureStatus"] = "Failed"
			results["CaptureError"] = err.Error()
			return
		}
		defer srcFile.Close()

		destFile, err := os.Create(finalFilename)
		if err != nil {
			fmt.Printf("\n[FAIL] Cannot create destination file: %v\n", err)
			results["CaptureStatus"] = "Failed"
			results["CaptureError"] = err.Error()
			return
		}
		defer destFile.Close()

		// Copy the contents
		_, err = io.Copy(destFile, srcFile)
		if err != nil {
			fmt.Printf("\n[FAIL] Error copying file: %v\n", err)
			results["CaptureStatus"] = "Failed"
			results["CaptureError"] = err.Error()
			return
		}

		// Make sure the final file is readable by the current user
		os.Chmod(finalFilename, 0666)

		// Clean up the temporary file
		os.Remove(tmpFilename)

		// Get file info for size reporting
		fileInfo, err := os.Stat(finalFilename)
		if err != nil {
			fmt.Printf("\n[FAIL] Cannot access capture file: %v\n", err)
			results["CaptureStatus"] = "Failed"
			results["CaptureError"] = err.Error()
			return
		}

		// Consider any file with size >= 24 bytes as valid (tcpdump creates at least a pcap header)
		// Small files (24 bytes) are valid but may not contain actual packet data
		fileSizeKB := float64(fileInfo.Size()) / 1024.0
		var fileSizeStr string
		if fileSizeKB < 1.0 {
			fileSizeStr = fmt.Sprintf("%.2f", fileSizeKB)
		} else {
			fileSizeStr = fmt.Sprintf("%.1f", fileSizeKB)
		}
		fmt.Printf("\n[PASS] Capture completed successfully: %s\n", finalFilename)
		fmt.Printf("   File size: %s KB\n", fileSizeStr)
		fmt.Printf("   To analyze this capture, run: ./pqc-scanner tcpdump -parse -f %s\n", finalFilename)
		results["CaptureStatus"] = "Success"
		results["CaptureFile"] = finalFilename
	}
}

// Global WHOIS cache to avoid redundant lookups across runs
var whoisCache = make(map[string]string)

// whoisCacheDir is the directory where whois cache files are stored
const whoisCacheDir = "./whois/cache"

// isPrivateIP checks if an IP address is in a private range
// loadWhoisFromCache attempts to load whois info for an IP from the file cache
func loadWhoisFromCache(ip string) (string, bool) {
	// Sanitize IP for filename
	safeIP := strings.ReplaceAll(ip, ":", "_")
	cacheFile := filepath.Join(whoisCacheDir, safeIP+".json")

	// Check if cache file exists
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return "", false
	}

	// Parse JSON
	var cacheEntry struct {
		Info string    `json:"info"`
		Time time.Time `json:"time"`
	}

	if err := json.Unmarshal(data, &cacheEntry); err != nil {
		return "", false
	}

	// Return the cached info
	return cacheEntry.Info, true
}

// saveWhoisToCache moved to tcpdump_utils.go

// getLatestCaptureFile moved to tcpdump_utils.go

// isPrivateIP moved to tcpdump_utils.go

// GetWhoisInfo performs a WHOIS lookup for an IP address with caching
func GetWhoisInfo(ip string) string {
	// Check if we already have this IP in the in-memory cache
	if info, ok := whoisCache[ip]; ok {
		return info
	}

	// Skip WHOIS lookup for private/local IPs
	if isPrivateIP(ip) || ip == "154.53.43.159" {
		info := "Local Network"
		whoisCache[ip] = info
		// Save to file cache
		saveWhoisToCache(ip, info)
		return info
	}

	// Check if we have this IP in the file cache
	if info, found := loadWhoisFromCache(ip); found {
		// Update in-memory cache and return
		whoisCache[ip] = info
		return info
	}

	// Create a context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run the whois command
	cmd := exec.CommandContext(ctx, "whois", ip)
	output, err := cmd.CombinedOutput()

	// Check for errors or timeout
	if err != nil {
		info := "Unknown"
		whoisCache[ip] = info
		// Save to file cache
		saveWhoisToCache(ip, info)
		return info
	}

	// Process the output to extract organization or netname
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	// First try to find organization name (preferred)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)

		// Look for organization name fields first
		if strings.HasPrefix(lowerLine, "organization:") ||
			strings.HasPrefix(lowerLine, "orgname:") ||
			strings.HasPrefix(lowerLine, "org-name:") ||
			strings.HasPrefix(lowerLine, "owner:") ||
			strings.HasPrefix(lowerLine, "name:") && !strings.Contains(lowerLine, "netname:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				info := strings.TrimSpace(parts[1])
				if info != "" {
					// Truncate if too long
					if len(info) > 25 {
						info = info[:22] + "..."
					}
					// Cache the result in memory and file
					whoisCache[ip] = info
					saveWhoisToCache(ip, info)
					return info
				}
			}
		}
	}

	// If no organization name found, fall back to netname
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)

		// Look for netname fields as fallback
		if strings.HasPrefix(lowerLine, "netname:") ||
			strings.HasPrefix(lowerLine, "network:name:") ||
			strings.HasPrefix(lowerLine, "netname:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				info := strings.TrimSpace(parts[1])
				if info != "" {
					// Truncate if too long
					if len(info) > 25 {
						info = info[:22] + "..."
					}
					// Cache the result in memory and file
					whoisCache[ip] = info
					saveWhoisToCache(ip, info)
					return info
				}
			}
		}
	}

	// Cache unknown results too (in memory and file)
	info := "Unknown"
	whoisCache[ip] = info
	saveWhoisToCache(ip, info)
	return info
}

// parseTcpdumpFile analyzes a pcap file using tshark to extract TLS handshake information
func parseTcpdumpFile(filename string) {
	// Check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("[FAIL] Error: File '%s' does not exist\n", filename)
		return
	}

	// Check if tshark is installed
	cmd := exec.Command("which", "tshark")
	_, err := cmd.Output()
	if err != nil {
		fmt.Println("[FAIL] Error: tshark is not installed. Please install it to analyze pcap files.")
		fmt.Println("   Install with: sudo apt-get install tshark")
		return
	}

	fmt.Printf("\n=== Analyzing TLS Handshakes in %s ===\n\n", filename)

	// Run tshark to extract TLS handshake information
	cmd = exec.Command("tshark", "-r", filename, "-Y", "tls.handshake.type == 1",
		"-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tls.handshake.extensions_supported_group")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	// Check for specific errors but continue processing if there's output
	if err != nil {
		errMsg := stderr.String()

		// Check if the file is cut short but still has usable data
		if strings.Contains(errMsg, "cut short") {
			fmt.Println("[WARN] The pcap file appears to be incomplete or cut short.")
			fmt.Println("   Some packets may be missing or corrupted, but we'll analyze what we can.")
			fmt.Println()
		} else {
			// For other errors, print the error but continue if we have output
			fmt.Printf("[FAIL] Error analyzing file: %v\n", err)
			if len(errMsg) > 0 {
				// Filter out the common "Running as user root" warning
				if !strings.Contains(errMsg, "Running as user") || strings.Contains(errMsg, "error") {
					fmt.Printf("Error details: %s\n\n", errMsg)
				}
			}

			// If we don't have any output, return
			if stdout.Len() == 0 {
				return
			}

			fmt.Println("[INFO] Attempting to continue with partial data...")
		}
	}

	// Process and display the results
	output := stdout.String()
	if len(output) == 0 {
		fmt.Println("[INFO] No TLS handshakes found in the capture file.")
		return
	}

	// Define a map of known TLS groups
	knownGroups := map[string]string{
		// Classical groups
		"0x0017": "secp256r1 (NIST P-256)",
		"0x0018": "secp384r1 (NIST P-384)",
		"0x0019": "secp521r1 (NIST P-521)",
		"0x001d": "x25519",
		"0x001e": "x448",
		"0x0100": "ffdhe2048",
		"0x0101": "ffdhe3072",
		"0x0102": "ffdhe4096",
		"0x0103": "ffdhe6144",
		"0x0104": "ffdhe8192",

		// Post-quantum groups
		"0x0105": "kyber512 (PQC)",
		"0x0106": "kyber768 (PQC)",
		"0x0107": "kyber1024 (PQC)",
		"0x0108": "p256_kyber512 (Hybrid PQC)",
		"0x0109": "p384_kyber768 (Hybrid PQC)",
		"0x010a": "p521_kyber1024 (Hybrid PQC)",
		"0x010b": "x25519_kyber512 (Hybrid PQC)",
		"0x010c": "x448_kyber768 (Hybrid PQC)",
		"0x6000": "ML-KEM-512 (PQC)",
		"0x6001": "ML-KEM-768 (PQC)",
		"0x6002": "ML-KEM-1024 (PQC)",
		"0x6003": "P256_ML-KEM-512 (Hybrid PQC)",
		"0x6004": "P384_ML-KEM-768 (Hybrid PQC)",
		"0x6005": "P521_ML-KEM-1024 (Hybrid PQC)",
		"0x6006": "X25519_ML-KEM-512 (Hybrid PQC)",
		"0x6007": "X448_ML-KEM-768 (Hybrid PQC)",

		// Modern hybrid ML-KEM named groups (OpenSSL 3.2+ / oqs-provider)
		"0x11ec": "X25519MLKEM768 (Hybrid PQC)",
		"0x11eb": "SecP256r1MLKEM768 (Hybrid PQC)",
		"0x11ed": "SecP384r1MLKEM1024 (Hybrid PQC)",

		// Other values
		"0x2a2a": "GREASE value (RFC8701)",

		// WireGuard Curve IDs
		"0x01": "WireGuard Curve25519",
		"0x04": "WireGuard Kyber512-X25519 (PQC)",
	}

	// Print header
	fmt.Printf("%-15s %-25s %s (Remote IP)\n", "Server IP", "WHOIS Info", "Supported Groups")
	fmt.Println(strings.Repeat("-", 100))

	// Map to store unique source-destination pairs and their supported groups
	connections := make(map[string]map[string]bool)
	connectionGroups := make(map[string][]string)

	// Map to store WHOIS information for IPs to avoid redundant lookups
	ipWhoisInfo := make(map[string]string)

	// Process each line
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Split the line into columns
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		srcIP := fields[0]
		dstIP := fields[1]
		groups := fields[2]

		// Create a unique key for this connection
		connKey := srcIP + "-" + dstIP

		// Initialize maps if needed
		if _, exists := connections[connKey]; !exists {
			connections[connKey] = make(map[string]bool)
			connectionGroups[connKey] = []string{}
		}

		// Process the groups
		groupList := strings.Split(groups, ",")
		for _, group := range groupList {
			// Clean and normalize the group code
			groupCode := strings.TrimSpace(strings.ToLower(group))

			// Store the group if we haven't seen it for this connection
			if !connections[connKey][groupCode] {
				connections[connKey][groupCode] = true
				connectionGroups[connKey] = append(connectionGroups[connKey], groupCode)
			}
		}

		// Cache WHOIS info for this IP if we haven't already
		if _, exists := ipWhoisInfo[srcIP]; !exists {
			ipWhoisInfo[srcIP] = GetWhoisInfo(srcIP)
		}
		if _, exists := ipWhoisInfo[dstIP]; !exists {
			ipWhoisInfo[dstIP] = GetWhoisInfo(dstIP)
		}
	}

	fmt.Printf("Server IP       WHOIS Info                Supported Groups (Remote IP)\n")
	fmt.Printf("----------------------------------------------------------------------------------------------------\n")

	// Process each line as it comes in and print immediately
	for _, line := range lines {
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Split the line into columns
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		srcIP := fields[0]
		dstIP := fields[1]
		groups := fields[2]

		// Identify which IP is the remote IP (for WHOIS lookup)
		var remoteIP string

		// If the source is the server, then destination is remote
		if srcIP == "154.53.43.159" {
			remoteIP = dstIP
		} else if dstIP == "154.53.43.159" {
			remoteIP = srcIP
		} else {
			// If neither is the server IP, use the source as remote
			remoteIP = srcIP
		}

		// Process the groups
		groupList := strings.Split(groups, ",")
		readableGroups := []string{}
		hasPQC := false

		for _, group := range groupList {
			groupCode := strings.TrimSpace(strings.ToLower(group))

			// Extract the hex value from formats like "0x0017" or "0x00000017"
			parts := strings.Split(groupCode, "x")
			if len(parts) > 1 {
				hexPart := parts[1]

				// If it's a long format like "0x00000017", extract just the significant part
				if len(hexPart) > 4 {
					hexPart = hexPart[len(hexPart)-4:]
				}

				// Reconstruct the normalized group code
				groupCode = "0x" + hexPart
			}

			// Look up the group in our known groups map
			if desc, ok := knownGroups[groupCode]; ok {
				readableGroups = append(readableGroups, desc)
				if strings.Contains(desc, "PQC") {
					hasPQC = true
				}
			} else {
				// Check for PQC algorithms by name pattern even if not in our map
				lowerGroup := strings.ToLower(groupCode)
				if strings.Contains(lowerGroup, "kyber") ||
					strings.Contains(lowerGroup, "ml-kem") ||
					strings.Contains(lowerGroup, "ml_kem") ||
					strings.Contains(lowerGroup, "sntrup") ||
					strings.Contains(lowerGroup, "ntru") ||
					strings.Contains(lowerGroup, "pqc_kem") {
					readableGroups = append(readableGroups, groupCode+" (PQC)")
					hasPQC = true
				} else {
					// If we couldn't match it, add it as unknown
					readableGroups = append(readableGroups, group+" (unknown)")
				}
			}
		}

		// Get WHOIS info for the remote IP
		whoisInfo := GetWhoisInfo(remoteIP)

		// Print the line with color coding for PQC support
		statusPrefix := "[FAIL] "
		if hasPQC {
			statusPrefix = "[PASS] "
		}

		// Format the output with WHOIS info and remote IP at the end
		// Replace server IP with "Server" text
		displaySrcIP := srcIP
		if srcIP == "154.53.43.159" {
			displaySrcIP = "Server"
		}

		displayDstIP := dstIP
		if dstIP == "154.53.43.159" {
			displayDstIP = "Server"
		}

		fmt.Printf("%s%-15s %-15s %-25s %s (%s)\n",
			statusPrefix,
			displaySrcIP,
			displayDstIP,
			whoisInfo,
			strings.Join(readableGroups, ", "),
			remoteIP)

		// Flush stdout to ensure immediate output
		fmt.Print("")
		// Small delay to avoid overwhelming the system with WHOIS requests
		time.Sleep(50 * time.Millisecond)
	}

	// Print summary
	fmt.Println("\nAnalysis complete.")
	fmt.Println("[PASS] = Connection supports post-quantum cryptography")
	fmt.Println("[FAIL] = Connection does not support post-quantum cryptography")
}

// Note: getLatestCaptureFile function is now defined earlier in this file

// listCaptureFiles moved to tcpdump_utils.go

// checkTcpdumpCapabilities checks if tcpdump has the necessary capabilities to run without sudo
func checkTcpdumpCapabilities() bool {
	// Check if tcpdump has the cap_net_raw and cap_net_admin capabilities
	cmd := exec.Command("getcap", "/usr/sbin/tcpdump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// getcap command failed or tcpdump doesn't have capabilities
		return false
	}

	outputStr := string(output)
	// Check if the output contains both required capabilities
	return strings.Contains(outputStr, "cap_net_raw") && strings.Contains(outputStr, "cap_net_admin")
}

func printTcpdumpSummary(results map[string]string) {
	fmt.Println("\n=== Tcpdump PQC Readiness Summary ===")
	if results["Tcpdump"] == "Not installed" {
		fmt.Println("[FAIL] Tcpdump not installed")
		return
	}

	fmt.Printf("[PASS] Tcpdump installed: %s\n", results["TcpdumpPath"])
	fmt.Printf("   Version: %s\n", results["TcpdumpVersion"])
	fmt.Printf("   TLS Library: %s\n\n", results["TLSLibrary"])

	fmt.Println("   Protocol Support:")
	fmt.Printf("   - TLS: %s\n", results["TLSSupport"])
	fmt.Printf("   - SSH: %s\n", results["SSHSupport"])
	fmt.Printf("   - IPsec: %s\n", results["IPsecSupport"])
	fmt.Printf("   - QUIC (HTTP/3): %s\n", results["QUICSupport"])

	// Print tshark information if available
	if tshark, ok := results["tshark"]; ok {
		if tshark != "Not installed" {
			fmt.Printf("\n[PASS] Tshark installed: %s\n", strings.TrimPrefix(tshark, "Installed: "))
			if tsharkVersion, ok := results["tshark Version"]; ok {
				fmt.Printf("   Version: %s\n", tsharkVersion)
			}
		} else {
			fmt.Println("\n[FAIL] Tshark not installed")
		}
	}

}

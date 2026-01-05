package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// checkTcpdumpIsInstalled checks if tcpdump is installed and gets its version
func checkTcpdumpIsInstalled(results map[string]string) {
	// Check if tcpdump is installed
	cmd := exec.Command("which", "tcpdump")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Tcpdump not found")
		results["Tcpdump"] = "Not installed"
		return
	}

	// Store tcpdump path
	tcpdumpPath := strings.TrimSpace(string(output))
	fmt.Println("Tcpdump found at:", tcpdumpPath)
	results["TcpdumpPath"] = tcpdumpPath

	// Get tcpdump version
	cmd = exec.Command("tcpdump", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		results["TcpdumpVersion"] = "Unknown"
		fmt.Println("Could not determine tcpdump version")
	} else {
		// Extract just the version number from the output
		versionOutput := strings.TrimSpace(string(output))
		// Extract just the first line which contains the version
		lines := strings.Split(versionOutput, "\n")
		if len(lines) > 0 {
			versionOutput = lines[0]
		}
		// Store full version info in results but display concise version
		results["TcpdumpVersion"] = versionOutput
		fmt.Println("Tcpdump version:", versionOutput)
	}
}

// checkTsharkIsInstalled checks if tshark is installed
func checkTsharkIsInstalled(results map[string]string) {
	// Check if tshark is installed
	cmd := exec.Command("which", "tshark")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[FAIL] Tshark not found")
		results["Tshark"] = "Not installed"
		return
	}

	// Store tshark path
	tsharkPath := strings.TrimSpace(string(output))
	fmt.Println("Tshark found at:", tsharkPath)
	results["TsharkPath"] = tsharkPath

	// Get tshark version
	cmd = exec.Command("tshark", "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		results["TsharkVersion"] = "Unknown"
		fmt.Println("[FAIL] Could not determine tshark version")
	} else {
		// Extract just the version number from the output
		versionOutput := strings.TrimSpace(string(output))
		// Extract just the first line which contains the version
		lines := strings.Split(versionOutput, "\n")
		if len(lines) > 0 {
			versionOutput = lines[0]
		}
		// Store full version info in results but display concise version
		results["TsharkVersion"] = versionOutput
		fmt.Println("[PASS] Tshark version:", versionOutput)
	}
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.") ||
		ip == "127.0.0.1" ||
		ip == "localhost"
}

// getWhoisInfoFromCache retrieves cached whois info for an IP
func getWhoisInfoFromCache(ip string) (string, bool) {
	// Sanitize IP for filename
	safeIP := strings.ReplaceAll(ip, ":", "_")
	cacheFile := filepath.Join(whoisCacheDir, safeIP+".json")

	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return "", false
	}

	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return "", false
	}

	// Parse JSON
	cacheEntry := struct {
		Info string    `json:"info"`
		Time time.Time `json:"time"`
	}{}

	if err := json.Unmarshal(data, &cacheEntry); err != nil {
		return "", false
	}

	// Return the cached info
	return cacheEntry.Info, true
}

// saveWhoisToCache saves whois info for an IP to the file cache
func saveWhoisToCache(ip, info string) {
	// Ensure cache directory exists
	os.MkdirAll(whoisCacheDir, 0755)

	// Sanitize IP for filename
	safeIP := strings.ReplaceAll(ip, ":", "_")
	cacheFile := filepath.Join(whoisCacheDir, safeIP+".json")

	// Create cache entry
	cacheEntry := struct {
		Info string    `json:"info"`
		Time time.Time `json:"time"`
	}{
		Info: info,
		Time: time.Now(),
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(cacheEntry, "", "  ")
	if err != nil {
		return // Silently fail, we can still use in-memory cache
	}

	// Write to file
	os.WriteFile(cacheFile, data, 0644)
}

// getLatestCaptureFile returns the path to the most recent capture file in the dump directory
func getLatestCaptureFile() string {
	// Get the dump directory path
	dumpDir := filepath.Join(getProjectRootDir(), "dump")

	// Check if the directory exists
	if _, err := os.Stat(dumpDir); os.IsNotExist(err) {
		return ""
	}

	// Read all files in the dump directory
	files, err := os.ReadDir(dumpDir)
	if err != nil {
		return ""
	}

	// Filter for .pcap files and find the most recent one
	var latestFile string
	var latestTime time.Time

	for _, file := range files {
		// Skip directories and non-pcap files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".pcap") {
			continue
		}

		// Get file info to check modification time
		filePath := filepath.Join(dumpDir, file.Name())
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		// If this is the first file or newer than our current latest
		if latestFile == "" || fileInfo.ModTime().After(latestTime) {
			latestFile = filePath
			latestTime = fileInfo.ModTime()
		}
	}

	return latestFile
}

// listCaptureFiles lists the last 10 capture files in the dump directory
func listCaptureFiles() {
	// Get the dump directory path
	dumpDir := filepath.Join(getProjectRootDir(), "dump")

	// Check if the directory exists
	if _, err := os.Stat(dumpDir); os.IsNotExist(err) {
		fmt.Println("\nNo capture files found - dump directory does not exist.")
		return
	}

	// Get all pcap files in the dump directory
	files, err := filepath.Glob(filepath.Join(dumpDir, "*.pcap"))
	if err != nil {
		fmt.Printf("Error reading dump directory: %v\n", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("\nNo capture files found in the dump directory.")
		return
	}

	// Sort files by modification time (newest first)
	type fileInfo struct {
		path    string
		modTime time.Time
		size    int64
	}

	fileInfos := make([]fileInfo, 0, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, fileInfo{
			path:    file,
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}

	// Sort by modification time (newest first)
	for i := 0; i < len(fileInfos)-1; i++ {
		for j := i + 1; j < len(fileInfos); j++ {
			if fileInfos[i].modTime.Before(fileInfos[j].modTime) {
				fileInfos[i], fileInfos[j] = fileInfos[j], fileInfos[i]
			}
		}
	}

	// Display the files
	fmt.Println("\nAvailable capture files:")
	fmt.Println("------------------------")
	for i, fi := range fileInfos {
		if i >= 10 {
			break // Only show the 10 most recent files
		}
		// Format the size in KB
		sizeKB := float64(fi.size) / 1024.0
		fmt.Printf("%d. %s (%.1f KB, %s)\n", i+1, filepath.Base(fi.path), sizeKB, fi.modTime.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()
}

// formatFileSize formats a file size in bytes to a human-readable string
func formatFileSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/1024/1024)
	} else {
		return fmt.Sprintf("%.1f GB", float64(size)/1024/1024/1024)
	}
}

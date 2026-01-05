package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"mini-pqc/scan"
	"regexp"
	"sort"
	"strings"
	"time"
)

// AppInfo represents information about an installed application
type AppInfo struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	PackageManager string            `json:"package_manager"`
	Architecture   string            `json:"architecture,omitempty"`
	Description    string            `json:"description,omitempty"`
	Dependencies   []string          `json:"dependencies,omitempty"`
	ConfigFiles    []string          `json:"config_files,omitempty"`
	InstallSize    string            `json:"install_size,omitempty"`
	Status         string            `json:"status,omitempty"`
	Priority       string            `json:"priority,omitempty"`
	Section        string            `json:"section,omitempty"`
	Maintainer     string            `json:"maintainer,omitempty"`
	Homepage       string            `json:"homepage,omitempty"`
	Essential      bool              `json:"essential,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	// PQC-specific fields
	LogicalName    string            `json:"logical_name,omitempty"`
	Category       string            `json:"category,omitempty"`
	PQCReady       string            `json:"pqc_ready,omitempty"`
	PQCComment     string            `json:"pqc_comment,omitempty"`
}

// PQCAppMapping represents the mapping of RPM packages to logical applications with PQC readiness info
type PQCAppMapping struct {
	Name      string   `json:"name"`
	RPM       []string `json:"rpm"`
	Category  string   `json:"category"`
	PQCReady  string   `json:"pqc_ready"`
	Comment   string   `json:"comment,omitempty"`
}

// AppsReport represents the complete application inventory report
type AppsReport struct {
	ServerIP        string                `json:"server_ip"`
	ReportTime      string                `json:"report_time"`
	Hostname        string                `json:"hostname"`
	Distribution    string                `json:"distribution"`
	Architecture    string                `json:"architecture"`
	KernelVersion   string                `json:"kernel_version"`
	PackageManagers []string              `json:"package_managers"`
	TotalApps       int                   `json:"total_apps"`
	Applications    []AppInfo             `json:"applications"`
	SystemFiles     []string              `json:"system_files,omitempty"`
	Recommendations []scan.Recommendation `json:"recommendations"`
}

// PQCMappingFile represents the structure of the external PQC mapping JSON file
type PQCMappingFile struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	LastUpdated string `json:"last_updated"`
	Mappings    []struct {
		Name     string   `json:"name"`
		RPM      []string `json:"rpm"`
		Deb      []string `json:"deb"`
		Category string   `json:"category"`
		PQCReady string   `json:"pqc_ready"`
		Comment  string   `json:"comment"`
		External bool     `json:"external,omitempty"`
	} `json:"mappings"`
}

// getPQCAppMappings loads the comprehensive mapping of packages to logical applications with PQC readiness info from external JSON file
func getPQCAppMappings() []PQCAppMapping {
	// Try multiple possible locations for the mapping file
	mappingPaths := []string{
		"./cmd/pqc_app_mappings.json",
		"../cmd/pqc_app_mappings.json",
		"./pqc_app_mappings.json", // If running from cmd directory
		"/var/local/pqc-scanner/cmd/pqc_app_mappings.json",
		"/etc/pqc-scanner/pqc_app_mappings.json",
	}

	var mappingFile PQCMappingFile
	var fileFound bool

	for _, path := range mappingPaths {
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &mappingFile); err == nil {
				fileFound = true
				break
			}
		}
	}

	if !fileFound {
		// Fallback to minimal hardcoded mappings if file not found
		return []PQCAppMapping{
			{Name: "OpenSSL", RPM: []string{"openssl-libs", "openssl", "openssl-devel"}, Category: "Crypto Implementer", PQCReady: "partial", Comment: "PQC is experimental in 3.x branch"},
			{Name: "OpenSSH", RPM: []string{"openssh", "openssh-clients", "openssh-server"}, Category: "Crypto Consumer", PQCReady: "partial", Comment: "Kyber NIST draft support via OQS patches"},
			{Name: "Docker CE / Containerd", RPM: []string{"docker-ce", "containerd.io", "docker-ce-cli"}, Category: "Crypto Infrastructure", PQCReady: "no"},
		}
	}

	// Convert the loaded data to our internal format
	var result []PQCAppMapping
	for _, mapping := range mappingFile.Mappings {
		result = append(result, PQCAppMapping{
			Name:     mapping.Name,
			RPM:      mapping.RPM,
			Category: mapping.Category,
			PQCReady: mapping.PQCReady,
			Comment:  mapping.Comment,
		})
	}

	return result
}

// Apps command collects comprehensive application inventory for Docker environment replication
func Apps(jsonOutput bool) []scan.Recommendation {
	var recommendations []scan.Recommendation

	// Create the report structure
	report := AppsReport{
		ServerIP:        getServerIP(),
		ReportTime:      time.Now().UTC().Format(time.RFC3339),
		Hostname:        getHostname(),
		Distribution:    getDistribution(),
		Architecture:    getArchitecture(),
		KernelVersion:   getKernelVersionApps(),
		PackageManagers: []string{},
		Applications:    []AppInfo{},
		SystemFiles:     []string{},
		Recommendations: []scan.Recommendation{},
	}

	// Collect applications using progressive fallback approach
	collectApplications(&report)

	// Collect critical system files
	collectSystemFiles(&report)

	// AWS Load Balancer Crypto Inspection (if running in AWS environment)
	awsResults := make(map[string]string)
	if awsData := inspectAWSLoadBalancerForApps(); len(awsData) > 0 {
		for key, value := range awsData {
			awsResults[key] = value
		}
	}

	// Generate recommendations
	generateAppsRecommendations(&report, &recommendations, awsResults)

	// Output results
	if jsonOutput {
		outputJSON, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(outputJSON))
	} else {
		printAppsSummary(&report)
	}

	return recommendations
}

// enrichAppWithPQCInfo enriches an AppInfo with PQC mapping information
func enrichAppWithPQCInfo(app *AppInfo, pqcMappings []PQCAppMapping) {
	for _, mapping := range pqcMappings {
		for _, rpmName := range mapping.RPM {
			// Check if the app name matches any RPM package in the mapping
			if strings.Contains(strings.ToLower(app.Name), strings.ToLower(rpmName)) {
				app.LogicalName = mapping.Name
				app.Category = mapping.Category
				app.PQCReady = mapping.PQCReady
				app.PQCComment = mapping.Comment
				return // Found a match, stop searching
			}
		}
	}
}

// collectApplications uses progressive fallback to enumerate installed applications
func collectApplications(report *AppsReport) {
	// Get PQC mappings for enrichment
	pqcMappings := getPQCAppMappings()
	
	// Try different package managers in order of preference
	var allApps []AppInfo

	// Try dpkg first (Debian/Ubuntu)
	if apps := collectDpkgApps(); len(apps) > 0 {
		allApps = append(allApps, apps...)
		report.PackageManagers = append(report.PackageManagers, "dpkg")
	}

	// Try RPM (RHEL/CentOS/Fedora)
	if apps := collectRpmApps(); len(apps) > 0 {
		allApps = append(allApps, apps...)
		report.PackageManagers = append(report.PackageManagers, "rpm")
	}

	// Try Alpine apk
	if apps := collectApkApps(); len(apps) > 0 {
		allApps = append(allApps, apps...)
		report.PackageManagers = append(report.PackageManagers, "apk")
	}

	// Try Snap packages
	if apps := collectSnapApps(); len(apps) > 0 {
		allApps = append(allApps, apps...)
		report.PackageManagers = append(report.PackageManagers, "snap")
	}

	// Try Flatpak packages
	if apps := collectFlatpakApps(); len(apps) > 0 {
		allApps = append(allApps, apps...)
		report.PackageManagers = append(report.PackageManagers, "flatpak")
	}

	// Fallback to filesystem enumeration for minimal systems
	if len(allApps) == 0 {
		allApps = collectExecutableApps()
		report.PackageManagers = append(report.PackageManagers, "filesystem")
	}

	// Enrich all apps with PQC information
	for i := range allApps {
		enrichAppWithPQCInfo(&allApps[i], pqcMappings)
	}

	// Sort applications by name
	sort.Slice(allApps, func(i, j int) bool {
		return allApps[i].Name < allApps[j].Name
	})

	report.Applications = allApps
	report.TotalApps = len(allApps)
}

// collectDpkgApps collects applications from dpkg database
func collectDpkgApps() []AppInfo {
	var apps []AppInfo

	// Check if dpkg database exists
	if _, err := os.Stat("/var/lib/dpkg/status"); err != nil {
		return apps
	}

	// Try dpkg-query first (more reliable)
	if cmd := exec.Command("dpkg-query", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\t${Status}\t${Priority}\t${Section}\t${Maintainer}\t${Homepage}\t${Description}\t${Essential}\t${Installed-Size}\n"); cmd.Err == nil {
		if output, err := cmd.Output(); err == nil {
			apps = parseDpkgQueryOutput(string(output))
			if len(apps) > 0 {
				return apps
			}
		}
	}

	// Fallback to parsing dpkg status file directly with awk
	cmd := exec.Command("awk", `
		BEGIN { RS=""; FS="\n" }
		/^Status:.*installed/ {
			pkg=""; ver=""; arch=""; desc=""; prio=""; sect=""; maint=""; home=""; essential=""; size=""
			for(i=1; i<=NF; i++) {
				if($i ~ /^Package:/) pkg=substr($i,10)
				if($i ~ /^Version:/) ver=substr($i,10)
				if($i ~ /^Architecture:/) arch=substr($i,14)
				if($i ~ /^Description:/) desc=substr($i,13)
				if($i ~ /^Priority:/) prio=substr($i,11)
				if($i ~ /^Section:/) sect=substr($i,10)
				if($i ~ /^Maintainer:/) maint=substr($i,13)
				if($i ~ /^Homepage:/) home=substr($i,11)
				if($i ~ /^Essential:/) essential=substr($i,12)
				if($i ~ /^Installed-Size:/) size=substr($i,17)
			}
			if(pkg) print pkg "\t" ver "\t" arch "\t" desc "\t" prio "\t" sect "\t" maint "\t" home "\t" essential "\t" size
		}
	`, "/var/lib/dpkg/status")

	if output, err := cmd.Output(); err == nil {
		apps = parseDpkgAwkOutput(string(output))
	}

	return apps
}

// collectRpmApps collects applications from RPM database
func collectRpmApps() []AppInfo {
	var apps []AppInfo

	cmd := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\t%{SIZE}\t%{VENDOR}\t%{URL}\n")
	if output, err := cmd.Output(); err == nil {
		apps = parseRpmOutput(string(output))
	}

	return apps
}

// collectApkApps collects applications from Alpine apk
func collectApkApps() []AppInfo {
	var apps []AppInfo

	cmd := exec.Command("apk", "info", "-vv")
	if output, err := cmd.Output(); err == nil {
		apps = parseApkOutput(string(output))
	}

	return apps
}

// collectSnapApps collects Snap packages
func collectSnapApps() []AppInfo {
	var apps []AppInfo

	cmd := exec.Command("snap", "list")
	if output, err := cmd.Output(); err == nil {
		apps = parseSnapOutput(string(output))
	}

	return apps
}

// collectFlatpakApps collects Flatpak packages
func collectFlatpakApps() []AppInfo {
	var apps []AppInfo

	cmd := exec.Command("flatpak", "list", "--app", "--columns=name,version,arch,size,installation")
	if output, err := cmd.Output(); err == nil {
		apps = parseFlatpakOutput(string(output))
	}

	return apps
}

// collectExecutableApps fallback for minimal systems - enumerate executables
func collectExecutableApps() []AppInfo {
	var apps []AppInfo

	// Standard executable paths
	paths := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

	for _, path := range paths {
		if files, err := filepath.Glob(filepath.Join(path, "*")); err == nil {
			for _, file := range files {
				if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
					name := filepath.Base(file)
					app := AppInfo{
						Name:           name,
						Version:        "unknown",
						PackageManager: "filesystem",
						Status:         "executable",
						Metadata: map[string]string{
							"path": file,
							"size": fmt.Sprintf("%d", info.Size()),
							"mode": info.Mode().String(),
						},
					}
					apps = append(apps, app)
				}
			}
		}
	}

	return apps
}

// collectSystemFiles collects critical system configuration files
func collectSystemFiles(report *AppsReport) {
	criticalFiles := []string{
		"/etc/os-release",
		"/etc/lsb-release",
		"/etc/debian_version",
		"/etc/redhat-release",
		"/etc/alpine-release",
		"/etc/passwd",
		"/etc/group",
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/fstab",
		"/etc/crontab",
		"/etc/systemd/system",
		"/etc/init.d",
		"/etc/rc.local",
		"/etc/environment",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/ssh/sshd_config",
		"/etc/ssl/certs",
		"/etc/ca-certificates",
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			report.SystemFiles = append(report.SystemFiles, file)
		}
	}
}

// Parser functions for different package manager outputs
func parseDpkgQueryOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 4 {
			// Only include installed packages
			if !strings.Contains(fields[3], "installed") {
				continue
			}

			app := AppInfo{
				Name:           fields[0],
				Version:        fields[1],
				PackageManager: "dpkg",
				Status:         "installed",
			}

			if len(fields) > 2 {
				app.Architecture = fields[2]
			}
			if len(fields) > 4 {
				app.Priority = fields[4]
			}
			if len(fields) > 5 {
				app.Section = fields[5]
			}
			if len(fields) > 6 {
				app.Maintainer = fields[6]
			}
			if len(fields) > 7 {
				app.Homepage = fields[7]
			}
			if len(fields) > 8 {
				app.Description = fields[8]
			}
			if len(fields) > 9 {
				app.Essential = fields[9] == "yes"
			}
			if len(fields) > 10 {
				app.InstallSize = fields[10] + " KB"
			}

			apps = append(apps, app)
		}
	}

	return apps
}

func parseDpkgAwkOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 2 {
			app := AppInfo{
				Name:           strings.TrimSpace(fields[0]),
				Version:        strings.TrimSpace(fields[1]),
				PackageManager: "dpkg",
				Status:         "installed",
			}

			if len(fields) > 2 {
				app.Architecture = strings.TrimSpace(fields[2])
			}
			if len(fields) > 3 {
				app.Description = strings.TrimSpace(fields[3])
			}
			if len(fields) > 4 {
				app.Priority = strings.TrimSpace(fields[4])
			}
			if len(fields) > 5 {
				app.Section = strings.TrimSpace(fields[5])
			}
			if len(fields) > 6 {
				app.Maintainer = strings.TrimSpace(fields[6])
			}
			if len(fields) > 7 {
				app.Homepage = strings.TrimSpace(fields[7])
			}
			if len(fields) > 8 {
				app.Essential = strings.TrimSpace(fields[8]) == "yes"
			}
			if len(fields) > 9 && strings.TrimSpace(fields[9]) != "" {
				app.InstallSize = strings.TrimSpace(fields[9]) + " KB"
			}

			apps = append(apps, app)
		}
	}

	return apps
}

func parseRpmOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 2 {
			app := AppInfo{
				Name:           fields[0],
				Version:        fields[1],
				PackageManager: "rpm",
				Status:         "installed",
			}

			if len(fields) > 2 {
				app.Architecture = fields[2]
			}
			if len(fields) > 3 {
				app.Description = fields[3]
			}
			if len(fields) > 4 {
				app.InstallSize = fields[4] + " bytes"
			}
			if len(fields) > 5 {
				app.Maintainer = fields[5]
			}
			if len(fields) > 6 {
				app.Homepage = fields[6]
			}

			apps = append(apps, app)
		}
	}

	return apps
}

func parseApkOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Parse apk info output format: package-version-release description
		re := regexp.MustCompile(`^([a-zA-Z0-9\-\+\.]+)-([0-9][a-zA-Z0-9\-\+\.]*)-r?([0-9]+)\s*(.*)$`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 4 {
			app := AppInfo{
				Name:           matches[1],
				Version:        matches[2] + "-r" + matches[3],
				PackageManager: "apk",
				Status:         "installed",
			}

			if len(matches) > 4 {
				app.Description = matches[4]
			}

			apps = append(apps, app)
		}
	}

	return apps
}

func parseSnapOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Skip header line
	if len(lines) > 1 {
		lines = lines[1:]
	}

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			app := AppInfo{
				Name:           fields[0],
				Version:        fields[1],
				PackageManager: "snap",
				Status:         "installed",
			}

			if len(fields) > 2 {
				app.Architecture = fields[2]
			}
			if len(fields) > 3 {
				app.Description = strings.Join(fields[3:], " ")
			}

			apps = append(apps, app)
		}
	}

	return apps
}

func parseFlatpakOutput(output string) []AppInfo {
	var apps []AppInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 2 {
			app := AppInfo{
				Name:           fields[0],
				Version:        fields[1],
				PackageManager: "flatpak",
				Status:         "installed",
			}

			if len(fields) > 2 {
				app.Architecture = fields[2]
			}
			if len(fields) > 3 {
				app.InstallSize = fields[3]
			}
			if len(fields) > 4 {
				app.Metadata = map[string]string{
					"installation": fields[4],
				}
			}

			apps = append(apps, app)
		}
	}

	return apps
}

// Helper functions for system information
func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func getDistribution() string {
	// Try /etc/os-release first
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}

	// Fallback to other methods
	if content, err := os.ReadFile("/etc/lsb-release"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
				return strings.Trim(strings.TrimPrefix(line, "DISTRIB_DESCRIPTION="), `"`)
			}
		}
	}

	return "unknown"
}

func getArchitecture() string {
	if cmd := exec.Command("uname", "-m"); cmd.Err == nil {
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "unknown"
}

func getKernelVersionApps() string {
	if cmd := exec.Command("uname", "-r"); cmd.Err == nil {
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "unknown"
}

// getSystemOpenSSLVersion detects the system OpenSSL version
func getSystemOpenSSLVersion() string {
	// Try to get OpenSSL version from command line
	if cmd := exec.Command("openssl", "version"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			versionStr := strings.TrimSpace(string(output))
			// Extract version number from output like "OpenSSL 3.2.2 4 Jun 2024"
			parts := strings.Fields(versionStr)
			if len(parts) >= 2 {
				return parts[1] // Return version like "3.2.2"
			}
		}
	}
	return ""
}

// isOpenSSLVersionSufficient checks if the system OpenSSL version meets PQC requirements
func isOpenSSLVersionSufficient(systemVersion string) bool {
	if systemVersion == "" {
		return false
	}
	// Check if version is 3.0.0 or higher
	return compareVersions(systemVersion, "3.0.0") >= 0
}

// generateAppsRecommendations generates recommendations based on the application inventory
func generateAppsRecommendations(report *AppsReport, recommendations *[]scan.Recommendation, awsResults map[string]string) {
	// Detect system OpenSSL version for smarter recommendations
	systemOpenSSLVersion := getSystemOpenSSLVersion()
	openSSLSufficient := isOpenSSLVersionSufficient(systemOpenSSLVersion)
	// Recommend Docker creation
	*recommendations = append(*recommendations, scan.Recommendation{
		ModuleID:  20, // New module ID for apps command
		SectionID: 1,
		ItemID:    1,
		Text:      fmt.Sprintf("Found %d applications across %d package managers. Create a Docker image to replicate this environment for safe PQC upgrade testing.", report.TotalApps, len(report.PackageManagers)),
		Type:      scan.InfoRecommendation,
		Details:   fmt.Sprintf("Package managers detected: %s", strings.Join(report.PackageManagers, ", ")),
		Kind:      scan.KindRecommendation,
		Severity:  2, // Low-medium severity
	})

	// Collect PQC-relevant applications (those with PQC mapping information)
	type PQCApp struct {
		Name          string
		Version       string
		LogicalName   string
		Category      string
		PQCReady      string
		PQCComment    string
		NeedsAction   bool
		ActionText    string
		TargetVersion string
	}
	foundPQCApps := []PQCApp{}

	// Collect apps with PQC information and determine if they need specific actions
	for _, app := range report.Applications {
		if app.LogicalName != "" { // Only include apps with PQC mapping
			suggestedChange := generateSuggestedChange(app.Name, app.Version, systemOpenSSLVersion, openSSLSufficient)
			needsAction := !strings.HasPrefix(suggestedChange, "[PASS]")
			targetVersion := extractTargetVersion(app.Name, suggestedChange)

			foundPQCApps = append(foundPQCApps, PQCApp{
				Name:          app.Name,
				Version:       app.Version,
				LogicalName:   app.LogicalName,
				Category:      app.Category,
				PQCReady:      app.PQCReady,
				PQCComment:    app.PQCComment,
				NeedsAction:   needsAction,
				ActionText:    suggestedChange,
				TargetVersion: targetVersion,
			})
		}
	}

	// Section 2: Status items - show app name, version, category, and PQC readiness for all PQC-relevant apps
	if len(foundPQCApps) > 0 {
		for i, pqcApp := range foundPQCApps {
			pqcStatus := ""
			switch pqcApp.PQCReady {
			case "yes":
				pqcStatus = "PQC Ready"
			case "partial":
				pqcStatus = "Partial PQC"
			case "no":
				pqcStatus = "No PQC"
			default:
				pqcStatus = "Unknown"
			}
			
			detailsText := fmt.Sprintf("Category: %s | PQC Status: %s", pqcApp.Category, pqcStatus)
			if pqcApp.PQCComment != "" {
				detailsText += fmt.Sprintf(" | %s", pqcApp.PQCComment)
			}
			
			// Determine severity based on category - HIGH only for crypto-related apps
			severity := 1 // Default: Low severity for status
			if pqcApp.NeedsAction {
				// Use category-based severity assignment
				switch pqcApp.Category {
				case "Crypto Implementer":
					// Core crypto libraries - VERY HIGH severity
					severity = 5 // VERY HIGH: OpenSSL, GnuTLS, libgcrypt, etc.
				case "Crypto Consumer":
					// Network-facing crypto endpoints - HIGH severity  
					severity = 4 // HIGH: Nginx, Apache, SSH, Docker, etc.
				case "Crypto Infrastructure":
					// Certificate infrastructure - HIGH severity
					severity = 4 // HIGH: CA certificates, P11-kit, etc.
				default:
					// Non-crypto apps - LOW severity
					severity = 1 // LOW: Other applications
				}
			}

			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 2,
				ItemID:    i + 1,
				Text:      fmt.Sprintf("%s (%s): Version %s", pqcApp.LogicalName, pqcApp.Name, pqcApp.Version),
				Type:      scan.InfoRecommendation,
				Details:   detailsText,
				Kind:      scan.KindStatus,
				Severity:  severity,
			})
		}
	}

	// Section 3: Recommendations - show upgrade needs with target versions only for apps that need action
	actionableApps := []PQCApp{}
	for _, app := range foundPQCApps {
		if app.NeedsAction {
			actionableApps = append(actionableApps, app)
		}
	}

	if len(actionableApps) > 0 {
		upgradeItemID := 1
		// Create individual recommendations for apps that need upgrades
		for _, pqcApp := range actionableApps {
			// Determine severity based on category - HIGH only for crypto-related apps
			severity := 1 // Default: Low severity for non-crypto apps
			
			// Use category-based severity assignment for recommendations
			switch pqcApp.Category {
			case "Crypto Implementer":
				// Core crypto libraries - VERY HIGH severity for upgrades
				severity = 5 // VERY HIGH: OpenSSL, GnuTLS, libgcrypt, etc.
			case "Crypto Consumer":
				// Network-facing crypto endpoints - HIGH severity for upgrades
				severity = 4 // HIGH: Nginx, Apache, SSH, Docker, etc.
			case "Crypto Infrastructure":
				// Certificate infrastructure - HIGH severity for upgrades
				severity = 4 // HIGH: CA certificates, P11-kit, etc.
			default:
				// Non-crypto apps - LOW severity for upgrades
				severity = 1 // LOW: Other applications
			}

			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 3,
				ItemID:    upgradeItemID,
				Text:      fmt.Sprintf("Upgrade %s (%s) to %s for PQC readiness", pqcApp.LogicalName, pqcApp.Name, pqcApp.TargetVersion),
				Type:      scan.WarningRecommendation,
				Details:   fmt.Sprintf("Current version: %s. Category: %s. %s", pqcApp.Version, pqcApp.Category, pqcApp.ActionText),
				Kind:      scan.KindRecommendation,
				Severity:  severity,
			})
			upgradeItemID++
		}
	}

	// Check for minimal systems
	if len(report.PackageManagers) == 1 && report.PackageManagers[0] == "filesystem" {
		*recommendations = append(*recommendations, scan.Recommendation{
			ModuleID:  20,
			SectionID: 1,
			ItemID:    3,
			Text:      "This appears to be a minimal or hardened system with no package manager. Docker replication will require manual file-based approach.",
			Type:      scan.InfoRecommendation,
			Details:   "Consider creating a custom Docker image based on the detected executables and system files.",
			Kind:      scan.KindRecommendation,
			Severity:  2, // Low-medium severity
		})
	}

	// Section 10: AWS Load Balancer Status (if running in AWS environment)
	if awsEnv, ok := awsResults["AWS Environment"]; ok {
		awsItemID := 1
		*recommendations = append(*recommendations, scan.Recommendation{
			ModuleID:  20,
			SectionID: 10,
			ItemID:    awsItemID,
			Text:      fmt.Sprintf("AWS Environment: %s", awsEnv),
			Type:      scan.InfoRecommendation,
			Details:   "Application inventory running in AWS environment with potential load balancer crypto termination",
			Kind:      scan.KindStatus,
			Severity:  1,
		})
		awsItemID++

		if instanceID, ok := awsResults["AWS Instance ID"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("EC2 Instance ID: %s", instanceID),
				Type:      scan.InfoRecommendation,
				Details:   "EC2 instance identifier for load balancer association analysis",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if lbType, ok := awsResults["Load Balancer Type"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("Load Balancer Type: %s", lbType),
				Type:      scan.InfoRecommendation,
				Details:   "Type of AWS load balancer handling application traffic",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if lbName, ok := awsResults["Load Balancer Name"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("Load Balancer Name: %s", lbName),
				Type:      scan.InfoRecommendation,
				Details:   "AWS load balancer name for application traffic management",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if appPorts, ok := awsResults["Application Ports"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("Application Ports: %s", appPorts),
				Type:      scan.InfoRecommendation,
				Details:   "Load balancer ports serving application traffic",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if sslPolicy, ok := awsResults["SSL Policy"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("SSL Policy: %s", sslPolicy),
				Type:      scan.InfoRecommendation,
				Details:   "Load balancer SSL/TLS policy for application crypto termination",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if protocols, ok := awsResults["TLS Protocols"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("TLS Protocols: %s", protocols),
				Type:      scan.InfoRecommendation,
				Details:   "Supported TLS protocol versions for application connections",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if cipherCount, ok := awsResults["Cipher Suite Count"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("Cipher Suite Count: %s", cipherCount),
				Type:      scan.InfoRecommendation,
				Details:   "Number of cipher suites available for application encryption",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if pqcScore, ok := awsResults["PQC Readiness Score"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("PQC Readiness Score: %s", pqcScore),
				Type:      scan.InfoRecommendation,
				Details:   "Load balancer PQC readiness assessment for application traffic",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if pqcAssessment, ok := awsResults["PQC Assessment"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("PQC Assessment: %s", pqcAssessment),
				Type:      scan.InfoRecommendation,
				Details:   "Overall assessment of load balancer PQC readiness for applications",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
			awsItemID++
		}

		if cliStatus, ok := awsResults["AWS CLI Status"]; ok {
			*recommendations = append(*recommendations, scan.Recommendation{
				ModuleID:  20,
				SectionID: 10,
				ItemID:    awsItemID,
				Text:      fmt.Sprintf("AWS CLI Status: %s", cliStatus),
				Type:      scan.InfoRecommendation,
				Details:   "AWS CLI availability for load balancer crypto inspection",
				Kind:      scan.KindStatus,
				Severity:  1,
			})
		}

		// Section 11: AWS Load Balancer Recommendations (if running in AWS environment)
		if awsEnv, ok := awsResults["AWS Environment"]; ok && awsEnv == "EC2" {
			awsRecItemID := 1

			// Application deployment and AWS load balancer coordination
			if _, ok := awsResults["Load Balancer Name"]; ok {
				*recommendations = append(*recommendations, scan.Recommendation{
					ModuleID:  20,
					SectionID: 11,
					ItemID:    awsRecItemID,
					Text:      "Coordinate application upgrades with AWS load balancer configurations",
					Type:      scan.InfoRecommendation,
					Details:   "Your applications run behind an AWS load balancer. Consider these deployment coordination strategies:\n\n" +
						"- Applications handle business logic while AWS load balancer manages internet-facing TLS termination\n" +
						"- For comprehensive PQC readiness: upgrade load balancer SSL policies AND update application crypto libraries\n" +
						"- Application-level crypto (databases, internal APIs) should use PQC-ready libraries independently\n" +
						"- Consider blue-green deployments using multiple target groups for safe application upgrades\n" +
						"- Monitor both AWS load balancer metrics and application-level crypto performance\n" +
						"- Use AWS Application Load Balancer health checks during crypto library upgrades\n\n" +
						"This coordinated approach ensures seamless application upgrades with minimal downtime.",
					Kind:      scan.KindRecommendation,
					Severity:  2, // Low-medium severity - informational
				})
				awsRecItemID++
			}

			// AWS-specific application deployment considerations
			if pqcReadiness, ok := awsResults["PQC Readiness"]; ok {
				if strings.Contains(strings.ToLower(pqcReadiness), "needs upgrade") || strings.Contains(strings.ToLower(pqcReadiness), "poor") {
					*recommendations = append(*recommendations, scan.Recommendation{
						ModuleID:  20,
						SectionID: 11,
						ItemID:    awsRecItemID,
						Text:      "Upgrade AWS load balancer SSL policy alongside application crypto libraries",
						Type:      scan.WarningRecommendation,
						Details:   fmt.Sprintf("Current PQC readiness: %s. While upgrading your applications' crypto libraries improves internal security, your AWS load balancer also needs attention for comprehensive PQC readiness. Upgrade the load balancer's SSL policy to support TLS 1.3 and modern cipher suites to complement application-level cryptographic improvements.", pqcReadiness),
						Kind:      scan.KindRecommendation,
						Severity:  3, // Medium severity
					})
					awsRecItemID++
				}
			}

			// AWS infrastructure recommendations for application deployment
			if lbType, ok := awsResults["Load Balancer Type"]; ok {
				*recommendations = append(*recommendations, scan.Recommendation{
					ModuleID:  20,
					SectionID: 11,
					ItemID:    awsRecItemID,
					Text:      "Optimize AWS infrastructure for application deployment and PQC readiness",
					Type:      scan.InfoRecommendation,
					Details:   fmt.Sprintf("Load balancer type: %s. For application deployment in AWS:\n\n" +
						"- Use AWS Systems Manager for secure application configuration management\n" +
						"- Enable AWS CloudTrail for auditing application deployment changes\n" +
						"- Use AWS Secrets Manager for application crypto keys and certificates\n" +
						"- Consider AWS Certificate Manager for automated certificate lifecycle management\n" +
						"- Implement AWS Auto Scaling for resilient application deployments during upgrades\n" +
						"- Use AWS Parameter Store for application crypto configuration settings\n" +
						"- Monitor AWS security bulletins for application runtime and infrastructure updates\n\n" +
						"This AWS-integrated approach provides enterprise-grade application security with cloud-native deployment and management.", lbType),
					Kind:      scan.KindRecommendation,
					Severity:  1, // Low severity - informational
				})
				awsRecItemID++
			}
		}
	}
}

func printAppsSummary(report *AppsReport) {
    fmt.Printf("Application Inventory Report\n")
    fmt.Printf("=====================================\n\n")

    fmt.Printf("System Information:\n")
    fmt.Printf("   Hostname: %s\n", report.Hostname)
    fmt.Printf("   Distribution: %s\n", report.Distribution)
    fmt.Printf("   Architecture: %s\n", report.Architecture)
    fmt.Printf("   Kernel: %s\n", report.KernelVersion)
    fmt.Printf("   Report Time: %s\n\n", report.ReportTime)

    fmt.Printf("Package Managers Detected: %s\n", strings.Join(report.PackageManagers, ", "))
    fmt.Printf("Total Applications: %d\n\n", report.TotalApps)

    // Display critical applications status
    criticalApps := []string{"nginx", "apache2", "httpd", "mysql", "postgresql", "redis", "docker", "openssh", "openssl"}
    foundCritical := []struct {
        Name    string
        Version string
        Status  string
    }{}

    for _, app := range report.Applications {
        for _, critical := range criticalApps {
            if strings.Contains(strings.ToLower(app.Name), critical) {
                suggestedChange := generateSuggestedChange(app.Name, app.Version)
                status := "NEEDS UPDATE"
                if strings.HasPrefix(suggestedChange, "[PASS]") {
                    status = "PQC-COMPATIBLE"
                }

                foundCritical = append(foundCritical, struct {
                    Name    string
                    Version string
                    Status  string
                }{
                    Name:    app.Name,
                    Version: app.Version,
                    Status:  status,
                })
                break
            }
        }
    }

    if len(foundCritical) > 0 {
        fmt.Printf("Critical Applications Status (%d found):\n", len(foundCritical))
        fmt.Printf("%-30s %-20s %s\n", "Name", "Version", "PQC Status")
        fmt.Printf("%-30s %-20s %s\n", "----", "-------", "----------")
        for _, app := range foundCritical {
            statusIndicator := "[WARN]"
            if app.Status == "PQC-COMPATIBLE" {
                statusIndicator = "[PASS]"
            }
            fmt.Printf("%-30s %-20s %s %s\n",
                truncateString(app.Name, 29),
                truncateString(app.Version, 19),
                statusIndicator,
                app.Status)
        }
        fmt.Printf("\n")
    }

    if len(report.Applications) > 0 {
        fmt.Printf("Application Summary (showing first 20):\n")
        fmt.Printf("%-30s %-20s %-10s %s\n", "Name", "Version", "Manager", "Architecture")
        fmt.Printf("%-30s %-20s %-10s %s\n", "----", "-------", "-------", "------------")

        count := 0
        for _, app := range report.Applications {
            if count >= 20 {
                fmt.Printf("... and %d more applications\n", len(report.Applications)-20)
                break
            }
            fmt.Printf("%-30s %-20s %-10s %s\n",
                truncateString(app.Name, 29),
                truncateString(app.Version, 19),
                app.PackageManager,
                app.Architecture)
            count++
        }
    }

    if len(report.SystemFiles) > 0 {
        fmt.Printf("\nCritical System Files Found: %d\n", len(report.SystemFiles))
    }

    if len(report.Recommendations) > 0 {
        fmt.Printf("\nRecommendations:\n")
        for _, rec := range report.Recommendations {
            fmt.Printf("   - %s\n", rec.Text)
            if rec.Details != "" {
                fmt.Printf("     Details: %s\n", rec.Details)
            }
        }
    }

    fmt.Printf("\nDocker Integration:\n")
    fmt.Printf("   Use this inventory to create a Docker image that replicates\n")
    fmt.Printf("   this environment for safe PQC upgrade testing.\n")
}

func compareVersions(v1, v2 string) int {
	v1 = cleanVersion(v1)
	v2 = cleanVersion(v2)

	// Split versions into parts
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// Compare each part
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int

		if i < len(parts1) {
			// Extract numeric part from version component
			numStr := ""
			for _, r := range parts1[i] {
				if r >= '0' && r <= '9' {
					numStr += string(r)
				} else {
					break
				}
			}
			if numStr != "" {
				fmt.Sscanf(numStr, "%d", &p1)
			}
		}

		if i < len(parts2) {
			// Extract numeric part from version component
			numStr := ""
			for _, r := range parts2[i] {
				if r >= '0' && r <= '9' {
					numStr += string(r)
				} else {
					break
				}
			}
			if numStr != "" {
				fmt.Sscanf(numStr, "%d", &p2)
			}
		}

		if p1 < p2 {
			return -1
		} else if p1 > p2 {
			return 1
		}
	}

	return 0
}

// cleanVersion removes common prefixes and suffixes from version strings
func cleanVersion(version string) string {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "OpenSSL ")
	version = strings.TrimPrefix(version, "nginx/")
	version = strings.TrimPrefix(version, "Apache/")
	version = strings.TrimPrefix(version, "OpenSSH_")

	// Remove everything after space or hyphen (build info, etc.)
	if idx := strings.Index(version, " "); idx != -1 {
		version = version[:idx]
	}
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	if idx := strings.Index(version, "p"); idx != -1 && strings.Contains(version, "ssh") {
		// For OpenSSH versions like "8.7p1", keep the p1 part
		version = strings.Replace(version, "p", ".", 1)
	}

	return version
}

// extractTargetVersion extracts the target version from the suggested change text
func extractTargetVersion(appName, suggestedChange string) string {
	appLower := strings.ToLower(appName)

	// Extract target versions based on app type
	switch {
	case strings.Contains(appLower, "nginx"):
		return "1.25+"
	case strings.Contains(appLower, "httpd") || strings.Contains(appLower, "apache"):
		return "2.4.58+"
	case strings.Contains(appLower, "openssh"):
		return "9.0+"
	case strings.Contains(appLower, "openssl"):
		return "3.0+"
	case strings.Contains(appLower, "mysql"):
		return "8.0.34+"
	case strings.Contains(appLower, "postgresql"):
		return "15.0+"
	case strings.Contains(appLower, "redis"):
		return "7.0+"
	case strings.Contains(appLower, "docker"):
		return "24.0+"
	case strings.Contains(appLower, "php"):
		return "8.2+"
	default:
		return "latest PQC-compatible version"
	}
}



// generateSuggestedChange provides specific suggestions for critical applications
// Optional context parameters: systemOpenSSLVersion and openSSLSufficient for OpenSSL-dependent packages
func generateSuggestedChange(appName, currentVersion string, contextArgs ...interface{}) string {
	appLower := strings.ToLower(appName)
	
	// Extract optional context parameters
	var systemOpenSSLVersion string
	var openSSLSufficient bool
	if len(contextArgs) >= 2 {
		if sslVer, ok := contextArgs[0].(string); ok {
			systemOpenSSLVersion = sslVer
		}
		if sslSuff, ok := contextArgs[1].(bool); ok {
			openSSLSufficient = sslSuff
		}
	}

	switch {
	case strings.Contains(appLower, "nginx"):
		if compareVersions(currentVersion, "1.25.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure OpenSSL 3.0+ is used and configure ssl_protocols to include TLSv1.3."
		}
		return "Update to nginx 1.25+ with OpenSSL 3.0+ for PQC support. Configure ssl_protocols to include TLSv1.3. Test with PQC cipher suites."
	case strings.Contains(appLower, "httpd") || strings.Contains(appLower, "apache"):
		if compareVersions(currentVersion, "2.4.58") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure OpenSSL 3.0+ is used and configure SSLProtocol to include TLSv1.3."
		}
		return "Update to Apache 2.4.58+ with OpenSSL 3.0+ for PQC support. Configure SSLProtocol to include TLSv1.3. Test with PQC cipher suites."
	case strings.Contains(appLower, "openssh"):
		if compareVersions(currentVersion, "9.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Configure PQC-compatible key exchange algorithms and host key types."
		}
		return "Update to OpenSSH 9.0+ for PQC key exchange support. Configure PQC-compatible key exchange algorithms and host key types."
	case strings.Contains(appLower, "openssl"):
		if compareVersions(currentVersion, "3.0.0") >= 0 {
			return "[PASS] Version supports PQC algorithms. Consider installing OQS provider for additional PQC algorithm support."
		}
		return "Update to OpenSSL 3.0+ for native PQC algorithm support. Rebuild dependent applications against new OpenSSL version."
	case strings.Contains(appLower, "mysql"):
		if compareVersions(currentVersion, "8.0.34") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure OpenSSL 3.5+ is used for native ML-KEM-1024/ML-DSA-87 and configure ssl_cipher for PQC-compatible cipher suites."
		}
		return "Update to MySQL 8.0.34+ with OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 TLS connections. Configure ssl_cipher for PQC-compatible cipher suites."
	case strings.Contains(appLower, "postgresql"):
		if compareVersions(currentVersion, "15.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure OpenSSL 3.5+ is used for native ML-KEM-1024/ML-DSA-87 and configure ssl_ciphers for PQC-compatible cipher suites."
		}
		return "Update to PostgreSQL 15+ with OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 TLS connections. Configure ssl_ciphers for PQC-compatible cipher suites."
	case strings.Contains(appLower, "redis"):
		if compareVersions(currentVersion, "7.0.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure OpenSSL 3.5+ is used for native ML-KEM-1024/ML-DSA-87 and configure tls-ciphers and tls-ciphersuites for PQC support."
		}
		return "Update to Redis 7.0+ with OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 TLS connections. Configure tls-ciphers and tls-ciphersuites for PQC support."
	case strings.Contains(appLower, "docker"):
		if compareVersions(currentVersion, "24.0.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure containerd 1.7+ is used for PQC-compatible container registry TLS connections."
		}
		return "Update to Docker 24.0+ with containerd 1.7+ for PQC-compatible container registry TLS connections."
	case strings.Contains(appLower, "php"):
		if compareVersions(currentVersion, "8.2.0") >= 0 {
			return "[PASS] Version is PQC-compatible. Ensure compiled with OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 support in HTTPS and database connections."
		}
		return "Update to PHP 8.2+ compiled with OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 support in HTTPS and database connections."
	// Handle OpenSSL-dependent packages with smarter logic
	case strings.Contains(appLower, "openssl") && appLower != "openssl": // e.g., apr-util-openssl, openssl-devel, openssl-libs
		if len(contextArgs) >= 2 && openSSLSufficient {
			return fmt.Sprintf("[PASS] System OpenSSL %s is PQC-compatible. This package should work with the existing OpenSSL installation.", systemOpenSSLVersion)
		}
		return "Update to OpenSSL 3.5+ for native ML-KEM-1024/ML-DSA-87 support. Rebuild dependent applications against new OpenSSL version."
	default:
		return "This application handles cryptographic operations. Update to latest version with PQC-compatible cryptographic libraries (OpenSSL 3.5+, etc.)."
	}
}

// truncateString truncates a string to the specified length
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

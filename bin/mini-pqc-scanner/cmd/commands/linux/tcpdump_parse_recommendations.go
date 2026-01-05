package linux

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"bytes"
	"strings"
	"mini-pqc/scan"
	"net"
	"path/filepath"
	"time"
)

// GenerateTcpdumpParseRecommendations generates recommendations from parsed tcpdump data
// Returns both standard recommendations and a special TCPScanRecommendation with detailed connection data
func GenerateTcpdumpParseRecommendations(filename string) []scan.Recommendation {
	// Check if the file exists
	if filename == "" {
		filename := "dump/latest_capture.pcap"
		if filename == "" {
			return []scan.Recommendation{{
				ModuleID:  17, // Tcpdump module ID
				SectionID: 1,
				ItemID:    1,
				Text:      "No capture files found",
				Type:      scan.CriticalRecommendation,
				Details:   "No capture files were found in the dump directory. Please run a tcpdump capture first.",
			}}
		}
	}

	// Check if tshark is installed
	cmd := exec.Command("which", "tshark")
	_, err := cmd.Output()
	if err != nil {
		return []scan.Recommendation{{
			ModuleID:  17, // Tcpdump module ID
			SectionID: 1,
			ItemID:    1,
			Text:      "tshark is not installed",
			Type:      scan.CriticalRecommendation,
			Details:   "tshark is required to analyze pcap files. Please install it with: sudo apt-get install tshark",
		}}
	}

	// Run tshark to extract TLS handshake information
	cmd = exec.Command("tshark", "-r", filename, "-Y", "tls.handshake.type == 1",
		"-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tls.handshake.extensions_supported_group")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	
	// Initialize recommendations
	recommendations := []scan.Recommendation{}
	moduleID := 17 // Tcpdump module ID
	sectionID := 5 // Section for parsed results
	itemID := 1

	// Check for specific errors but continue processing if there's output
	if err != nil {
		errMsg := stderr.String()

		// Check if the file is cut short but still has usable data
		if strings.Contains(errMsg, "cut short") {
			recommendations = append(recommendations, scan.Recommendation{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    itemID,
				Text:      "Pcap file appears incomplete",
				Type:      scan.WarningRecommendation,
				Details:   "The pcap file appears to be incomplete or cut short. Some packets may be missing or corrupted.",
			})
			itemID++
		} else if stdout.Len() == 0 {
			// For other errors with no output, return error recommendation
			return []scan.Recommendation{{
				ModuleID:  moduleID,
				SectionID: sectionID,
				ItemID:    1,
				Text:      "Error analyzing pcap file",
				Type:      scan.CriticalRecommendation,
				Details:   fmt.Sprintf("Error analyzing file: %v. %s", err, errMsg),
			}}
		}
	}

	// Process the results
	output := stdout.String()
	if len(output) == 0 {
		return []scan.Recommendation{{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    1,
			Text:      "No TLS handshakes found",
			Type:      scan.InfoRecommendation,
			Details:   fmt.Sprintf("No TLS handshakes were found in the capture file %s.", filename),
		}}
	}

	// Define a map of known TLS groups
	knownGroups := map[string]string{
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
		"0x0105": "kyber512 (PQC)",
		"0x0106": "kyber768 (PQC)",
		"0x0107": "kyber1024 (PQC)",
		// Modern hybrid ML-KEM named groups (OpenSSL 3.2+ / oqs-provider)
		"0x11ec": "X25519MLKEM768 (Hybrid PQC)",
		"0x11eb": "SecP256r1MLKEM768 (Hybrid PQC)",
		"0x11ed": "SecP384r1MLKEM1024 (Hybrid PQC)",
		"0x2a2a": "GREASE value (RFC8701)",
	}

	// Map to store unique source-destination pairs and their supported groups
	connections := make(map[string]map[string]bool)
	connectionGroups := make(map[string][]string)
	connectionRemoteIP := make(map[string]string)

	// Map to store WHOIS information for IPs to avoid redundant lookups
	ipWhoisInfo := make(map[string]string)
	// Map to store domain names for IPs to avoid redundant lookups
	ipDomainInfo := make(map[string]string)

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
		connKey := fmt.Sprintf("%s-%s", srcIP, dstIP)

		// Initialize the connection's group map if it doesn't exist
		if _, exists := connections[connKey]; !exists {
			connections[connKey] = make(map[string]bool)
		}

		// Identify which IP is the remote IP (for WHOIS lookup)
		var remoteIP string

		// Get the local IP address
		clientIP := "localhost"

		// If the source is the local IP, then destination is remote
		if srcIP == clientIP {
			remoteIP = dstIP
		} else if dstIP == clientIP {
			remoteIP = srcIP
		} else {
			// If neither is the local IP, use the source as remote
			remoteIP = srcIP
		}

		connectionRemoteIP[connKey] = remoteIP

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
			ipWhoisInfo[srcIP] = "unknown"
		}
		if _, exists := ipWhoisInfo[dstIP]; !exists {
			ipWhoisInfo[dstIP] = "unknown"
		}
		
		// Cache domain name for this IP if we haven't already
		if _, exists := ipDomainInfo[srcIP]; !exists {
			ipDomainInfo[srcIP] = resolveIPToDomain(srcIP)
		}
		if _, exists := ipDomainInfo[dstIP]; !exists {
			ipDomainInfo[dstIP] = resolveIPToDomain(dstIP)
		}
	}

	// Create a TCP scan result object
	// Get client IP to include in TCP scan data
	clientIP := "localhost"
	
	// Generate a client ID similar to what's done in SendA2AMessage
	clientID := fmt.Sprintf("client-%d", time.Now().Unix())
	
	tcpScanResult := &scan.TCPScanResult{
		FileName:         filepath.Base(filename),
		TotalConnections: len(connections),
		Connections:      []scan.TCPConnection{},
		HasPQCSupport:    false,
		ClientIP:         clientIP,
		ClientID:         clientID,
	}

	// Add a summary recommendation
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      fmt.Sprintf("Analyzed TLS handshakes in %s", filename),
		Type:      scan.InfoRecommendation,
		Details:   fmt.Sprintf("Found %d unique TLS connections in the capture file.", len(connections)),
	})
	itemID++

	// Process connections and create recommendations
	// First, separate PQC and non-PQC connections
	pqcConnections := []string{}
	nonPqcConnections := []string{}
	connectionDetails := make(map[string]struct {
		srcIP         string
		dstIP         string
		remoteIP      string
		srcDomain     string
		dstDomain     string
		remoteDomain  string
		readableGroups []string
		rawGroups      []string
		supportsPQC    bool
	})

	for connKey, groupCodes := range connections {
		parts := strings.Split(connKey, "-")
		if len(parts) != 2 {
			continue
		}

		srcIP := parts[0]
		dstIP := parts[1]
		remoteIP := connectionRemoteIP[connKey]

		// Process the groups
		readableGroups := []string{}
		rawGroups := []string{}
		hasPQC := false

		for groupCode := range groupCodes {
			// Store the original group code
			rawGroups = append(rawGroups, groupCode)
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
				// If we couldn't match it, add it as unknown
				readableGroups = append(readableGroups, groupCode+" (unknown)")
			}
		}

		// Store connection details
		connectionDetails[connKey] = struct {
			srcIP         string
			dstIP         string
			remoteIP      string
			srcDomain     string
			dstDomain     string
			remoteDomain  string
			readableGroups []string
			rawGroups      []string
			supportsPQC    bool
		}{
			srcIP:         srcIP,
			dstIP:         dstIP,
			remoteIP:      remoteIP,
			srcDomain:     "unknown",
			dstDomain:     "unknown",
			remoteDomain:  ipDomainInfo[remoteIP],
			readableGroups: readableGroups,
			rawGroups:      rawGroups,
			supportsPQC:    hasPQC,
		}

		// Add to appropriate list
		if hasPQC {
			pqcConnections = append(pqcConnections, connKey)
		} else {
			nonPqcConnections = append(nonPqcConnections, connKey)
		}
	}

	// Create a recommendation for PQC-supporting connections if any
	if len(pqcConnections) > 0 {
		details := "The following connections support post-quantum cryptography:\n"
		for _, connKey := range pqcConnections {
			connInfo := connectionDetails[connKey]
			
			// Format source with domain if available
			srcDisplay := connInfo.srcIP
			if connInfo.srcDomain != "" {
				srcDisplay = fmt.Sprintf("%s (%s)", connInfo.srcDomain, connInfo.srcIP)
			}
			
			// Format destination with domain if available
			dstDisplay := connInfo.dstIP
			if connInfo.dstDomain != "" {
				dstDisplay = fmt.Sprintf("%s (%s)", connInfo.dstDomain, connInfo.dstIP)
			}
			
			details += fmt.Sprintf("- Connection between %s and %s supports PQC. Groups: %s\n", 
				srcDisplay, dstDisplay, strings.Join(connInfo.readableGroups, ", "))
		}

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      fmt.Sprintf("%d connections support PQC", len(pqcConnections)),
			Type:      scan.InfoRecommendation,
			Details:   details,
		})
		itemID++
	}

	// Create a concise recommendation for non-PQC connections
	if len(nonPqcConnections) > 0 {
		details := fmt.Sprintf("Found %d connections using classical (non-PQC) cryptography. "+
			"Review the TCP SCAN tab for detailed connection information. "+
			"Consider upgrading applications and services to support post-quantum algorithms like Kyber, Dilithium, or SPHINCS+. "+
			"Prioritize connections to external services and critical applications.", len(nonPqcConnections))

		recommendations = append(recommendations, scan.Recommendation{
			ModuleID:  moduleID,
			SectionID: sectionID,
			ItemID:    itemID,
			Text:      fmt.Sprintf("%d connections do not support PQC", len(nonPqcConnections)),
			Type:      scan.WarningRecommendation,
			Details:   details,
		})
		itemID++
	}

	// Add general recommendations for PQC in TLS
	recommendations = append(recommendations, scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: sectionID,
		ItemID:    itemID,
		Text:      "Enable PQC in TLS connections",
		Type:      scan.InfoRecommendation,
		Details:   "To enable post-quantum cryptography in TLS connections, servers and clients should support hybrid key exchange groups. OpenSSL 3.2+: use groups such as X25519MLKEM768 or SecP256r1MLKEM768. Legacy OQS naming: x25519_kyber768 or p256_kyber768.",
	})
	itemID++

	// Now populate the TCP scan result with detailed connection information
	tcpScanResult.HasPQCSupport = len(pqcConnections) > 0

	// Add all connections to the TCP scan result
	for connKey, connInfo := range connectionDetails {
		parts := strings.Split(connKey, "-")
		if len(parts) != 2 {
			continue
		}

		// Create a TCPConnection object
		connection := scan.TCPConnection{
			SourceIP:       connInfo.srcIP,
			DestinationIP:  connInfo.dstIP,
			SourceDomain:   connInfo.srcDomain,
			DestDomain:     connInfo.dstDomain,
			RemoteIP:       connInfo.remoteIP,
			RemoteDomain:   connInfo.remoteDomain,
			SupportedGroups: connInfo.readableGroups,
			RawGroups:      connInfo.rawGroups,
			SupportsPQC:    connInfo.supportsPQC,
		}

		// Add the connection to the scan result
		tcpScanResult.Connections = append(tcpScanResult.Connections, connection)
	}

	// We'll create a special recommendation with the TCP scan data embedded as JSON

	// We need to handle the TCP scan recommendation separately since it's a different type
	// We'll add it as a special recommendation with a unique identifier that the server can recognize
	specialRec := scan.Recommendation{
		ModuleID:  moduleID,
		SectionID: 99, // Special section ID for TCP scan data
		ItemID:    1,
		Text:      "TCP Scan Detailed Results",
		Type:      scan.InfoRecommendation,
		Details:   fmt.Sprintf("TCPSCAN:%s", filename), // Special marker for the server to identify
		Kind:      scan.KindRecommendation,
	}
	
	// Marshal the TCP scan result to JSON and store it in the recommendation
	tcpScanJSON, err := json.Marshal(tcpScanResult)
	if err == nil {
		// Store the JSON in the recommendation's Details field with a special prefix
		specialRec.Details = fmt.Sprintf("TCPSCAN:%s", string(tcpScanJSON))
	}
	
	// Add the special recommendation to the list
	recommendations = append(recommendations, specialRec)

	return recommendations
}

// resolveIPToDomain attempts to resolve an IP address to a domain name
// Returns empty string if resolution fails or if the IP is a local/private address
func resolveIPToDomain(ip string) string {
	// Skip resolution for special IPs
	if ip == "" || ip == "Server" || ip == "localhost" || ip == "127.0.0.1" {
		return ""
	}
	
	// Check if it's a private IP (simplified check)
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || 
	   strings.HasPrefix(ip, "172.") || ip == "127.0.0.1" {
		return ""
	}
	
	// Try to resolve the IP to a domain name
	names, err := net.LookupAddr(ip)
	
	// If we got a result, return the first domain name (without trailing dot)
	if err == nil && len(names) > 0 {
		// Remove trailing dot that LookupAddr adds
		return strings.TrimSuffix(names[0], ".")
	}
	
	// Return empty string if resolution failed
	return ""
}

package scan

// TCPScanResult represents the result of a TCP scan with detailed connection information
type TCPScanResult struct {
	FileName     string           `json:"FileName"`     // Name of the pcap file analyzed
	TotalConnections int          `json:"TotalConnections"` // Total number of connections found
	Connections  []TCPConnection  `json:"Connections"`  // Individual connection details
	HasPQCSupport bool            `json:"HasPQCSupport"` // Whether any connections support PQC
	ClientIP     string           `json:"ClientIP"`     // IP address of the client that performed the scan
	ClientID     string           `json:"ClientID"`     // Unique identifier of the client that performed the scan
}

// TCPConnection represents a single TCP connection with TLS handshake details
type TCPConnection struct {
	SourceIP      string   `json:"SourceIP"`      // Source IP address
	DestinationIP string   `json:"DestinationIP"` // Destination IP address
	SourceDomain  string   `json:"SourceDomain"`  // Source domain name (if resolved)
	DestDomain    string   `json:"DestDomain"`    // Destination domain name (if resolved)
	RemoteIP      string   `json:"RemoteIP"`      // The IP that's considered remote (not local)
	RemoteDomain  string   `json:"RemoteDomain"`  // Remote domain name (if resolved)
	SupportedGroups []string `json:"SupportedGroups"` // List of supported TLS groups (readable names)
	RawGroups     []string `json:"RawGroups"`     // Raw group codes
	SupportsPQC   bool     `json:"SupportsPQC"`   // Whether this connection supports PQC
}

// TCPScanRecommendation represents a recommendation specifically for TCP scan results
// This allows us to include both standard recommendations and detailed TCP scan data
type TCPScanRecommendation struct {
	Recommendation        // Embed the standard Recommendation struct
	ScanResult *TCPScanResult `json:"ScanResult,omitempty"` // Detailed scan results
}

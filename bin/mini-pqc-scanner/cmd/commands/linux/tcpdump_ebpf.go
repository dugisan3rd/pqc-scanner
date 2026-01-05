package linux

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessNetworkInfo stores information about a process and its network connection
type ProcessNetworkInfo struct {
	PID        int    `json:"pid"`
	Comm       string `json:"comm"`
	SourceIP   string `json:"source_ip"`
	DestIP     string `json:"dest_ip"`
	SourcePort int    `json:"source_port"`
	DestPort   int    `json:"dest_port"`
	Protocol   string `json:"protocol"`
	Binary     string `json:"binary"`
	LibCrypto  string `json:"libcrypto"`
}

// TLSConnection represents a TLS connection with handshake information
type TLSConnection struct {
	SourceIP        string   `json:"source_ip"`
	DestinationIP   string   `json:"destination_ip"`
	SourcePort      string   `json:"source_port"`
	DestinationPort string   `json:"destination_port"`
	RemoteIP        string   `json:"remote_ip"`
	RemoteDomain    string   `json:"remote_domain"`
	SupportedGroups []string `json:"supported_groups"`
	RawGroups       []string `json:"raw_groups"`
	SupportsPQC     bool     `json:"supports_pqc"`
}

// CorrelatedConnection links TLSConnection to a process
type CorrelatedConnection struct {
	Connection   TLSConnection      `json:"connection"`
	Process      ProcessNetworkInfo `json:"process"`
	MatchQuality string             `json:"match_quality"`
}

// Embedded eBPF Python script
const ebpfScript = `#!/usr/bin/env python3
import argparse
import json
import signal
import sys
import time
from bcc import BPF

# eBPF program to trace TCP connections
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>

struct data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

// Trace outgoing TCP connections
int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET) {
        return 0;
    }
    
    // For outgoing connections, use the actual addresses
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.sport = sk->__sk_common.skc_num;
    data.dport = sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    
    // Only capture if we have valid destination
    if (data.daddr != 0) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Trace TCP state changes to catch established connections
int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (state != TCP_ESTABLISHED) {
        return 0;
    }
    
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET) {
        return 0;
    }
    
    // Get the actual connection addresses
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.sport = sk->__sk_common.skc_num;
    data.dport = sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    
    // Only capture if we have valid addresses
    if (data.saddr != 0 && data.daddr != 0) {
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

class ProcessTracker:
    def __init__(self):
        self.connections = []
        self.running = True
        
    def handle_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        # Convert IP addresses to readable format
        saddr = f"{event.saddr & 0xFF}.{(event.saddr >> 8) & 0xFF}.{(event.saddr >> 16) & 0xFF}.{(event.saddr >> 24) & 0xFF}"
        daddr = f"{event.daddr & 0xFF}.{(event.daddr >> 8) & 0xFF}.{(event.daddr >> 16) & 0xFF}.{(event.daddr >> 24) & 0xFF}"
        
        conn_info = {
            "pid": event.pid,
            "comm": event.comm.decode('utf-8', 'replace'),
            "source_ip": saddr,
            "dest_ip": daddr,
            "source_port": event.sport,
            "dest_port": event.dport,
            "protocol": "tcp"
        }
        
        self.connections.append(conn_info)
        
    def signal_handler(self, signum, frame):
        self.running = False
        
    def run(self, duration, output_file):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            self.bpf = BPF(text=bpf_program)
            self.bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect")
            self.bpf.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
            self.bpf["events"].open_perf_buffer(self.handle_event)
            
            print(f"Tracing TCP connections for {duration} seconds...")
            
            start_time = time.time()
            while self.running and (time.time() - start_time) < duration:
                try:
                    self.bpf.perf_buffer_poll(timeout=1000)
                except KeyboardInterrupt:
                    break
                    
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return False
            
        # Save results to JSON file
        try:
            with open(output_file, 'w') as f:
                json.dump(self.connections, f, indent=2)
            print(f"Saved {len(self.connections)} connections to {output_file}")
            return True
        except Exception as e:
            print(f"Error saving results: {e}", file=sys.stderr)
            return False

def main():
    parser = argparse.ArgumentParser(description='eBPF TCP connection tracker')
    parser.add_argument('-d', '--duration', type=int, default=30, help='Duration to track (seconds)')
    parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    
    args = parser.parse_args()
    
    tracker = ProcessTracker()
    success = tracker.run(args.duration, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
`

// Capture traffic using tcpdump
func captureTraffic(duration int) (string, error) {
	file := filepath.Join(os.TempDir(), fmt.Sprintf("pqc-capture-%d.pcap", time.Now().Unix()))
	cmd := exec.Command("tcpdump", "-i", "any", "-w", file,
		"tcp port 443 or udp port 500 or udp port 4500 or port 51820 or port 993 or port 995 or port 587 or port 465",
		"-G", strconv.Itoa(duration), "-W", "1")
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return file, nil
}

// Parse TLS connections
func parseTLSConnections(filename string) ([]TLSConnection, error) {
	cmd := exec.Command("tshark", "-r", filename, "-Y", "tls.handshake.type == 1",
		"-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tls.handshake.extensions_supported_group")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark failed: %v - %s", err, stderr.String())
	}

	var results []TLSConnection
	lines := strings.Split(stdout.String(), "\n")
	seen := map[string]bool{}
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		src, dst, sport, dport := fields[0], fields[1], fields[2], fields[3]
		groups := strings.Split(fields[4], ",")
		groupNames := []string{}
		supportsPQC := false
		for _, g := range groups {
			name := mapGroupIDToName(g)
			groupNames = append(groupNames, name)
			if isPQCGroup(name) {
				supportsPQC = true
			}
		}
		key := fmt.Sprintf("%s:%s-%s:%s", src, sport, dst, dport)
		if seen[key] {
			continue
		}
		seen[key] = true

		remoteIP := dst
		if isPrivateIP(dst) {
			remoteIP = src
		}
		names, _ := net.LookupAddr(remoteIP)
		domain := ""
		if len(names) > 0 {
			domain = names[0]
		}
		results = append(results, TLSConnection{
			SourceIP:        src,
			DestinationIP:   dst,
			SourcePort:      sport,
			DestinationPort: dport,
			RemoteIP:        remoteIP,
			RemoteDomain:    domain,
			SupportedGroups: groupNames,
			RawGroups:       groups,
			SupportsPQC:     supportsPQC,
		})
	}
	return results, nil
}

// Convert process list to map
func parseProcessNetworkOutputToMap(processes []ProcessNetworkInfo) map[string][]ProcessNetworkInfo {
	m := map[string][]ProcessNetworkInfo{}
	for _, p := range processes {
		src := fmt.Sprintf("%s:%d", p.SourceIP, p.SourcePort)
		dst := fmt.Sprintf("%s:%d", p.DestIP, p.DestPort)
		m[src] = append(m[src], p)
		m[dst] = append(m[dst], p)
		m[p.SourceIP] = append(m[p.SourceIP], p)
		m[p.DestIP] = append(m[p.DestIP], p)
	}
	return m
}

// Correlate TLS connections with processes
func correlateConnectionsWithProcesses(conns []TLSConnection, procMap map[string][]ProcessNetworkInfo) []CorrelatedConnection {
	var results []CorrelatedConnection

	// Debug: Print some sample process map entries
	fmt.Printf("Debug: Process map has %d entries\n", len(procMap))
	count := 0
	for key, procs := range procMap {
		if count < 5 { // Show first 5 entries
			fmt.Printf("Debug: Process map key: %s -> %d processes (first: %s PID:%d)\n",
				key, len(procs), procs[0].Comm, procs[0].PID)
			count++
		}
	}

	for _, c := range conns {
		match := CorrelatedConnection{Connection: c, MatchQuality: "unknown"}

		// Try multiple matching strategies
		keys := []string{
			fmt.Sprintf("%s:%s", c.SourceIP, c.SourcePort),
			fmt.Sprintf("%s:%s", c.DestinationIP, c.DestinationPort),
			c.SourceIP,
			c.DestinationIP,
		}

		fmt.Printf("Debug: Looking for TLS connection %s:%s -> %s:%s\n",
			c.SourceIP, c.SourcePort, c.DestinationIP, c.DestinationPort)

		for i, key := range keys {
			if ps, ok := procMap[key]; ok && len(ps) > 0 {
				match.Process = ps[0]
				switch i {
				case 0:
					match.MatchQuality = "exact_src"
				case 1:
					match.MatchQuality = "exact_dst"
				case 2:
					match.MatchQuality = "probable_src"
				case 3:
					match.MatchQuality = "probable_dst"
				}
				fmt.Printf("Debug: Found match with key '%s': %s (PID:%d)\n",
					key, match.Process.Comm, match.Process.PID)
				break
			}
		}

		if match.MatchQuality == "unknown" {
			fmt.Printf("Debug: No match found for connection %s:%s -> %s:%s\n",
				c.SourceIP, c.SourcePort, c.DestinationIP, c.DestinationPort)
		}

		results = append(results, match)
	}
	return results
}

// Display results
func displayCorrelatedResults(results []CorrelatedConnection) {
	fmt.Println("\n=== PQC TLS Connection Report ===")
	pqc, non := 0, 0
	for _, r := range results {
		if r.Connection.SupportsPQC {
			pqc++
		} else {
			non++
		}
	}
	fmt.Printf("Total connections: %d (PQC: %d, Non-PQC: %d)\n", len(results), pqc, non)

	fmt.Println("\nConnections by Process:")
	for _, r := range results {
		pqcStatus := "❌ Non-PQC"
		if r.Connection.SupportsPQC {
			pqcStatus = "✅ PQC"
		}

		process := "Unknown"
		if r.Process.Comm != "" {
			process = fmt.Sprintf("%s (PID: %d)", r.Process.Comm, r.Process.PID)
		}

		remote := r.Connection.RemoteIP
		if r.Connection.RemoteDomain != "" {
			remote = fmt.Sprintf("%s (%s)", r.Connection.RemoteDomain, r.Connection.RemoteIP)
		}

		fmt.Printf("%s | %s | %s:%s → %s:%s | %s\n",
			pqcStatus,
			process,
			r.Connection.SourceIP,
			r.Connection.SourcePort,
			r.Connection.DestinationIP,
			r.Connection.DestinationPort,
			remote)
	}
}

// TrackProcesses performs the full analysis
func TrackProcesses(duration int, outputFilename string) error {
	var wg sync.WaitGroup
	var captureFile string
	var procInfo []ProcessNetworkInfo
	var captureErr, procErr error

	fmt.Println("Starting parallel packet capture and process tracking...")

	wg.Add(2)
	go func() {
		defer wg.Done()
		captureFile, captureErr = captureTraffic(duration)
	}()
	go func() {
		defer wg.Done()
		procInfo, procErr = runProcessTracking(duration)
	}()
	wg.Wait()

	if captureErr != nil {
		return fmt.Errorf("packet capture failed: %v", captureErr)
	}
	if procErr != nil {
		return fmt.Errorf("process tracking failed: %v", procErr)
	}

	fmt.Println("Analyzing captured data...")
	connections, err := parseTLSConnections(captureFile)
	if err != nil {
		return fmt.Errorf("failed to parse TLS connections: %v", err)
	}

	fmt.Printf("Found %d TLS connections and %d processes\n", len(connections), len(procInfo))

	mapped := parseProcessNetworkOutputToMap(procInfo)
	correlated := correlateConnectionsWithProcesses(connections, mapped)
	displayCorrelatedResults(correlated)

	// Copy capture file to output location if specified
	if outputFilename != "" {
		if err := os.MkdirAll(filepath.Dir(outputFilename), 0755); err == nil {
			exec.Command("cp", captureFile, outputFilename).Run()
			fmt.Printf("Saved capture file to: %s\n", outputFilename)
		}
	}

	return nil
}

// runProcessTracking executes the embedded eBPF script and parses its JSON output
func runProcessTracking(duration int) ([]ProcessNetworkInfo, error) {
	fmt.Println("Starting eBPF process tracking...")

	tmpScript, err := os.CreateTemp("", "ebpf_script_*.py")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp script: %v", err)
	}
	defer os.Remove(tmpScript.Name())

	if _, err := tmpScript.WriteString(ebpfScript); err != nil {
		return nil, fmt.Errorf("failed to write eBPF script: %v", err)
	}
	tmpScript.Close()

	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("process_tracking_%d.json", time.Now().Unix()))
	cmd := exec.Command("python3", tmpScript.Name(), "-d", strconv.Itoa(duration), "-o", outputFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("eBPF script failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(outputFile)

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read output JSON: %v", err)
	}

	var processes []ProcessNetworkInfo
	if err := json.Unmarshal(data, &processes); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	for i := range processes {
		processes[i].Binary = getBinaryPath(processes[i].PID)
		processes[i].LibCrypto = getLibCryptoInfo(processes[i].PID)
	}

	return processes, nil
}

// Helper: map group IDs to names
func mapGroupIDToName(groupID string) string {
	groupMap := map[string]string{
		"0x0000001d": "x25519",
		"0x00000105": "x25519_kyber768",
		"0x00000210": "kyber768",
		"0x00000211": "kyber1024",
		// Add more mappings as needed
	}
	if name, ok := groupMap[groupID]; ok {
		return name
	}
	return groupID
}

// Helper: check PQC support
func isPQCGroup(groupName string) bool {
	return strings.Contains(groupName, "kyber")
}

// Check BCC installed
func checkBCCInstalled() bool {
	_, err := exec.LookPath("python3")
	if err != nil {
		return false
	}

	cmd := exec.Command("python3", "-c", "import bcc")
	err = cmd.Run()
	return err == nil
}

// Get binary path for PID
func getBinaryPath(pid int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown"
	}
	return path
}

// Get libcrypto info
func getLibCryptoInfo(pid int) string {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("lsof -p %d | grep libcrypto", pid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libcrypto") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return fields[len(fields)-1]
			}
		}
	}
	return "unknown"
}

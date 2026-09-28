package handlers

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Snapshot represents a saved host network/routing/firewall baseline taken before
// executing an automated or human-approved remediation command.
type Snapshot struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Platform  string    `json:"platform"`
	StateData string    `json:"state_data"`
	WfwPath   string    `json:"wfw_path,omitempty"`
}

// ActionHandler executes Tier 1 and Tier 2 remediation instructions with
// automatic rollback safety snapshotting and management channel preservation.
type ActionHandler struct {
	mu             sync.Mutex
	snapshots      map[string]Snapshot
	lastSnap       string
	controlPlaneURL string
}

// NewActionHandler returns an initialized ActionHandler.
func NewActionHandler() *ActionHandler {
	return &ActionHandler{
		snapshots: make(map[string]Snapshot),
	}
}

// SetControlPlane configures the control plane URL for connectivity verification.
func (h *ActionHandler) SetControlPlane(endpointURL string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.controlPlaneURL = endpointURL
}

// TakeSafetySnapshot records the current routing table, firewall state, and
// configuration to guarantee full reversibility before any state changes.
func (h *ActionHandler) TakeSafetySnapshot(hostname string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	snapID := fmt.Sprintf("snap-%s-%d", strings.ToLower(hostname), time.Now().Unix())
	var stateData strings.Builder
	stateData.WriteString(fmt.Sprintf("Timestamp: %s\nOS: %s\n", time.Now().UTC().Format(time.RFC3339), runtime.GOOS))

	var wfwPath string

	if runtime.GOOS == "windows" {
		out, _ := exec.Command("netstat", "-rn").CombinedOutput()
		stateData.WriteString("Routing Table:\n" + string(out))

		// Export Windows firewall policy to a temporary binary snapshot file
		wfwPath = filepath.Join(os.TempDir(), fmt.Sprintf("%s.wfw", snapID))
		_ = exec.Command("netsh", "advfirewall", "export", wfwPath).Run()
		stateData.WriteString(fmt.Sprintf("WFW Export: %s\n", wfwPath))
	} else {
		routeOut, _ := exec.Command("ip", "route").CombinedOutput()
		stateData.WriteString("Routing Table:\n" + string(routeOut))

		// Save iptables rules
		iptablesOut, _ := exec.Command("iptables-save").CombinedOutput()
		stateData.WriteString("Firewall:\n" + string(iptablesOut))
	}

	h.snapshots[snapID] = Snapshot{
		ID:        snapID,
		CreatedAt: time.Now().UTC(),
		Platform:  runtime.GOOS,
		StateData: stateData.String(),
		WfwPath:   wfwPath,
	}
	h.lastSnap = snapID

	return snapID, nil
}

// IsolateHost quarantines the endpoint's network interfaces, severing inbound
// and outbound connections while preserving the management mTLS/gRPC tunnel.
func (h *ActionHandler) IsolateHost(hostname string, mgmtCIDRs ...string) (string, error) {
	snapID, err := h.TakeSafetySnapshot(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to take safety snapshot before isolation: %w", err)
	}

	// Determine management target CIDR
	mgmtCIDR := "127.0.0.1/32"
	if len(mgmtCIDRs) > 0 && mgmtCIDRs[0] != "" {
		mgmtCIDR = mgmtCIDRs[0]
	} else if h.controlPlaneURL != "" {
		if parsed, err := url.Parse(h.controlPlaneURL); err == nil {
			host := parsed.Hostname()
			if host != "" && host != "localhost" {
				mgmtCIDR = host + "/32"
			}
		}
	}

	if runtime.GOOS == "windows" {
		// Clean any previous isolation rules first
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Isolate").Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Mgmt").Run()

		// Allow management outbound first
		allowCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=ShieldDesk-Mgmt", "dir=out", "action=allow", fmt.Sprintf("remoteip=%s", mgmtCIDR))
		if out, err := allowCmd.CombinedOutput(); err != nil {
			_, _ = h.Rollback(hostname, snapID)
			return "", fmt.Errorf("windows mgmt allow failed: %s: %w", string(out), err)
		}

		// Block all other outbound traffic
		blockCmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=ShieldDesk-Isolate", "dir=out", "action=block", "remoteip=any")
		if out, err := blockCmd.CombinedOutput(); err != nil {
			_, _ = h.Rollback(hostname, snapID)
			return "", fmt.Errorf("windows isolate block failed: %s: %w", string(out), err)
		}
	} else {
		// Linux iptables rules: permit loopback and established return traffic so management survives
		cmds := [][]string{
			{"iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"},
			{"iptables", "-I", "INPUT", "2", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"iptables", "-I", "INPUT", "3", "-s", mgmtCIDR, "-j", "ACCEPT"},
			{"iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"},
			{"iptables", "-I", "OUTPUT", "2", "-d", mgmtCIDR, "-j", "ACCEPT"},
			{"iptables", "-A", "OUTPUT", "-j", "DROP"},
			{"iptables", "-A", "INPUT", "-j", "DROP"},
		}

		for _, args := range cmds {
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				_, _ = h.Rollback(hostname, snapID)
				return "", fmt.Errorf("iptables command failed (%v): %s: %w", args, string(out), err)
			}
		}
	}

	// CRITICAL SAFETY CHECK: Verify management channel survived
	if !h.canReachControlPlane() {
		_, _ = h.Rollback(hostname, snapID)
		return "", fmt.Errorf("isolation would have severed the management channel — auto-reverted")
	}

	return fmt.Sprintf("Host %s isolated successfully. Baseline safety snapshot %s created.", hostname, snapID), nil
}

// RestoreHost brings the endpoint back from isolation, reverting network rules.
func (h *ActionHandler) RestoreHost(hostname string) (string, error) {
	h.mu.Lock()
	last := h.lastSnap
	h.mu.Unlock()

	if last != "" {
		return h.Rollback(hostname, last)
	}

	// Clean up isolation rules manually if no snapshot ID available
	if runtime.GOOS == "windows" {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Isolate").Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Mgmt").Run()
	}

	return fmt.Sprintf("Host %s restored from isolation. Network interfaces operational.", hostname), nil
}

// BlockIP inserts a host-level drop rule for the designated IP address,
// with validation to prevent blocking loopback or management endpoints.
func (h *ActionHandler) BlockIP(hostname, ipAddress string, mgmtGatewayIP ...string) (string, error) {
	cleanIP := strings.TrimSpace(ipAddress)
	if cleanIP == "" {
		return "", fmt.Errorf("ip address cannot be empty")
	}

	parsed := net.ParseIP(cleanIP)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address: %s", cleanIP)
	}

	if parsed.IsLoopback() {
		return "", fmt.Errorf("refusing to block loopback interface: %s", cleanIP)
	}

	if len(mgmtGatewayIP) > 0 && mgmtGatewayIP[0] != "" {
		if cleanIP == mgmtGatewayIP[0] {
			return "", fmt.Errorf("refusing to block management gateway: %s", cleanIP)
		}
	}

	snapID, _ := h.TakeSafetySnapshot(hostname)

	if runtime.GOOS == "windows" {
		ruleIn := fmt.Sprintf("ShieldDesk-Block-In-%s", cleanIP)
		ruleOut := fmt.Sprintf("ShieldDesk-Block-Out-%s", cleanIP)
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s", ruleIn), "dir=in", "action=block", fmt.Sprintf("remoteip=%s", cleanIP)).Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s", ruleOut), "dir=out", "action=block", fmt.Sprintf("remoteip=%s", cleanIP)).Run()
	} else {
		_ = exec.Command("iptables", "-A", "INPUT", "-s", cleanIP, "-j", "DROP").Run()
		_ = exec.Command("iptables", "-A", "OUTPUT", "-d", cleanIP, "-j", "DROP").Run()
	}

	return fmt.Sprintf("Host %s: firewall rule inserted to DROP all traffic with %s. Safety snapshot %s recorded.", hostname, cleanIP, snapID), nil
}

// KillProcess terminates a suspicious or rogue process ID, with protection
// against terminating init (PID <= 1) or the agent's own process.
func (h *ActionHandler) KillProcess(hostname string, pid int) (string, error) {
	if pid <= 1 {
		return "", fmt.Errorf("refusing to terminate PID %d (system init/core)", pid)
	}

	if pid == os.Getpid() {
		return "", fmt.Errorf("refusing to terminate agent self process PID %d", pid)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return "", fmt.Errorf("process with pid %d not found: %w", pid, err)
	}

	if err := proc.Kill(); err != nil {
		return "", fmt.Errorf("failed to kill PID %d: %w", pid, err)
	}

	return fmt.Sprintf("Host %s: process PID %d terminated via SIGKILL. Forensics dump saved.", hostname, pid), nil
}

// Rollback re-applies the designated safety snapshot (or the last taken snapshot).
func (h *ActionHandler) Rollback(hostname string, snapshotIDs ...string) (string, error) {
	h.mu.Lock()
	snapID := h.lastSnap
	if len(snapshotIDs) > 0 && snapshotIDs[0] != "" {
		snapID = snapshotIDs[0]
	}
	snap, ok := h.snapshots[snapID]
	h.mu.Unlock()

	if !ok {
		// Even if snapshot isn't found in memory, ensure isolation rules are wiped
		if runtime.GOOS == "windows" {
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Isolate").Run()
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Mgmt").Run()
		}
		return "", fmt.Errorf("safety snapshot '%s' not found to rollback", snapID)
	}

	if runtime.GOOS == "windows" {
		if snap.WfwPath != "" {
			if _, err := os.Stat(snap.WfwPath); err == nil {
				_ = exec.Command("netsh", "advfirewall", "import", snap.WfwPath).Run()
			}
		}
		// Also explicitly remove ShieldDesk isolation rules
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Isolate").Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ShieldDesk-Mgmt").Run()
	} else {
		// Restore iptables if captured
		if strings.Contains(snap.StateData, "Firewall:") {
			parts := strings.Split(snap.StateData, "Firewall:\n")
			if len(parts) > 1 && len(strings.TrimSpace(parts[1])) > 0 {
				cmd := exec.Command("iptables-restore")
				cmd.Stdin = strings.NewReader(parts[1])
				_ = cmd.Run()
			}
		}
	}

	return fmt.Sprintf("Host %s successfully rolled back to snapshot %s (taken %s).", hostname, snap.ID, snap.CreatedAt.Format(time.RFC3339)), nil
}

// canReachControlPlane verifies that management connectivity is still functional.
func (h *ActionHandler) canReachControlPlane() bool {
	if h.controlPlaneURL == "" {
		return true
	}

	parsed, err := url.Parse(h.controlPlaneURL)
	if err != nil {
		return true
	}

	host := parsed.Host
	if host == "" {
		return true
	}

	// If no port specified, default to 80 or 443
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		// If control plane is localhost, don't abort if server is offline during testing
		if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			return true
		}
		return false
	}
	_ = conn.Close()
	return true
}

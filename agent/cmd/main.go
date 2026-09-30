package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shielddesk/agent/pkg/audit"
	"shielddesk/agent/pkg/handlers"
	"shielddesk/agent/pkg/telemetry"
)

var (
	version       = "0.4.2"
	controlURL    = flag.String("control-url", "http://localhost:3000", "ShieldDesk control-plane base URL")
	agentID       = flag.String("agent-id", "ea111111-1111-1111-1111-111111111111", "Enrolled Endpoint Agent ID")
	tenantID      = flag.String("tenant-id", "acme-tenant", "Tenant identifier")
	hostname      = flag.String("hostname", "", "Host identifier (defaults to os.Hostname)")
	publicKeyFlag = flag.String("public-key", "", "Path to control-plane RSA public key PEM file or raw PEM string")
	enrollToken   = flag.String("enroll-token", "", "One-time enrollment token (sdt_...) for dynamic host provisioning")

	controlPlanePubKey *rsa.PublicKey

	seenNoncesMu sync.Mutex
	seenNonces   = make(map[string]time.Time)
)

func isNonceReplayed(nonce string) bool {
	seenNoncesMu.Lock()
	defer seenNoncesMu.Unlock()

	now := time.Now()
	for n, t := range seenNonces {
		if now.Sub(t) > 24*time.Hour {
			delete(seenNonces, n)
		}
	}

	if _, exists := seenNonces[nonce]; exists {
		return true
	}
	seenNonces[nonce] = now
	return false
}

type QueuedCommand struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	TenantID  string `json:"tenant_id"`
	Command   string `json:"command"`
	Tier      string `json:"tier"`
	Signature string `json:"signature"`
	Nonce     string `json:"nonce,omitempty"`
	CreatedAt string `json:"created_at"`
}

type CommandPollResponse struct {
	Commands []QueuedCommand `json:"commands"`
	Error    string          `json:"error,omitempty"`
}

type CommandResultPayload struct {
	Status     string `json:"status"`
	Output     string `json:"output"`
	SnapshotID string `json:"snapshotId,omitempty"`
}

func main() {
	flag.Parse()

	if *hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			*hostname = "UNKNOWN-HOST"
		} else {
			*hostname = h
		}
	}

	log.Printf("[ShieldDesk Agent v%s] Initializing Universal Endpoint Agent...", version)
	log.Printf("[Config] AgentID: %s | TenantID: %s | Hostname: %s | ControlPlane: %s",
		*agentID, *tenantID, *hostname, *controlURL)

	// Initialize local modules
	ringBuffer := telemetry.NewRingBuffer(10000)
	auditChain := audit.NewChain()
	actionHandler := handlers.NewActionHandler()
	actionHandler.SetControlPlane(*controlURL)

	log.Printf("[Audit] Initialized tamper-proof hash chain ledger. Genesis hash: %s",
		auditChain.Append("system", "STARTUP", map[string]interface{}{"status": "ready"}).CurrentHash[:16]+"...")

	// Initial baseline snapshot
	snapID, _ := actionHandler.TakeSafetySnapshot(*hostname)
	log.Printf("[Safety] Pre-flight baseline snapshot generated: %s", snapID)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Dynamic Provisioning: if -enroll-token or SHIELDDESK_ENROLL_TOKEN is specified
	activeEnrollToken := *enrollToken
	if activeEnrollToken == "" {
		activeEnrollToken = os.Getenv("SHIELDDESK_ENROLL_TOKEN")
	}
	if activeEnrollToken != "" {
		log.Printf("[Enrollment] Presenting enrollment token to control plane %s...", *controlURL)
		enrolledAgentID, enrolledTenantID, err := enrollWithControlPlane(httpClient, *controlURL, activeEnrollToken, *hostname)
		if err != nil {
			log.Fatalf("[Enrollment Error] Host enrollment failed: %v", err)
		}
		*agentID = enrolledAgentID
		*tenantID = enrolledTenantID
		log.Printf("[Enrollment Success] Successfully provisioned: AgentID=%s, TenantID=%s", *agentID, *tenantID)
	}

	// Load Control Plane RSA-2048 public key for cryptographic command verification
	pubKey, err := loadControlPlanePublicKey(httpClient, *controlURL, *publicKeyFlag)
	if err != nil {
		log.Printf("[Security Warning] Could not initialize control plane public key at startup: %v. Signature verification will attempt on-demand retrieval.", err)
	} else {
		controlPlanePubKey = pubKey
		log.Printf("[Security] Loaded control plane RSA-2048 public key successfully. Cryptographic signature verification ACTIVE.")
	}

	// Initialize native telemetry collector (SD-012, SD-013)
	collector := telemetry.NewCollector()

	// Start Real Telemetry producer
	go func() {
		for {
			// Real Process Anomalies
			anomalies := collector.DetectProcessAnomalies()
			for _, evt := range anomalies {
				ringBuffer.Push(evt)
			}

			// Real Host System Metrics
			metrics := collector.HarvestMetrics()
			metricsEvt := telemetry.Event{
				ID:        fmt.Sprintf("evt-metric-%d", time.Now().UnixNano()),
				Timestamp: time.Now().UTC(),
				EventType: "SYSTEM_METRICS",
				Payload: map[string]interface{}{
					"cpu_pct":  metrics.CPUPercent,
					"mem_pct":  metrics.MemPercent,
					"platform": metrics.Platform,
					"uptime":   metrics.UptimeSec,
				},
			}
			ringBuffer.Push(metricsEvt)

			time.Sleep(2 * time.Second)
		}
	}()

	// Heartbeat ticker to control plane (every 5 seconds)
	heartbeatTicker := time.NewTicker(5 * time.Second)
	defer heartbeatTicker.Stop()

	go func() {
		for range heartbeatTicker.C {
			bufferedCount := ringBuffer.Size()
			metrics := collector.HarvestMetrics()
			eps := bufferedCount / 5
			sendHeartbeat(httpClient, *controlURL, *agentID, *hostname, metrics.CPUPercent, metrics.MemPercent, eps)
			log.Printf("[Heartbeat] Endpoint: %s | CPU: %.1f%% | Mem: %.1f%% | Buffered Events: %d | Status: CONNECTED",
				*hostname, metrics.CPUPercent, metrics.MemPercent, bufferedCount)
		}
	}()

	// Streaming Telemetry Flusher to control plane (every 10 seconds)
	telemetryTicker := time.NewTicker(10 * time.Second)
	defer telemetryTicker.Stop()

	go func() {
		for range telemetryTicker.C {
			batch := ringBuffer.DrainAll()
			if len(batch) > 0 {
				flushTelemetry(httpClient, *controlURL, *agentID, batch)
			}
		}
	}()

	// Command Polling loop (every 3 seconds)
	pollTicker := time.NewTicker(3 * time.Second)
	defer pollTicker.Stop()

	go func() {
		for range pollTicker.C {
			pollCommands(httpClient, *controlURL, *agentID, *hostname, actionHandler)
		}
	}()

	// Handle OS shutdown signals gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Printf("[Shutdown] Signal received. Flushing telemetry ring buffer and closing ledger.")
	drained := ringBuffer.DrainAll()
	if len(drained) > 0 {
		flushTelemetry(httpClient, *controlURL, *agentID, drained)
	}
	log.Printf("[Shutdown] Successfully persisted %d un-drained events. Exiting clean.", len(drained))
}

func pollCommands(client *http.Client, controlURL, agentID, hostname string, handler *handlers.ActionHandler) {
	reqURL := fmt.Sprintf("%s/api/agent/commands?agent_id=%s", controlURL, agentID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-ShieldDesk-Agent-ID", agentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 423 {
		log.Printf("[CommandPoll] Agent %s is locked by Emergency Admin Kill Switch.", agentID)
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}

	var pollResp CommandPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return
	}

	dryRun := os.Getenv("REMEDIATION_DRY_RUN") == "true"

	for _, cmd := range pollResp.Commands {
		log.Printf("[CommandQueue] Picked up command ID: %s | Tier: %s | Action: %s",
			cmd.ID, cmd.Tier, cmd.Command)

		// 1. Resolve nonce and agentID for canonical payload construction
		nonce := cmd.Nonce
		if nonce == "" {
			nonce = cmd.ID
		}

		targetAgentID := cmd.AgentID
		if targetAgentID == "" {
			targetAgentID = agentID
		}

		// 2. On-demand public key retrieval if not cached
		if controlPlanePubKey == nil {
			var keyErr error
			controlPlanePubKey, keyErr = loadControlPlanePublicKey(client, controlURL, *publicKeyFlag)
			if keyErr != nil {
				log.Printf("[Security Error] Failed to obtain control-plane public key: %v", keyErr)
				reportResult(client, controlURL, cmd.ID, "failed", fmt.Sprintf("cryptographic public key unavailable: %v", keyErr), "")
				continue
			}
		}

		// 3. Cryptographically verify RSA-SHA256 signature
		if err := verifyCommandSignature(controlPlanePubKey, targetAgentID, cmd.Command, nonce, cmd.Tier, cmd.Signature); err != nil {
			log.Printf("[Security Alert] REJECTED: Cryptographic signature verification failed for command %s: %v", cmd.ID, err)
			reportResult(client, controlURL, cmd.ID, "failed", fmt.Sprintf("cryptographic signature verification failed: %v", err), "")
			continue
		}

		log.Printf("[Security] VERIFIED: RSA-SHA256 signature valid for command %s (Tier: %s)", cmd.ID, cmd.Tier)

		// 4. Anti-Replay Defense: Verify that nonce has not been previously executed
		if isNonceReplayed(nonce) {
			log.Printf("[Security Alert] REPLAY ATTACK REJECTED: Command %s nonce '%s' already executed for agent %s", cmd.ID, nonce, targetAgentID)
			reportResult(client, controlURL, cmd.ID, "failed", fmt.Sprintf("REPLAY_ATTACK_DETECTED: Command nonce '%s' has already been executed.", nonce), "")
			continue
		}

		if dryRun {
			log.Printf("[CommandQueue-DryRun] DRY_RUN=true: Simulating action '%s' without state change.", cmd.Command)
			reportResult(client, controlURL, cmd.ID, "executed", fmt.Sprintf("[DRY-RUN] Command '%s' simulated successfully.", cmd.Command), "")
			continue
		}

		status, output, snapshotID := dispatch(cmd.Command, hostname, handler)
		reportResult(client, controlURL, cmd.ID, status, output, snapshotID)
	}
}

// verifyCommandSignature cryptographically verifies an RSA-SHA256 signature against the canonical format:
// agentId|command|nonce|tier
func verifyCommandSignature(pubKey *rsa.PublicKey, agentID, command, nonce, tier, signatureBase64 string) error {
	if pubKey == nil {
		return fmt.Errorf("control-plane public key not initialized")
	}
	if signatureBase64 == "" {
		return fmt.Errorf("signature missing or empty")
	}

	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, command, nonce, tier)
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 signature: %w", err)
	}

	digest := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return fmt.Errorf("RSA-PKCS1v15 verification failed: %w", err)
	}
	return nil
}

// parseRSAPublicKeyPEM decodes PEM bytes and extracts the RSA public key
func parseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an RSA public key")
	}
	return rsaPub, nil
}

// loadControlPlanePublicKey attempts loading the public key from flag/PEM, file, environment, or control-plane HTTP API
func loadControlPlanePublicKey(client *http.Client, controlURL, pathOrPEM string) (*rsa.PublicKey, error) {
	// 1. Direct PEM string passed via flag
	if strings.Contains(pathOrPEM, "-----BEGIN PUBLIC KEY-----") {
		return parseRSAPublicKeyPEM([]byte(pathOrPEM))
	}

	// 2. File path passed via flag
	if pathOrPEM != "" {
		data, err := os.ReadFile(pathOrPEM)
		if err == nil {
			return parseRSAPublicKeyPEM(data)
		}
	}

	// 3. Environment variable CONTROL_PLANE_PUBLIC_KEY
	if envKey := os.Getenv("CONTROL_PLANE_PUBLIC_KEY"); envKey != "" {
		if strings.Contains(envKey, "-----BEGIN PUBLIC KEY-----") {
			return parseRSAPublicKeyPEM([]byte(envKey))
		}
		if data, err := os.ReadFile(envKey); err == nil {
			return parseRSAPublicKeyPEM(data)
		}
	}

	// 4. On-demand fetch from control plane endpoint (/api/fleet/public-key)
	fetchURL := fmt.Sprintf("%s/api/fleet/public-key", controlURL)
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key from %s: %w", fetchURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned HTTP %d for public key", resp.StatusCode)
	}

	var keyResp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, fmt.Errorf("failed to decode public key response: %w", err)
	}
	if keyResp.PublicKey == "" {
		return nil, fmt.Errorf("empty public key returned by control plane")
	}

	return parseRSAPublicKeyPEM([]byte(keyResp.PublicKey))
}

func dispatch(command, hostname string, handler *handlers.ActionHandler) (string, string, string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "failed", "empty command", ""
	}

	action := parts[0]
	switch action {
	case "isolate_host":
		mgmtCIDR := ""
		if len(parts) > 1 {
			mgmtCIDR = parts[1]
		}
		out, err := handler.IsolateHost(hostname, mgmtCIDR)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "restore_host":
		out, err := handler.RestoreHost(hostname)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "block_ip":
		if len(parts) < 2 {
			return "failed", "missing target IP address", ""
		}
		ip := parts[1]
		mgmtGateway := ""
		if len(parts) > 2 {
			mgmtGateway = parts[2]
		}
		out, err := handler.BlockIP(hostname, ip, mgmtGateway)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "kill_process":
		if len(parts) < 2 {
			return "failed", "missing target PID", ""
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return "failed", fmt.Sprintf("invalid PID '%s': %v", parts[1], err), ""
		}
		out, err := handler.KillProcess(hostname, pid)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "take_safety_snapshot":
		snapID, err := handler.TakeSafetySnapshot(hostname)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", fmt.Sprintf("Safety snapshot %s created on %s", snapID, hostname), snapID

	case "rollback_snapshot":
		targetSnap := ""
		if len(parts) > 1 {
			targetSnap = parts[1]
		}
		out, err := handler.Rollback(hostname, targetSnap)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "rolled_back", out, targetSnap

	default:
		return "failed", fmt.Sprintf("unrecognized command action: %s", action), ""
	}
}

func reportResult(client *http.Client, controlURL, commandID, status, output, snapshotID string) {
	reqURL := fmt.Sprintf("%s/api/agent/commands/%s/result", controlURL, commandID)
	payload := CommandResultPayload{
		Status:     status,
		Output:     output,
		SnapshotID: snapshotID,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}

	resp, err := client.Post(reqURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[CommandQueue] Failed to report result for command %s: %v", commandID, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("[CommandQueue] Reported result for command %s: status=%s", commandID, status)
}

type CertificatePayload struct {
	CertificatePEM    string `json:"certificatePem"`
	CACertificatePEM  string `json:"caCertificatePem"`
	SerialNumber      string `json:"serialNumber"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
	ExpiresAt         string `json:"expiresAt"`
	PrivateKeyPEM     string `json:"privateKeyPem,omitempty"`
}

type EnrollmentResponse struct {
	Success     bool                `json:"success"`
	AgentID     string              `json:"agentId"`
	TenantID    string              `json:"tenantId"`
	Certificate *CertificatePayload `json:"certificate,omitempty"`
	Error       string              `json:"error,omitempty"`
}

func enrollWithControlPlane(client *http.Client, controlURL, token, hostname string) (string, string, error) {
	osType := runtime.GOOS
	if osType != "windows" && osType != "darwin" {
		osType = "linux"
	}
	payload := map[string]string{
		"token":        token,
		"hostname":     hostname,
		"osType":       osType,
		"agentVersion": version,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Post(controlURL+"/api/agent/enroll", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", "", fmt.Errorf("network error during enrollment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("control plane rejected enrollment (status %d): %s", resp.StatusCode, string(body))
	}

	var enrollResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return "", "", fmt.Errorf("malformed enrollment response: %w", err)
	}
	if !enrollResp.Success || enrollResp.AgentID == "" {
		return "", "", fmt.Errorf("enrollment unsuccessful: %s", enrollResp.Error)
	}

	// Persist X.509 client certificate if issued by control plane (SD-008)
	if enrollResp.Certificate != nil && enrollResp.Certificate.CertificatePEM != "" {
		_ = os.WriteFile("agent.crt", []byte(enrollResp.Certificate.CertificatePEM), 0644)
		_ = os.WriteFile("ca.crt", []byte(enrollResp.Certificate.CACertificatePEM), 0644)
		if enrollResp.Certificate.PrivateKeyPEM != "" {
			_ = os.WriteFile("agent.key", []byte(enrollResp.Certificate.PrivateKeyPEM), 0600)
		}
		log.Printf("[Security] Issued X.509 client certificate for mTLS. Serial: %s | Fingerprint: %s",
			enrollResp.Certificate.SerialNumber, enrollResp.Certificate.FingerprintSHA256)
	}

	return enrollResp.AgentID, enrollResp.TenantID, nil
}

func sendHeartbeat(client *http.Client, controlURL, agentID, hostname string, cpu, mem float64, eps int) {
	payload := map[string]interface{}{
		"agentId":     agentID,
		"cpuUsage":    cpu,
		"memoryUsage": mem,
		"eps":         eps,
		"status":      "connected",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", controlURL+"/api/agent/heartbeat", bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ShieldDesk-Agent-ID", agentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 423 {
		log.Printf("[Heartbeat Alert] Kill switch is active for agent %s. Host commands blocked.", agentID)
	}
}

func flushTelemetry(client *http.Client, controlURL, agentID string, events []telemetry.Event) {
	if len(events) == 0 {
		return
	}
	payloadEvents := make([]map[string]interface{}, len(events))
	for i, e := range events {
		payloadEvents[i] = map[string]interface{}{
			"eventType": e.EventType,
			"payload":   e.Payload,
			"timestamp": e.Timestamp.Format(time.RFC3339),
		}
	}
	body := map[string]interface{}{
		"agentId": agentID,
		"events":  payloadEvents,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", controlURL+"/api/agent/telemetry", bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ShieldDesk-Agent-ID", agentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// BlockedIPRecord represents an IP contained either automatically or manually by SOC
type BlockedIPRecord struct {
	IP        string    `json:"ip"`
	TenantID  string    `json:"tenant_id"`
	BlockedAt time.Time `json:"blockedAt"`
	Reason    string    `json:"reason"`
	Attempts  int       `json:"attempts"`
}

// EgressBurst represents a burst of outbound network transmission
type EgressBurst struct {
	Timestamp int64   `json:"timestamp"`
	MB        float64 `json:"mb"`
}

// ThreatAlert represents an actionable security alert
type ThreatAlert struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Type           string    `json:"type"` // auth_failure | brute_force_spike | anomaly
	Severity       string    `json:"severity"` // critical | high | medium | low
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	TargetUser     string    `json:"targetUser"`
	ClientIP       string    `json:"clientIp"`
	FailureReason  string    `json:"failureReason"`
	AttemptsCount  int       `json:"attemptsCount"`
	IsBlocked      bool      `json:"isBlocked"`
	Status         string    `json:"status"` // active | acknowledged | resolved
	CreatedAt      time.Time `json:"createdAt"`
}

// AnomalyMetric represents a live evaluated 3-sigma baseline metric
type AnomalyMetric struct {
	Metric          string  `json:"metric"`
	Mean            float64 `json:"mean"`
	StdDev          float64 `json:"stdDev"`
	Threshold3Sigma float64 `json:"threshold_3sigma,omitempty"`
	Threshold2Sigma float64 `json:"threshold_2sigma,omitempty"`
	CurrentValue    float64 `json:"current_value"`
	IsAnomaly       bool    `json:"is_anomaly"`
	Unit            string  `json:"unit"`
}

// RuleItem represents a YARA or Sigma detection rule descriptor
type RuleItem struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Title          string `json:"title,omitempty"`
	Category       string `json:"category,omitempty"`
	Logsource      string `json:"logsource,omitempty"`
	Severity       string `json:"severity"`
	MatchesToday   int    `json:"matches_today"`
	Status         string `json:"status"`
	Target         string `json:"target,omitempty"`
	Description    string `json:"description,omitempty"`
	DetectionLogic string `json:"detection_logic,omitempty"`
}

// MultiTenantThreatStore maintains in-memory sliding windows and tenant-scoped containment state
type MultiTenantThreatStore struct {
	mu                sync.RWMutex
	failureTimestamps []int64
	sudoTimestamps    []int64
	egressBursts      []EgressBurst
	// tenantID -> ip -> BlockedIPRecord
	blockedIPs map[string]map[string]*BlockedIPRecord
	// tenantID -> []ThreatAlert
	alerts map[string][]*ThreatAlert
}

func NewMultiTenantThreatStore() *MultiTenantThreatStore {
	return &MultiTenantThreatStore{
		failureTimestamps: make([]int64, 0),
		sudoTimestamps:    make([]int64, 0),
		egressBursts:      make([]EgressBurst, 0),
		blockedIPs:        make(map[string]map[string]*BlockedIPRecord),
		alerts:            make(map[string][]*ThreatAlert),
	}
}

// RecordFailureTimestamp adds failed authentication attempt(s)
func (s *MultiTenantThreatStore) RecordFailureTimestamp(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	for i := 0; i < count; i++ {
		s.failureTimestamps = append(s.failureTimestamps, now)
	}
}

// GetLiveFailureRate returns failures in the last 60 seconds
func (s *MultiTenantThreatStore) GetLiveFailureRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second).UnixMilli()

	valid := make([]int64, 0, len(s.failureTimestamps))
	for _, ts := range s.failureTimestamps {
		if ts > cutoff {
			valid = append(valid, ts)
		}
	}
	s.failureTimestamps = valid
	return float64(len(valid))
}

// RecordSudoExecution records sudo execution count(s)
func (s *MultiTenantThreatStore) RecordSudoExecution(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	for i := 0; i < count; i++ {
		s.sudoTimestamps = append(s.sudoTimestamps, now)
	}
}

// GetLiveSudoRate returns sudo commands in the last 60 seconds
func (s *MultiTenantThreatStore) GetLiveSudoRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second).UnixMilli()

	valid := make([]int64, 0, len(s.sudoTimestamps))
	for _, ts := range s.sudoTimestamps {
		if ts > cutoff {
			valid = append(valid, ts)
		}
	}
	s.sudoTimestamps = valid
	return float64(len(valid))
}

// RecordNetworkEgress logs outbound egress burst in MB
func (s *MultiTenantThreatStore) RecordNetworkEgress(mb float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egressBursts = append(s.egressBursts, EgressBurst{
		Timestamp: time.Now().UnixMilli(),
		MB:        mb,
	})
}

// GetLiveEgressRate returns egress rate in MB/min over the last 60 seconds
func (s *MultiTenantThreatStore) GetLiveEgressRate() (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second).UnixMilli()

	valid := make([]EgressBurst, 0, len(s.egressBursts))
	totalMB := 0.0
	for _, burst := range s.egressBursts {
		if burst.Timestamp > cutoff {
			valid = append(valid, burst)
			totalMB += burst.MB
		}
	}
	s.egressBursts = valid
	isAnomaly := totalMB > 215.0
	return totalMB, isAnomaly
}

// BlockIP blocks an IP for a specific tenant
func (s *MultiTenantThreatStore) BlockIP(tenantID, ip, reason string) *BlockedIPRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "::1" || cleanIP == "" {
		cleanIP = "127.0.0.1"
	}

	if _, exists := s.blockedIPs[tenantID]; !exists {
		s.blockedIPs[tenantID] = make(map[string]*BlockedIPRecord)
	}

	rec, exists := s.blockedIPs[tenantID][cleanIP]
	if exists {
		rec.Attempts++
		rec.Reason = reason
		return rec
	}

	rec = &BlockedIPRecord{
		IP:        cleanIP,
		TenantID:  tenantID,
		BlockedAt: time.Now().UTC(),
		Reason:    reason,
		Attempts:  5,
	}
	s.blockedIPs[tenantID][cleanIP] = rec
	return rec
}

// UnblockIP unblocks an IP for a specific tenant
func (s *MultiTenantThreatStore) UnblockIP(tenantID, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "::1" || cleanIP == "" {
		cleanIP = "127.0.0.1"
	}

	if tenantMap, exists := s.blockedIPs[tenantID]; exists {
		if _, found := tenantMap[cleanIP]; found {
			delete(tenantMap, cleanIP)
			return true
		}
	}
	return false
}

// GetBlockedIPs returns all blocked IPs for a given tenant
func (s *MultiTenantThreatStore) GetBlockedIPs(tenantID string) []*BlockedIPRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*BlockedIPRecord, 0)
	if tenantMap, exists := s.blockedIPs[tenantID]; exists {
		for _, rec := range tenantMap {
			results = append(results, rec)
		}
	}
	return results
}

// IsIPBlocked checks if an IP is blocked for a specific tenant
func (s *MultiTenantThreatStore) IsIPBlocked(tenantID, ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "::1" || cleanIP == "" {
		cleanIP = "127.0.0.1"
	}

	if tenantMap, exists := s.blockedIPs[tenantID]; exists {
		_, blocked := tenantMap[cleanIP]
		return blocked
	}
	return false
}

// RecordAlert records a threat alert in memory for a tenant
func (s *MultiTenantThreatStore) RecordAlert(tenantID string, alert *ThreatAlert) *ThreatAlert {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now().UTC()
	}
	if alert.Status == "" {
		alert.Status = "active"
	}

	s.alerts[tenantID] = append([]*ThreatAlert{alert}, s.alerts[tenantID]...)
	if len(s.alerts[tenantID]) > 100 {
		s.alerts[tenantID] = s.alerts[tenantID][:100]
	}
	return alert
}

// GetAlerts returns threat alerts for a tenant
func (s *MultiTenantThreatStore) GetAlerts(tenantID string) []*ThreatAlert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := s.alerts[tenantID]
	if list == nil {
		return []*ThreatAlert{}
	}
	return list
}

// AcknowledgeAlert updates the status of an alert to acknowledged
func (s *MultiTenantThreatStore) AcknowledgeAlert(tenantID, alertID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range s.alerts[tenantID] {
		if a.ID == alertID {
			a.Status = "acknowledged"
			return true
		}
	}
	return false
}

// Reset clears sliding windows and tenant containment state
func (s *MultiTenantThreatStore) Reset(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failureTimestamps = make([]int64, 0)
	s.sudoTimestamps = make([]int64, 0)
	s.egressBursts = make([]EgressBurst, 0)

	if tenantID != "" {
		delete(s.blockedIPs, tenantID)
		delete(s.alerts, tenantID)
	} else {
		s.blockedIPs = make(map[string]map[string]*BlockedIPRecord)
		s.alerts = make(map[string][]*ThreatAlert)
	}
}

// ResetAnomalies clears only the sliding-window anomaly telemetry rates back to nominal
func (s *MultiTenantThreatStore) ResetAnomalies() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failureTimestamps = make([]int64, 0)
	s.sudoTimestamps = make([]int64, 0)
	s.egressBursts = make([]EgressBurst, 0)
}

// HTTPServer provides the REST API for the Next.js BFF and remote clients
type HTTPServer struct {
	port   int
	store  *MultiTenantThreatStore
	engine *ThreatEngine
}

func NewHTTPServer(port int, engine *ThreatEngine) *HTTPServer {
	return &HTTPServer{
		port:   port,
		store:  NewMultiTenantThreatStore(),
		engine: engine,
	}
}

func (h *HTTPServer) Start() error {
	mux := http.NewServeMux()

	// 1. Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"service":  "shielddesk-threat-go",
			"version":  "1.0.0",
			"engine":   "go1.27",
			"time_utc": time.Now().UTC(),
		})
	})

	// 2. Main Threat State Endpoint (Queried by /api/threats)
	mux.HandleFunc("GET /api/threats/state", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			tenantID = "acme-tenant"
		}

		liveFailureRate := h.store.GetLiveFailureRate()
		liveSudoRate := h.store.GetLiveSudoRate()
		liveEgressRate, isEgressAnomaly := h.store.GetLiveEgressRate()

		yaraRules := []RuleItem{
			{
				ID:           "YARA-MAL-001",
				Name:         "WebShell_C99_PHP",
				Category:     "Malware / Webshell",
				Severity:     "CRITICAL",
				MatchesToday: 3,
				Status:       "ACTIVE",
				Target:       "filesystem / webroot",
				Description:  "Detects obfuscated PHP C99/b374k webshell headers, base64_decode, and passthru command execution payloads.",
			},
			{
				ID:           "YARA-MAL-002",
				Name:         "Ransomware_LockBit_Indicators",
				Category:     "Ransomware",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "filesystem write operations",
				Description:  "Detects mass extension renaming (.lockbit, .blackcat) and automated shadow copy deletion commands.",
			},
			{
				ID:           "YARA-MAL-003",
				Name:         "Cobalt_Strike_Beacon_Memory",
				Category:     "C2 / Post-Exploitation",
				Severity:     "HIGH",
				MatchesToday: 1,
				Status:       "ACTIVE",
				Target:       "process memory",
				Description:  "Detects known Cobalt Strike malleable C2 reflective DLL loader memory patterns.",
			},
			{
				ID:           "YARA-MAL-004",
				Name:         "Log4j_JNDI_Exploit_Strings",
				Category:     "Exploit / Initial Access",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "inbound HTTP / log stream",
				Description:  "Detects Log4j JNDI injection attack strings in requests and logs.",
			},
			{
				ID:           "YARA-MAL-005",
				Name:         "Mimikatz_Credential_Dumping",
				Category:     "Credential Access",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "process memory / LSASS",
				Description:  "Detects Mimikatz sekurlsa and logonpasswords memory artifact signatures.",
			},
		}

		sigmaRules := []RuleItem{
			{
				ID:             "sigma_encoded_powershell",
				Title:          "Suspicious Encoded PowerShell Execution",
				Logsource:      "windows: process_creation",
				Severity:       "HIGH",
				MatchesToday:   4,
				Status:         "ACTIVE",
				DetectionLogic: "CommandLine matches -enc / -EncodedCommand with bypass execution policy.",
			},
			{
				ID:             "sigma_ssh_bruteforce",
				Title:          "SSH Distributed Brute Force Attempt",
				Logsource:      "linux: auth.log / sshd",
				Severity:       "MEDIUM",
				MatchesToday:   28,
				Status:         "ACTIVE",
				DetectionLogic: "More than 15 failed password authentications from single source IP within 60s window.",
			},
			{
				ID:             "sigma_shadow_copy_deletion",
				Title:          "VSS Volume Shadow Copy Deletion",
				Logsource:      "windows: vssadmin",
				Severity:       "CRITICAL",
				MatchesToday:   0,
				Status:         "ACTIVE",
				DetectionLogic: "vssadmin.exe delete shadows /all /quiet or wmic shadowcopy delete.",
			},
		}

		anomalyBaselines := []AnomalyMetric{
			{
				Metric:          "Failed Authentications / Min",
				Mean:            4.2,
				StdDev:          2.1,
				Threshold3Sigma: 10.5,
				CurrentValue:    liveFailureRate,
				IsAnomaly:       liveFailureRate > 10.5,
				Unit:            "attempts/min",
			},
			{
				Metric:          "Outbound Network Egress Rate",
				Mean:            84.5,
				StdDev:          65.2,
				Threshold2Sigma: 215.0,
				CurrentValue:    liveEgressRate,
				IsAnomaly:       isEgressAnomaly,
				Unit:            "MB/min",
			},
			{
				Metric:          "Sudo Execution Frequency",
				Mean:            1.1,
				StdDev:          0.8,
				Threshold3Sigma: 3.5,
				CurrentValue:    liveSudoRate,
				IsAnomaly:       liveSudoRate > 3.5,
				Unit:            "exec/min",
			},
		}

		blockedIPs := h.store.GetBlockedIPs(tenantID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"source":            "go-threat-service",
			"tenant_id":         tenantID,
			"yara_rules":        yaraRules,
			"sigma_rules":       sigmaRules,
			"anomaly_baselines": anomalyBaselines,
			"blocked_ips":       blockedIPs,
			"timestamp":         time.Now().UTC(),
		})
	})

	// 3. Containment Actions (Block / Unblock IP)
	mux.HandleFunc("POST /api/threats/containment", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action   string `json:"action"` // block_ip | unblock_ip
			TenantID string `json:"tenant_id"`
			IP       string `json:"ip"`
			Reason   string `json:"reason"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
			return
		}

		if req.TenantID == "" {
			req.TenantID = "acme-tenant"
		}
		if req.IP == "" {
			http.Error(w, `{"error":"ip address is required"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if req.Action == "unblock_ip" {
			unblocked := h.store.UnblockIP(req.TenantID, req.IP)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":     true,
				"action":      "unblock_ip",
				"unblocked":   unblocked,
				"ip":          req.IP,
				"blocked_ips": h.store.GetBlockedIPs(req.TenantID),
			})
			return
		}

		// Default: block_ip
		reason := req.Reason
		if reason == "" {
			reason = "Manual containment initiated via SOC console"
		}
		rec := h.store.BlockIP(req.TenantID, req.IP, reason)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"action":      "block_ip",
			"record":      rec,
			"ip":          req.IP,
			"blocked_ips": h.store.GetBlockedIPs(req.TenantID),
		})
	})

	// 4. Burst Simulation
	mux.HandleFunc("POST /api/threats/simulate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type     string  `json:"type"` // auth_failure | sudo_burst | egress_spike
			TenantID string  `json:"tenant_id"`
			Count    int     `json:"count"`
			MB       float64 `json:"mb"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
			return
		}

		if req.TenantID == "" {
			req.TenantID = "acme-tenant"
		}

		switch req.Type {
		case "auth_failure":
			cnt := req.Count
			if cnt <= 0 {
				cnt = 15
			}
			h.store.RecordFailureTimestamp(cnt)
		case "sudo_burst":
			cnt := req.Count
			if cnt <= 0 {
				cnt = 6
			}
			h.store.RecordSudoExecution(cnt)
		case "egress_spike":
			mb := req.MB
			if mb <= 0 {
				mb = 350.0
			}
			h.store.RecordNetworkEgress(mb)
		default:
			// Trigger all three as a massive security incident drill
			h.store.RecordFailureTimestamp(18)
			h.store.RecordSudoExecution(8)
			h.store.RecordNetworkEgress(380.0)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"type":    req.Type,
			"message": "Telemetry anomaly simulated in Go engine",
			"rates": map[string]interface{}{
				"failures_per_min": h.store.GetLiveFailureRate(),
				"sudo_per_min":     h.store.GetLiveSudoRate(),
			},
		})
	})

	// 5. Reset Baselines
	mux.HandleFunc("POST /api/threats/reset", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TenantID         string `json:"tenant_id"`
			ClearContainment bool   `json:"clear_containment"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ClearContainment {
			h.store.Reset(req.TenantID)
		} else {
			h.store.ResetAnomalies()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Anomaly baselines reset in Go engine",
		})
	})

	// 6. Check if an IP is blocked for a tenant
	mux.HandleFunc("GET /api/threats/is-blocked", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			tenantID = "acme-tenant"
		}

		isBlocked := h.store.IsIPBlocked(tenantID, ip)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":         ip,
			"tenant_id":  tenantID,
			"is_blocked": isBlocked,
		})
	})

	// 7. Record a Threat Alert
	mux.HandleFunc("POST /api/threats/alerts", func(w http.ResponseWriter, r *http.Request) {
		var alert ThreatAlert
		if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
			http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
			return
		}
		if alert.TenantID == "" {
			alert.TenantID = "acme-tenant"
		}

		created := h.store.RecordAlert(alert.TenantID, &alert)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created)
	})

	// 8. List Alerts
	mux.HandleFunc("GET /api/threats/alerts", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			tenantID = "acme-tenant"
		}

		alerts := h.store.GetAlerts(tenantID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"tenant_id": tenantID,
			"alerts":    alerts,
		})
	})

	// 9. Acknowledge Alert
	mux.HandleFunc("POST /api/threats/alerts/ack", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TenantID string `json:"tenant_id"`
			AlertID  string `json:"alert_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
			return
		}
		if req.TenantID == "" {
			req.TenantID = "acme-tenant"
		}

		success := h.store.AcknowledgeAlert(req.TenantID, req.AlertID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   success,
			"alert_id":  req.AlertID,
			"tenant_id": req.TenantID,
		})
	})

	// 10. Native YARA Rules & Match Stats (SD-027)
	mux.HandleFunc("GET /api/threats/yara", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			tenantID = "acme-tenant"
		}

		rules := []RuleItem{
			{
				ID:           "YARA-MAL-001",
				Name:         "WebShell_C99_PHP",
				Category:     "Malware / Webshell",
				Severity:     "CRITICAL",
				MatchesToday: 3,
				Status:       "ACTIVE",
				Target:       "filesystem / webroot",
				Description:  "Detects obfuscated PHP C99/b374k webshell headers, base64_decode, and passthru command execution payloads.",
			},
			{
				ID:           "YARA-MAL-002",
				Name:         "Ransomware_LockBit_Indicators",
				Category:     "Ransomware",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "filesystem write operations",
				Description:  "Detects mass extension renaming (.lockbit, .blackcat) and automated shadow copy deletion commands.",
			},
			{
				ID:           "YARA-MAL-003",
				Name:         "Cobalt_Strike_Beacon_Memory",
				Category:     "C2 / Post-Exploitation",
				Severity:     "HIGH",
				MatchesToday: 1,
				Status:       "ACTIVE",
				Target:       "process memory",
				Description:  "Detects known Cobalt Strike malleable C2 reflective DLL loader memory patterns.",
			},
			{
				ID:           "YARA-MAL-004",
				Name:         "Log4j_JNDI_Exploit_Strings",
				Category:     "Exploit / Initial Access",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "inbound HTTP / log stream",
				Description:  "Detects Log4j JNDI injection attack strings in requests and logs.",
			},
			{
				ID:           "YARA-MAL-005",
				Name:         "Mimikatz_Credential_Dumping",
				Category:     "Credential Access",
				Severity:     "CRITICAL",
				MatchesToday: 0,
				Status:       "ACTIVE",
				Target:       "process memory / LSASS",
				Description:  "Detects Mimikatz sekurlsa and logonpasswords memory artifact signatures.",
			},
		}

		totalMatches := 0
		for _, r := range rules {
			totalMatches += r.MatchesToday
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":              "ok",
			"source":              "go-threat-service",
			"tenant_id":           tenantID,
			"yara_rules":          rules,
			"total_rules":         len(rules),
			"matches_today_total": totalMatches,
			"timestamp":           time.Now().UTC(),
		})
	})

	addr := fmt.Sprintf(":%d", h.port)
	log.Info().Int("port", h.port).Msg("[ThreatEngine] Starting Go HTTP REST API server...")
	return http.ListenAndServe(addr, mux)
}

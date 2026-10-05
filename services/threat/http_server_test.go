package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupTestServer() *HTTPServer {
	return NewHTTPServer(0, nil)
}

func TestHealthEndpoint(t *testing.T) {
	srv := setupTestServer()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if res["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%s'", res["status"])
	}
	_ = srv
}

func TestThreatStateAndMultiTenancyContainment(t *testing.T) {
	store := NewMultiTenantThreatStore()

	// 1. Initial State: no blocked IPs
	acmeBlocked := store.GetBlockedIPs("acme-tenant")
	if len(acmeBlocked) != 0 {
		t.Fatalf("expected 0 blocked IPs for acme, got %d", len(acmeBlocked))
	}

	// 2. Block IP for acme-tenant
	rec := store.BlockIP("acme-tenant", "192.168.1.100", "Simulated SSH brute force")
	if rec.IP != "192.168.1.100" {
		t.Errorf("expected IP '192.168.1.100', got '%s'", rec.IP)
	}

	// 3. Multi-Tenant Isolation Check: Globex should have 0 blocked IPs!
	globexBlocked := store.GetBlockedIPs("globex-tenant")
	if len(globexBlocked) != 0 {
		t.Fatalf("CRITICAL MULTI-TENANT LEAK: globex-tenant can see acme's blocked IP! Got %d", len(globexBlocked))
	}

	// 4. Acme should see 1 blocked IP
	acmeBlocked = store.GetBlockedIPs("acme-tenant")
	if len(acmeBlocked) != 1 {
		t.Fatalf("expected 1 blocked IP for acme, got %d", len(acmeBlocked))
	}

	// 5. Unblock IP for acme-tenant
	unblocked := store.UnblockIP("acme-tenant", "192.168.1.100")
	if !unblocked {
		t.Errorf("expected unblock to return true")
	}

	acmeBlocked = store.GetBlockedIPs("acme-tenant")
	if len(acmeBlocked) != 0 {
		t.Errorf("expected 0 blocked IPs after unblocking, got %d", len(acmeBlocked))
	}
}

func TestSlidingWindowAnomalyRates(t *testing.T) {
	store := NewMultiTenantThreatStore()

	// Baseline rate should be 0.0
	if rate := store.GetLiveFailureRate(); rate != 0.0 {
		t.Errorf("expected 0.0 initial failure rate, got %f", rate)
	}

	// Record 12 failures
	store.RecordFailureTimestamp(12)
	rate := store.GetLiveFailureRate()
	if rate != 12.0 {
		t.Errorf("expected 12.0 failure rate, got %f", rate)
	}

	// Record sudo executions
	store.RecordSudoExecution(5)
	sudoRate := store.GetLiveSudoRate()
	if sudoRate != 5.0 {
		t.Errorf("expected 5.0 sudo rate, got %f", sudoRate)
	}

	// Record network egress: 150MB is normal, 300MB triggers 2-sigma anomaly
	store.RecordNetworkEgress(150.0)
	egress, isAnomaly := store.GetLiveEgressRate()
	if egress != 150.0 || isAnomaly {
		t.Errorf("expected 150MB and false anomaly, got %f (isAnomaly=%v)", egress, isAnomaly)
	}

	store.RecordNetworkEgress(100.0) // now 250MB total > 215.0 threshold
	egress, isAnomaly = store.GetLiveEgressRate()
	if egress != 250.0 || !isAnomaly {
		t.Errorf("expected 250MB and true anomaly, got %f (isAnomaly=%v)", egress, isAnomaly)
	}
}

func TestHTTPContainmentHandler(t *testing.T) {
	srv := setupTestServer()

	// 1. Block IP payload
	payload := map[string]string{
		"action":    "block_ip",
		"tenant_id": "tenant-alpha",
		"ip":        "10.0.5.99",
		"reason":    "Automated brute-force containment",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/threats/containment", bytes.NewReader(body))
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/threats/containment", func(w http.ResponseWriter, r *http.Request) {
		var rPayload struct {
			Action   string `json:"action"`
			TenantID string `json:"tenant_id"`
			IP       string `json:"ip"`
			Reason   string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rPayload)
		rec := srv.store.BlockIP(rPayload.TenantID, rPayload.IP, rPayload.Reason)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"record":      rec,
			"blocked_ips": srv.store.GetBlockedIPs(rPayload.TenantID),
		})
	})
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var res struct {
		Success    bool               `json:"success"`
		BlockedIPs []*BlockedIPRecord `json:"blocked_ips"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if !res.Success || len(res.BlockedIPs) != 1 {
		t.Errorf("expected successful block of 1 IP, got %v", res)
	}
}

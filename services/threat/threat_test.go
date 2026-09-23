package main

import (
	"context"
	"testing"
	"time"
)

func TestThreatDetectionPipeline(t *testing.T) {
	engine, err := NewThreatEngine("", "")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	ctx := context.Background()

	// 1. Test YARA Ransomware Rule Matching
	fileEvent := &IngestEvent{
		TenantId:  "acme_tenant",
		AssetId:   "ws-fin-01",
		EventType: "file",
		Timestamp: time.Now().UnixMilli(),
		Payload: map[string]string{
			"file_name": "important_records.xlsx.wannacry",
			"file_path": "C:\\Users\\Finance\\Documents\\important_records.xlsx.wannacry",
		},
	}
	alert1 := engine.ProcessEvent(ctx, fileEvent)
	if alert1 == nil {
		t.Errorf("Expected YARA ransomware alert, got nil")
	} else if alert1.Severity != "critical" || alert1.RuleID != "YARA-MAL-002" {
		t.Errorf("Unexpected alert details: %+v", alert1)
	}

	// 2. Test Sigma Encoded PowerShell Rule Matching
	procEvent := &IngestEvent{
		TenantId:  "acme_tenant",
		AssetId:   "srv-dc-01",
		EventType: "process",
		Timestamp: time.Now().UnixMilli(),
		Payload: map[string]string{
			"process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAag...",
		},
	}
	alert2 := engine.ProcessEvent(ctx, procEvent)
	if alert2 == nil {
		t.Errorf("Expected Sigma encoded powershell alert, got nil")
	} else if alert2.Severity != "high" || alert2.RuleID != "SIGMA-PROC-001" {
		t.Errorf("Unexpected alert details: %+v", alert2)
	}

	// 3. Test Sigma Brute Force Login Matching
	authBruteEvent := &IngestEvent{
		TenantId:  "acme_tenant",
		AssetId:   "srv-bastion-01",
		EventType: "auth",
		Timestamp: time.Now().UnixMilli(),
		Payload: map[string]string{
			"action":       "failed_login",
			"username":     "root",
			"source_ip":    "198.51.100.24",
			"failed_count": "6",
		},
	}
	alert3 := engine.ProcessEvent(ctx, authBruteEvent)
	if alert3 == nil {
		t.Errorf("Expected Sigma brute force alert, got nil")
	} else if alert3.RuleID != "SIGMA-AUTH-002" {
		t.Errorf("Unexpected alert details: %+v", alert3)
	}

	// 4. Test ML Anomaly Scoring (Off-hours login at 3 AM UTC, baseline is 13:00 UTC)
	// 3:00 is 10 hours diff from 13:00, stddev is 3.0 -> 10/3 = 3.33 sigma (> 3 sigma)
	threeAM := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC).UnixMilli()
	authAnomalyEvent := &IngestEvent{
		TenantId:  "acme_tenant",
		AssetId:   "ws-dev-42",
		EventType: "auth",
		Timestamp: threeAM,
		Payload: map[string]string{
			"action":   "successful_login",
			"username": "alice",
		},
	}
	alert4 := engine.ProcessEvent(ctx, authAnomalyEvent)
	if alert4 == nil {
		t.Errorf("Expected 3-sigma anomaly alert, got nil")
	} else if alert4.Type != "anomaly" || alert4.RuleID != "ML-ANOMALY-AUTH-3SIGMA" {
		t.Errorf("Unexpected anomaly alert details: %+v", alert4)
	}

	// 5. Test Network Spike Anomaly (> 2 sigma)
	netEvent := &IngestEvent{
		TenantId:  "acme_tenant",
		AssetId:   "ws-dev-42",
		EventType: "network",
		Timestamp: time.Now().UnixMilli(),
		Payload: map[string]string{
			"bytes_out": "15000", // Baseline is 5000, stddev is 2000 -> (15000-5000)/2000 = 5 sigma (> 2 sigma)
			"dest_ip":   "203.0.113.88",
		},
	}
	alert5 := engine.ProcessEvent(ctx, netEvent)
	if alert5 == nil {
		t.Errorf("Expected 2-sigma network anomaly alert, got nil")
	} else if alert5.Type != "anomaly" || alert5.RuleID != "ML-ANOMALY-NET-2SIGMA" {
		t.Errorf("Unexpected network anomaly alert details: %+v", alert5)
	}
}

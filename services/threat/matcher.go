package main

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// YARAMatcher performs pattern scanning on file events
type YARAMatcher struct{}

func NewYARAMatcher() *YARAMatcher {
	return &YARAMatcher{}
}

// MatchFileEvent checks file event payloads against known malware indicators
func (m *YARAMatcher) MatchFileEvent(event *IngestEvent) *Alert {
	filePath := strings.ToLower(event.Payload["file_path"])
	fileContent := event.Payload["content_preview"]
	fileName := strings.ToLower(event.Payload["file_name"])

	// 1. Ransomware extension check
	ransomExts := []string{".locky", ".cryptolocker", ".wannacry", ".blackcat"}
	for _, ext := range ransomExts {
		if strings.HasSuffix(fileName, ext) || strings.HasSuffix(filePath, ext) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-002",
				RuleName:  "SuspiciousRansomwareExtension",
				Payload:   map[string]interface{}{"file": filePath, "indicator": ext},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	// 2. Webshell / reverse shell string detection
	shellIndicators := []string{
		"c3lzdGVtKCRfR0VUWydjbWQnXS",
		"/bin/sh -i >& /dev/tcp/",
		"nc -e /bin/sh",
		"invoke-mimikatz",
		"sekurlsa::logonpasswords",
	}

	lowerContent := strings.ToLower(fileContent)
	for _, ind := range shellIndicators {
		if strings.Contains(lowerContent, ind) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-001",
				RuleName:  "SuspiciousWebshellStrings",
				Payload:   map[string]interface{}{"file": filePath, "indicator": ind},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	return nil
}

// SigmaMatcher evaluates process creation and authentication telemetry against behavioral rules
type SigmaMatcher struct{}

func NewSigmaMatcher() *SigmaMatcher {
	return &SigmaMatcher{}
}

func (m *SigmaMatcher) MatchProcessOrAuthEvent(event *IngestEvent) *Alert {
	// Process Creation
	if event.EventType == "process" {
		cmdLine := strings.ToLower(event.Payload["command_line"])
		processPath := strings.ToLower(event.Payload["process_path"])

		isPowerShell := strings.HasSuffix(processPath, "powershell.exe") || strings.HasSuffix(processPath, "pwsh.exe") || strings.Contains(cmdLine, "powershell")
		if isPowerShell {
			encodedPatterns := []string{" -enc ", " -encodedcommand ", "frombase64string", "downloadstring", "iex("}
			for _, pat := range encodedPatterns {
				if strings.Contains(cmdLine, pat) {
					return &Alert{
						ID:        uuid.New().String(),
						TenantID:  event.TenantId,
						AssetID:   event.AssetId,
						Severity:  "high",
						Type:      "intrusion",
						RuleID:    "SIGMA-PROC-001",
						RuleName:  "Suspicious PowerShell Encoded Command Execution",
						Payload:   map[string]interface{}{"command": cmdLine, "process": processPath},
						CreatedAt: time.Now().UTC(),
					}
				}
			}
		}
	}

	// Auth Events
	if event.EventType == "auth" {
		action := strings.ToLower(event.Payload["action"])
		if action == "failed_login" || action == "failed_auth" {
			failedCount := event.Payload["failed_count"]
			if failedCount >= "5" {
				return &Alert{
					ID:        uuid.New().String(),
					TenantID:  event.TenantId,
					AssetID:   event.AssetId,
					Severity:  "medium",
					Type:      "intrusion",
					RuleID:    "SIGMA-AUTH-002",
					RuleName:  "Multiple Failed Authentication Attempts (Brute Force)",
					Payload:   map[string]interface{}{"user": event.Payload["username"], "ip": event.Payload["source_ip"]},
					CreatedAt: time.Now().UTC(),
				}
			}
		}
	}

	return nil
}

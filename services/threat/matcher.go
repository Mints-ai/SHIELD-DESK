package main

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// YARAMatcher performs pattern scanning on file, process memory, and telemetry events
type YARAMatcher struct{}

func NewYARAMatcher() *YARAMatcher {
	return &YARAMatcher{}
}

// MatchFileEvent checks file event payloads against known malware indicators
func (m *YARAMatcher) MatchFileEvent(event *IngestEvent) *Alert {
	return m.MatchEvent(event)
}

// MatchEvent evaluates arbitrary security events against compiled YARA patterns
func (m *YARAMatcher) MatchEvent(event *IngestEvent) *Alert {
	filePath := strings.ToLower(event.Payload["file_path"])
	fileContent := event.Payload["content_preview"]
	if fileContent == "" {
		fileContent = event.Payload["content"]
	}
	if fileContent == "" {
		fileContent = event.Payload["payload"]
	}
	if fileContent == "" {
		fileContent = event.Payload["command_line"]
	}
	fileName := strings.ToLower(event.Payload["file_name"])
	lowerContent := strings.ToLower(fileContent)

	// 1. YARA-MAL-002: Ransomware Extensions & Encryption Notes
	ransomExts := []string{".locky", ".cryptolocker", ".wannacry", ".blackcat", ".lockbit"}
	for _, ext := range ransomExts {
		if strings.HasSuffix(fileName, ext) || strings.HasSuffix(filePath, ext) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-002",
				RuleName:  "Ransomware_LockBit_Indicators",
				Payload:   map[string]interface{}{"file": filePath, "indicator": ext},
				CreatedAt: time.Now().UTC(),
			}
		}
	}
	if strings.Contains(lowerContent, "all your files have been encrypted") || strings.Contains(lowerContent, "lockbit 3.0") {
		return &Alert{
			ID:        uuid.New().String(),
			TenantID:  event.TenantId,
			AssetID:   event.AssetId,
			Severity:  "critical",
			Type:      "malware",
			RuleID:    "YARA-MAL-002",
			RuleName:  "Ransomware_LockBit_Indicators",
			Payload:   map[string]interface{}{"file": filePath, "indicator": "encryption_note"},
			CreatedAt: time.Now().UTC(),
		}
	}

	// 2. YARA-MAL-001: Webshell / Reverse Shell String Detection
	shellIndicators := []string{
		"c3lzdGVtKCRfr0vtwydjmdjxs", // base64 system($_GET['cmd'])
		"/bin/sh -i >& /dev/tcp/",
		"nc -e /bin/sh",
		"c99shell",
		"b374k",
		"passthru($_post",
	}
	for _, ind := range shellIndicators {
		if strings.Contains(lowerContent, strings.ToLower(ind)) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-001",
				RuleName:  "WebShell_C99_PHP",
				Payload:   map[string]interface{}{"file": filePath, "indicator": ind},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	// 3. YARA-MAL-003: Cobalt Strike Beacon Memory Patterns
	cobaltIndicators := []string{
		"reflectiveloader",
		`\\.\pipe\status_`,
		"%s as %s\\%s: %d",
	}
	for _, ind := range cobaltIndicators {
		if strings.Contains(lowerContent, strings.ToLower(ind)) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "high",
				Type:      "malware",
				RuleID:    "YARA-MAL-003",
				RuleName:  "Cobalt_Strike_Beacon_Memory",
				Payload:   map[string]interface{}{"target": filePath, "indicator": ind},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	// 4. YARA-MAL-004: Log4j JNDI Exploit Strings
	log4jIndicators := []string{
		"${jndi:ldap://",
		"${jndi:rmi://",
		"${jndi:dns://",
		"${lower:j}${lower:n}${lower:d}${lower:i}",
	}
	for _, ind := range log4jIndicators {
		if strings.Contains(lowerContent, strings.ToLower(ind)) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-004",
				RuleName:  "Log4j_JNDI_Exploit_Strings",
				Payload:   map[string]interface{}{"target": filePath, "indicator": ind},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	// 5. YARA-MAL-005: Mimikatz Credential Dumping
	mimikatzIndicators := []string{
		"sekurlsa::logonpasswords",
		"lsadump::sam",
		"privilege::debug",
		"mimilib.dll",
		"invoke-mimikatz",
	}
	for _, ind := range mimikatzIndicators {
		if strings.Contains(lowerContent, strings.ToLower(ind)) {
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "critical",
				Type:      "malware",
				RuleID:    "YARA-MAL-005",
				RuleName:  "Mimikatz_Credential_Dumping",
				Payload:   map[string]interface{}{"target": filePath, "indicator": ind},
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

# Threat Detection Engine

**URL:** `/dashboard/threats`

The real-time detection engine. Four tabs:

## Tab 1: 3-Sigma ML Anomaly Engine

ShieldDesk builds a statistical baseline (Gaussian distribution) per metric per tenant. When a live value exceeds 3 standard deviations above normal (3σ), an alert fires automatically.

**Tracked metrics:**
- Failed authentication rate (brute-force indicator)
- Network egress bandwidth (data exfiltration indicator)
- Process spawn rate (malware execution indicator)

Each metric card shows current value vs. threshold, a progress bar (turns red when anomalous), and the baseline mean (μ) and deviation (σ).

**Status badges:**
- `NOMINAL` — value is within normal bounds
- `SPIKE ANOMALY` — threshold exceeded; alert dispatched

Click **"Simulate Anomaly Burst"** to test your alerting integrations. Click **"Reset Baseline"** to restore normal state.

---

## Tab 2: YARA Malware Rules

Scan file artefacts and process memory for known malware signatures. Cards show:
- Rule name and malware category
- Severity level
- Daily match count
- Target inspection zone

---

## Tab 3: Sigma Behavioral Detection

Detect suspicious log patterns (lateral movement, privilege escalation, living-off-the-land attacks). Cards show title, severity, detection logic, log source, and daily match count.

---

## Tab 4: gRPC Ingestion & HMAC Webhooks

**Ingest pipeline:**
- Protocol: `mTLS v1.3` with X.509 certificates
- Rate limit: 10,000 events/minute per tenant
- PII scrubbing: credentials and tokens redacted before storage

**Webhook dispatcher:** Click **"Dispatch Test Webhook"** to send a signed test payload to Slack, PagerDuty, or any configured endpoint. All payloads carry an `HMAC-SHA256` signature. Failed deliveries retry with exponential backoff.

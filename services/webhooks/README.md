# ShieldDesk Webhooks Service (Go)

The Webhooks Service subscribes to NATS JetStream `alerts.{tenant_id}`, signs outgoing payloads with HMAC-SHA256 using the customer's webhook secret, and delivers events to customer URLs with exponential backoff retries.

---

## Supported Events

- `alert.created` — Threat detected by YARA, Sigma, or ML Anomaly engine
- `alert.resolved` — Alert triaged and resolved by analyst
- `vulnerability.critical` — High/Critical CVE detected on fleet asset
- `policy.violated` — Endpoint policy violation identified
- `asset.discovered` — New host or cloud asset enrolled
- `backup.integrity_failed` — Pre-patch snapshot or backup corrupted
- `lockdown.activated` — Emergency environment isolation triggered

---

## Webhook Payload Structure

```json
{
  "event": "alert.created",
  "timestamp": "2026-09-24T00:00:00Z",
  "tenant_id": "ten_acme123",
  "data": {
    "id": "alt-4819",
    "severity": "critical",
    "rule_name": "Suspicious PowerShell Encoded Execution"
  },
  "signature": "sha256=a8f5..."
}
```

---

## Local Development

```bash
cd services/webhooks
go test -v ./...
go run .
```

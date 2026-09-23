# ShieldDesk Threat Detection Service (Go)

The Threat Detection Service consumes real-time telemetry from NATS JetStream, evaluates incoming events against YARA and Sigma rules, runs statistical baseline anomaly detection, and publishes actionable security alerts.

---

## Responsibilities

1. **NATS JetStream Consumer**: Subscribes to `events.*.*` across all tenants with manual ack and durable push consumer.
2. **YARA Pattern Matching**: Evaluates file creation and modification events for webshells, ransomware extensions, and malicious strings (`rules/yara/*.yar`).
3. **Sigma Rule Engine**: Analyzes process creation and authentication telemetry for encoded PowerShell commands and brute-force logins (`rules/sigma/*.yml`).
4. **ML Anomaly Scoring**: Maintains per-asset baseline statistics (auth hours, outbound bytes). Triggers alerts for deviations > 3σ (auth) or > 2σ (network).
5. **TimescaleDB Persistence**: Writes raw telemetry to `public.security_events` hypertable and alerts to isolated `{tenant_id}.alerts` tables.
6. **Alert Broadcasting**: Emits alerts to NATS JetStream subject `alerts.{tenant_id}`.

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NATS_URL` | NATS JetStream cluster connection | `nats://localhost:4222` |
| `DATABASE_URL` | PostgreSQL / TimescaleDB connection | `postgresql://postgres:postgres@localhost:5432/shielddesk` |

---

## Local Development

```bash
cd services/threat
go test -v ./...
go run .
```

# ShieldDesk Ingest Service (Go 1.22 + gRPC)

The Ingest Service is the high-throughput front door for ShieldDesk endpoint agents, designed to process ~1,000 to 10,000 events/second per tenant.

---

## Responsibilities

1. **Bidirectional gRPC Streaming**: Receives continuous `AgentEvent` streams via `SendEvents`.
2. **mTLS & Token Authentication**: Validates agent TLS certificates against ShieldDesk internal CA and verifies tenant tokens via Redis.
3. **PII Sanitization**: Scrubs emails, credentials, private keys, credit cards, and bearer tokens before downstream messaging.
4. **Rate Limiting & Backpressure**: Enforces a strict 10,000 events/minute cap per tenant, returning backpressure flags to throttle agents before queue exhaustion.
5. **NATS JetStream Publishing**: Batches and fans out events to `events.{tenant_id}.{event_type}`.

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | gRPC listening port | `50051` |
| `NATS_URL` | NATS JetStream cluster URL | `nats://localhost:4222` |
| `REDIS_URL` | Redis instance for token caching | `localhost:6379` |
| `TLS_CERT_FILE` | Server certificate for mTLS | _(Optional in dev)_ |
| `TLS_KEY_FILE` | Server private key | _(Optional in dev)_ |
| `TLS_CA_FILE` | Internal CA certificate to verify agents | _(Optional in dev)_ |

---

## Local Development

```bash
cd services/ingest
go test ./...
go run .
```

# ShieldDesk Backend Services Directory

This directory contains standalone high-performance Go backend daemon services used for real-time telemetry streaming and threat matching alongside the native **Next.js App Router core** (`src/app/api/` and `src/lib/`):

| Active Service | Primary Language / Port | Purpose | Startup Script |
|---|---|---|---|
| `services/threat/` | Go / Port `8003` | Real-time Sigma rules & YARA threat detection engine. | `start.ps1` (`GoThreat`) |
| `services/ingest/` | Go / Port `8004` | High-throughput telemetry ingestion & PII redaction pipeline. | `start.ps1` (`GoIngest`) |
| `services/webhooks/` | Go / Port `8080` | High-throughput outbound notification webhook dispatcher. | `start.ps1` (`GoWebhook`) |

> **Architecture Note:**
> Early multi-container prototype services (`services/iam`, `services/scan`, `services/ai-advisor`, and 11 stub directories) have been completely removed. Auth, scanning, remediation, and AI capabilities operate directly within the Next.js control plane in `src/`.

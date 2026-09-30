# ShieldDesk Legacy Microservices Directory

> **DEPRECATION NOTICE:**
> The microservices contained in this directory (`services/iam`, `services/scan`, `services/ai-advisor`, `services/webhooks`) were created during initial multi-container prototyping.
> 
> In the current production architecture, all core capabilities have been consolidated natively into the **Next.js App Router core** under `src/app/api/` and `src/lib/`:
> 
> | Legacy Microservice | Native App Router Path | Notes |
> |---|---|---|
> | `services/iam/` | `src/app/api/auth/*`, `src/lib/auth/*` | Native session cookies, Supabase auth, and TOTP MFA. |
> | `services/scan/` | `src/app/api/scans/*`, `src/lib/detection/*` | Native CVE intelligence and Sigma rules engine. |
> | `services/webhooks/` | `src/app/api/webhooks/*`, `src/lib/notifications/*` | Native HMAC-SHA256 notification dispatcher. |
> | `services/ai-advisor/` | `src/app/api/chat/*`, `src/lib/tools/*` | Native OpenAI / Ollama tool-calling pipeline. |
> 
> This directory is preserved for reference or for standalone Docker container deployment if running decoupled microservice clusters.

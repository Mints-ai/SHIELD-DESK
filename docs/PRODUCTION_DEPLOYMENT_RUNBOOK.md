# ShieldDesk™ — Production Deployment & Rollback Runbook

**Document Version:** 1.0.0  
**Effective Date:** 2026-10-10  
**Target Environment:** Production Cloud & Hybrid Kubernetes / Container Infrastructure  
**Core Standard:** PROVE BEFORE YOU ACT

---

## 1. Pre-Deployment Release Verification

Before promoting any release artifact to staging or production, execute and verify the following gates:

### Step 1.1: Clean Codebase & Compilation Validation
```powershell
# 1. Verify clean working directory
git status -s

# 2. Execute TypeScript typecheck (Must exit 0 with zero errors)
npx tsc --noEmit

# 3. Execute Node.js full SOC test suite (Must pass 100% of non-skipped tests)
npm test

# 4. Verify Go universal endpoint agent build & tests
Set-Location agent
go test -v ./...
go build -ldflags="-s -w" -o ../bin/shielddesk-agent.exe ./cmd
Set-Location ..
```

### Step 1.2: Environment Variable Configuration Check
Ensure the production `.env.production` or container environment fulfills `src/config/schema.ts`:
- `APP_ENV=production`
- `NODE_ENV=production`
- `DEMO_MODE=false` (Strictly verified: system throws if `DEMO_MODE=true` in production)
- `SHIELDDESK_SESSION_SECRET` (Minimum 32 random cryptographic characters)
- `DATABASE_URL` (PostgreSQL with SSL enabled: `sslmode=require`)
- `RSA_SIGNING_PRIVATE_KEY` / `RSA_SIGNING_PUBLIC_KEY` (RSA-2048 PEM keys for signed command dispatch)

---

## 2. Production Deployment Execution

### Step 2.1: Database Migrations
Run schema migrations against the target database cluster:
```bash
# Execute schema migration script
npm run db:migrate # or execute src/lib/db migrations
```
Verify that Row-Level Security (RLS) is enabled on all tenant-isolated tables (`endpoint_agents`, `incidents`, `agent_commands`, `agent_command_logs`, `endpoint_telemetry`, `hash_chain_audit`).

### Step 2.2: Container Build & Promotion
```bash
# Build production container image using multi-stage Dockerfile
docker build -t registry.shielddesk.io/shielddesk-controlplane:v1.0.0 .

# Verify image vulnerability scan via Trivy
trivy image --severity HIGH,CRITICAL registry.shielddesk.io/shielddesk-controlplane:v1.0.0

# Deploy container with non-root user and read-only root filesystem
docker run -d \
  --name shielddesk-prod \
  -p 3000:3000 \
  --env-file .env.production \
  --restart unless-stopped \
  registry.shielddesk.io/shielddesk-controlplane:v1.0.0
```

### Step 2.3: Post-Deployment Probing
Verify service health within 30 seconds of launch:
```bash
# 1. Healthcheck Probe (Must return HTTP 200 with status=ok or degraded, not 500/503)
curl -s -f http://localhost:3000/api/health | jq .

# 2. Prometheus Metrics Check
curl -s -f http://localhost:3000/api/metrics | grep shielddesk
```

---

## 3. Emergency Deployment Rollback Procedure

If deployment health probes fail, error rates spike above 1%, or database connectivity cannot be established:

### Step 3.1: Traffic Redirection
Immediately switch ingress routing (Cloudflare / NGINX / ALB) to the previous known-good deployment target:
```bash
# Revert container or ingress target to previous release tag (e.g., v0.9.9)
docker stop shielddesk-prod
docker start shielddesk-prod-previous
```

### Step 3.2: Database Reversion
If a backward-incompatible database migration was applied:
```bash
# Restore PostgreSQL from pre-deployment snapshot
pg_restore --clean --if-exists -d shielddesk_prod /backups/pre-deploy-v1.0.0.dump
```

### Step 3.3: Fleet Isolation & Emergency Kill-Switch
If control-plane integrity is questioned or abnormal agent behavior is observed:
```bash
# Engage global fleet emergency kill-switch via authenticated administrative API
curl -X POST http://localhost:3000/api/fleet/kill-switch \
  -H "Authorization: Bearer $SUPER_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "ENGAGE_ALL", "reason": "Emergency deployment abort"}'
```
All connected agents will immediately lock down command execution and reject further instructions with `423 Locked`.

---

## 4. Commercial Billing & Licensing Operations Runbook

### Step 4.1: Database Migration Verification
Verify that the commercial licensing and billing schema (Phase M) is active in PostgreSQL:
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN (
  'billing_customers',
  'billing_catalog_plans',
  'checkout_attempts',
  'subscriptions',
  'subscription_history',
  'invoices',
  'product_licenses',
  'license_activations',
  'stripe_webhook_events',
  'billing_notification_outbox'
);
```
Ensure all tables have Row-Level Security (RLS) enabled and foreign key indexes created.

### Step 4.2: Stripe Production Merchant Setup
1. Configure Stripe API keys in secret manager:
   - `STRIPE_SECRET_KEY`: `rk_live_...` (Restricted Key with minimum required permissions: checkout, customers, subscriptions, billing_portal)
   - `STRIPE_WEBHOOK_SECRET`: `whsec_...` from Stripe Dashboard > Webhooks
   - `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`: `pk_live_...`
2. Create Webhook Endpoint in Stripe Dashboard pointing to:
   - `https://shielddesk.mintsglobal.ae/api/billing/webhook`
   - Monitored Events:
     - `checkout.session.completed`
     - `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`
     - `invoice.paid`, `invoice.payment_failed`
     - `charge.refunded`, `charge.dispute.created`
3. Configure License Asymmetric Signing Keys:
   - `LICENSE_SIGNING_PRIVATE_KEY_PEM`: RSA 2048 private key (kept strictly server-side)
   - `LICENSE_PEPPER`: 64-character hex cryptographic pepper (strictly isolated from session secret)

### Step 4.3: Webhook Event Ingestion & Inbox Processing Check
Execute health check on webhook event queue:
```sql
-- Check for pending or stalled webhook events
SELECT id, event_type, status, retry_count, last_error, received_at 
FROM stripe_webhook_events 
WHERE status IN ('received', 'processing', 'failed')
ORDER BY received_at DESC;
```

### Step 4.4: License Key Reissue & Revocation Procedure
1. **Emergency License Revocation:**
   ```bash
   curl -X POST https://shielddesk.mintsglobal.ae/api/v1/licenses/$LICENSE_ID/revoke \
     -H "Authorization: Bearer $SUPER_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason": "Compromised deployment or non-payment", "supersededBy": null}'
   ```
2. **Reissue License for Authorized Tenant:**
   - Revoke old license with reason "Administrative reissue".
   - Generate high-entropy 192-bit cryptographic replacement.
   - Display once in tenant administrative portal.

### Step 4.5: Offline Grace Period & Quota Invariants
- Delinquent payments enter a 14-day grace period; monitoring telemetry ingestion is **never** silently dropped.
- Hosted SaaS customers do not receive control-plane source code or binaries; access is mediated entirely through authenticated tenant isolation.


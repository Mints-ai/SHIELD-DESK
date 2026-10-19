-- ============================================================================
-- ShieldDesk Core & Commercial Production Schema
-- Authoritative schema definition covering multi-tenant identity, incidents,
-- telemetry, endpoint fleet, immutable hash-chain audit ledger, and Phase M
-- commercial licensing and Stripe billing infrastructure.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Identity & RBAC: Multi-tenant user credentials, roles, and TOTP/MFA state.
-- Enforces strict tenant isolation and role-based access control.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            text PRIMARY KEY,   -- opaque user id
  tenant_id     text NOT NULL,
  role          text NOT NULL CHECK (role IN ('system_admin', 'super_admin', 'responder', 'analyst')),

  email         text UNIQUE,
  password_hash text,
  -- TOTP / MFA columns (added in launch-readiness pass)
  totp_secret         text,              -- active TOTP secret (NULL = not enrolled)
  totp_pending_secret text,              -- unconfirmed secret during enrollment
  totp_enabled        boolean NOT NULL DEFAULT false,
  last_totp_at        timestamptz,       -- replay guard: last accepted TOTP step
  updated_at    timestamptz NOT NULL DEFAULT now(),
  created_at    timestamptz NOT NULL DEFAULT now()
);
-- Idempotent column additions for existing deployments
ALTER TABLE users ADD COLUMN IF NOT EXISTS email text UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();



-- ---------------------------------------------------------------------------
-- Incidents
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_code text UNIQUE NOT NULL,     -- e.g. 'INC-1042'
  tenant_id     text NOT NULL,
  severity      text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  status        text NOT NULL CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
  title         text NOT NULL,
  description   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents (tenant_id);

CREATE TABLE IF NOT EXISTS incident_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  occurred_at timestamptz NOT NULL,
  description text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events (incident_id);

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   text NOT NULL,
  hostname    text NOT NULL,
  asset_type  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets (tenant_id);

CREATE TABLE IF NOT EXISTS incident_assets (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  asset_id    uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, asset_id)
);

-- ---------------------------------------------------------------------------
-- Vulnerabilities linked to an incident.
-- One incident can touch multiple CVEs; one CVE can appear in multiple
-- incidents. Kept simple: just the IDs, with the Python service
-- (cve_ai_engine.py / server.py) being the authority on what the CVE
-- actually means (CVSS, KEV status, domain, recommended remediation).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_cves (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  cve_id      text NOT NULL,              -- e.g. 'CVE-2024-3400'
  PRIMARY KEY (incident_id, cve_id)
);

-- ---------------------------------------------------------------------------
-- Audit log: every question asked, tool called, and final answer recorded.
-- Critical for SOC compliance / SOC2.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chat_audit_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  uid         text NOT NULL,
  role        text NOT NULL,
  tenant_id   text NOT NULL,
  question    text NOT NULL,
  tool_called text,                       -- nullable; out-of-scope queries don't call one
  answer      text NOT NULL,
  outcome     text NOT NULL,              -- 'authorized' | 'denied' | 'error' | 'out_of_scope'
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Priority 1: Mitigation Plans & Tasks (Persistent Governance Artifacts)
-- Turns generateMitigationPlan into versioned, tracked database rows.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitigation_plans (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  version       integer NOT NULL DEFAULT 1,
  status        text NOT NULL CHECK (status IN ('draft', 'active', 'archived', 'completed')),
  summary       text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mitigation_plans_tenant ON mitigation_plans (tenant_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_plans_incident ON mitigation_plans (incident_id);

CREATE TABLE IF NOT EXISTS mitigation_tasks (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id       uuid NOT NULL REFERENCES mitigation_plans(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  horizon       text NOT NULL CHECK (horizon IN ('immediate', 'short_term', 'long_term')),
  title         text NOT NULL,
  description   text,
  tier          text NOT NULL DEFAULT 'Tier 2',
  status        text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'in_progress', 'completed', 'failed')),
  execution_command_id uuid,
  blast_radius  text,
  cve_id        text,
  assigned_to   text REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mitigation_tasks_plan ON mitigation_tasks (plan_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_tasks_execution_command ON mitigation_tasks (execution_command_id) WHERE execution_command_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Priority 2: Layer 4 Governance — Approval Tokens & Separation of Duties
-- Enforces human-in-the-loop gating before any Tier 2+ action can execute.
-- Separation of duties (requested_by != approved_by) is enforced at the DB level.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_tokens (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        text NOT NULL,
  task_id          uuid REFERENCES mitigation_tasks(id) ON DELETE CASCADE,
  action_type      text NOT NULL,               -- e.g. 'isolate_host', 'deploy_patch', 'quarantine'
  tier             text NOT NULL CHECK (tier IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')),
  status           text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  requested_by     text NOT NULL REFERENCES users(id),
  approved_by      text REFERENCES users(id),   -- first approver (or sole approver for Tier 1/2)
  secondary_approved_by text REFERENCES users(id),  -- second approver for Tier 3 dual-approval
  rejection_reason text,
  blast_radius     text,
  model_confidence numeric(4,2) DEFAULT 0.95,   -- e.g. 0.95 (95% confidence)
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT check_separation_of_duties
    CHECK (approved_by IS NULL OR tier IN ('Tier 1', 'Tier 2') OR requested_by <> approved_by),
  CONSTRAINT check_tier3_dual_approval_separation
    CHECK (secondary_approved_by IS NULL OR approved_by <> secondary_approved_by)
);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_tenant ON approval_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_status ON approval_tokens (status);
-- Idempotent migration for existing deployments
ALTER TABLE approval_tokens ADD COLUMN IF NOT EXISTS secondary_approved_by text REFERENCES users(id);


CREATE TABLE IF NOT EXISTS approval_audit_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_id    uuid,
  tenant_id   text NOT NULL,
  actor_id    text NOT NULL,
  action      text NOT NULL,                    -- 'token_requested' | 'token_approved' | 'token_rejected' | 'action_executed'
  details     text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_approval_audit_tenant ON approval_audit_log (tenant_id);

-- ---------------------------------------------------------------------------
-- Layer 2: Endpoint Agent Fleet Management
-- Tracks registered endpoints, real-time telemetry, and health status.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_agents (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           text NOT NULL,
  hostname            text NOT NULL,
  ip_address          text NOT NULL,
  os_type             text NOT NULL CHECK (os_type IN ('linux', 'windows', 'darwin')),
  agent_version       text NOT NULL DEFAULT '0.4.2',
  status              text NOT NULL CHECK (status IN ('connected', 'isolated', 'quarantined', 'disconnected')),
  cpu_usage           numeric(5,2) DEFAULT 0.0,
  memory_usage        numeric(5,2) DEFAULT 0.0,
  eps                 integer DEFAULT 0,         -- events per second
  kill_switch_active  boolean NOT NULL DEFAULT false,
  safety_snapshot_id  text,
  last_heartbeat      timestamptz NOT NULL DEFAULT now(),
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_tenant ON endpoint_agents (tenant_id);

CREATE TABLE IF NOT EXISTS agent_command_logs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  command       text NOT NULL,
  tier          text NOT NULL CHECK (tier IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')),
  token_id      uuid REFERENCES approval_tokens(id) ON DELETE CASCADE,
  status        text NOT NULL CHECK (status IN ('pending', 'executing', 'succeeded', 'failed', 'rolled_back')),
  output        text,
  executed_by   text NOT NULL,
  executed_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_command_logs_agent ON agent_command_logs (agent_id);

CREATE TABLE IF NOT EXISTS agent_commands (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  command       text NOT NULL,
  tier          text NOT NULL CHECK (tier IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')),
  token_id      uuid REFERENCES approval_tokens(id) ON DELETE CASCADE,
  signature     text NOT NULL,
  nonce         text,
  status        text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('requested', 'authorised', 'signed', 'queued', 'delivered', 'acknowledged', 'executing', 'executed', 'verified', 'failed', 'rolled_back', 'cancelled', 'expired', 'delivery_failed', 'execution_failed', 'verification_failed')),
  result        jsonb,
  snapshot_id   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  completed_at  timestamptz
);
ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS nonce text;
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_status ON agent_commands (agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_commands_tenant_created ON agent_commands (tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- Endpoint Enrollment Tokens
-- Short-lived, single-use, tenant-bound tokens for endpoint provisioning.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_enrollment_tokens (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     text NOT NULL,
  token_hash    text NOT NULL UNIQUE,
  label         text,
  expires_at    timestamptz NOT NULL,
  max_uses      integer NOT NULL DEFAULT 1,
  used_count    integer NOT NULL DEFAULT 0,
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant ON endpoint_enrollment_tokens (tenant_id);

-- ---------------------------------------------------------------------------
-- Endpoint High-Frequency Telemetry Ingestion
-- Stores streaming telemetry batches from enrolled endpoint agents.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_telemetry (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  event_type    text NOT NULL,
  payload       jsonb NOT NULL,
  timestamp     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_telemetry_agent_time ON endpoint_telemetry (agent_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_time ON endpoint_telemetry (tenant_id, timestamp DESC);

-- ---------------------------------------------------------------------------
-- Layer 3/4: Hash-Chained Tamper-Proof Audit Vault
-- Cryptographically chains events (prev_hash + payload -> current_hash)
-- for SOC 2 / ISO 27001 auditor verification.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hash_chain_audit (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     text NOT NULL,
  event_type    text NOT NULL,
  actor_id      text NOT NULL,
  payload       jsonb NOT NULL,
  prev_hash     text NOT NULL,
  current_hash  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_hash_chain_tenant ON hash_chain_audit (tenant_id);

-- ---------------------------------------------------------------------------
-- Endpoint Certificates & mTLS Identity Vault (SD-008, SD-009)
-- Tracks issued X.509 client certificates, serials, fingerprints, and revocations.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_certificates (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id           uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id          text NOT NULL,
  serial_number      text NOT NULL UNIQUE,
  certificate_pem    text NOT NULL,
  fingerprint_sha256 text NOT NULL,
  issued_at          timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  revoked_at         timestamptz,
  revocation_reason  text
);
CREATE INDEX IF NOT EXISTS idx_endpoint_certs_agent ON endpoint_certificates (agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_certs_tenant ON endpoint_certificates (tenant_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_certs_serial ON endpoint_certificates (serial_number);

-- ---------------------------------------------------------------------------
-- Endpoint Safety Snapshots (SD-024)
-- Tracks pre-flight restore points (LVM, Shadow Copy, or process/net states).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_snapshots (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id           uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id          text NOT NULL,
  snapshot_ref       text NOT NULL,
  hostname           text NOT NULL,
  snapshot_type      text NOT NULL DEFAULT 'pre_remediation',
  metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoint_snapshots_agent ON endpoint_snapshots (agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_snapshots_tenant ON endpoint_snapshots (tenant_id);

-- ---------------------------------------------------------------------------
-- Endpoint Emergency Kill Switches (SD-025)
-- Historical and active tenant-wide or agent-scoped emergency freeze ledger.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoint_kill_switches (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          text NOT NULL,
  agent_id           uuid REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  reason             text NOT NULL,
  triggered_by       text NOT NULL,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated')),
  created_at         timestamptz NOT NULL DEFAULT now(),
  deactivated_at     timestamptz
);
CREATE INDEX IF NOT EXISTS idx_kill_switches_tenant ON endpoint_kill_switches (tenant_id);

-- ---------------------------------------------------------------------------
-- Defense-in-Depth: Postgres Row-Level Security (RLS) Policies
-- Ensures tenant data cannot cross boundaries even if application filters fail.
-- ---------------------------------------------------------------------------
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitigation_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitigation_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_command_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE hash_chain_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_telemetry ENABLE ROW LEVEL SECURITY;

-- Tenant Isolation Policies (enforced when app.current_tenant session variable is set)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_incidents') THEN
    CREATE POLICY tenant_isolation_incidents ON incidents
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_assets') THEN
    CREATE POLICY tenant_isolation_assets ON assets
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_mitigation_plans') THEN
    CREATE POLICY tenant_isolation_mitigation_plans ON mitigation_plans
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_mitigation_tasks') THEN
    CREATE POLICY tenant_isolation_mitigation_tasks ON mitigation_tasks
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_approval_tokens') THEN
    CREATE POLICY tenant_isolation_approval_tokens ON approval_tokens
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_agents') THEN
    CREATE POLICY tenant_isolation_endpoint_agents ON endpoint_agents
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_agent_commands') THEN
    CREATE POLICY tenant_isolation_agent_commands ON agent_commands
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_agent_command_logs') THEN
    CREATE POLICY tenant_isolation_agent_command_logs ON agent_command_logs
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_hash_chain_audit') THEN
    CREATE POLICY tenant_isolation_hash_chain_audit ON hash_chain_audit
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_certificates') THEN
    CREATE POLICY tenant_isolation_endpoint_certificates ON endpoint_certificates
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_snapshots') THEN
    CREATE POLICY tenant_isolation_endpoint_snapshots ON endpoint_snapshots
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_kill_switches') THEN
    CREATE POLICY tenant_isolation_endpoint_kill_switches ON endpoint_kill_switches
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_chat_audit_log') THEN
    CREATE POLICY tenant_isolation_chat_audit_log ON chat_audit_log
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_enrollment_tokens') THEN
    CREATE POLICY tenant_isolation_endpoint_enrollment_tokens ON endpoint_enrollment_tokens
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_telemetry') THEN
    CREATE POLICY tenant_isolation_endpoint_telemetry ON endpoint_telemetry
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;
END $$;

-- ============================================================================
-- Phase M: Commercial Licensing, Stripe Billing & Customer Purchase Schema
-- ============================================================================

-- 1. Billing Customers (Binds authenticated tenant to Stripe Customer)
CREATE TABLE IF NOT EXISTS billing_customers (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL UNIQUE,
    stripe_customer_id VARCHAR(128) NOT NULL UNIQUE,
    billing_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_customers_lookup 
    ON billing_customers (tenant_id, stripe_customer_id);

-- 2. Product Catalogue and Price Mappings
CREATE TABLE IF NOT EXISTS product_catalog_prices (
    id VARCHAR(64) PRIMARY KEY,
    plan_id VARCHAR(32) NOT NULL, -- community, professional, enterprise
    billing_interval VARCHAR(16) NOT NULL, -- month, year
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    stripe_price_id VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    entitlement_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (plan_id, billing_interval, currency)
);

CREATE INDEX IF NOT EXISTS idx_product_catalog_prices_lookup 
    ON product_catalog_prices (plan_id, billing_interval, is_active);

-- 3. Checkout Attempts (Pre-checkout ledger and correlation)
CREATE TABLE IF NOT EXISTS checkout_attempts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    initiating_user_id VARCHAR(64) NOT NULL,
    stripe_checkout_session_id VARCHAR(128) UNIQUE,
    plan_id VARCHAR(32) NOT NULL,
    billing_interval VARCHAR(16) NOT NULL DEFAULT 'month',
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    deployment_type VARCHAR(32) NOT NULL DEFAULT 'saas', -- saas, customer-hosted
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, completed, expired, failed
    idempotency_key VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_checkout_attempts_tenant 
    ON checkout_attempts (tenant_id, status, created_at DESC);

-- 4. Tenant Subscriptions (Canonical state of tenant subscription)
CREATE TABLE IF NOT EXISTS tenant_subscriptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL UNIQUE,
    stripe_customer_id VARCHAR(128),
    stripe_subscription_id VARCHAR(128) UNIQUE,
    tier VARCHAR(32) NOT NULL DEFAULT 'community', -- community, professional, enterprise
    billing_interval VARCHAR(16) NOT NULL DEFAULT 'month',
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- trialing, active, past_due, grace_period, suspended, cancelled, expired
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    canceled_at TIMESTAMPTZ,
    grace_period_until TIMESTAMPTZ,
    entitlement_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_subscriptions_tenant_status 
    ON tenant_subscriptions (tenant_id, status);

-- 5. Subscription Status Transition Audit History
CREATE TABLE IF NOT EXISTS subscription_status_history (
    id VARCHAR(64) PRIMARY KEY,
    subscription_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    reason VARCHAR(255),
    actor_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sub_history_tenant 
    ON subscription_status_history (tenant_id, transitioned_at DESC);

-- 6. Invoices
CREATE TABLE IF NOT EXISTS invoices (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subscription_id VARCHAR(64),
    stripe_invoice_id VARCHAR(128) NOT NULL UNIQUE,
    invoice_number VARCHAR(64),
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    amount_due_cents INTEGER NOT NULL DEFAULT 0,
    amount_paid_cents INTEGER NOT NULL DEFAULT 0,
    amount_remaining_cents INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'draft', -- draft, open, paid, void, uncollectible, failed
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    hosted_invoice_url TEXT,
    invoice_pdf_url TEXT,
    paid_at TIMESTAMPTZ,
    due_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_tenant 
    ON invoices (tenant_id, status, created_at DESC);

-- 7. Product Licenses (Never persists raw secret; stores keyed digest & safe display hints)
CREATE TABLE IF NOT EXISTS product_licenses (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subscription_id VARCHAR(64),
    license_key_hash VARCHAR(128) NOT NULL UNIQUE, -- SHA-256(pepper + key)
    display_prefix VARCHAR(16) NOT NULL, -- e.g. 'SD-PRO'
    display_suffix VARCHAR(16) NOT NULL, -- e.g. '9F2B'
    tier VARCHAR(32) NOT NULL DEFAULT 'community',
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- draft, active, grace_period, suspended, expired, revoked
    max_endpoints INTEGER NOT NULL DEFAULT 5,
    max_users INTEGER NOT NULL DEFAULT 10,
    features TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    signing_key_id VARCHAR(64) NOT NULL DEFAULT 'sd-k1',
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    grace_period_days INTEGER NOT NULL DEFAULT 14,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    replaces_license_id VARCHAR(64),
    replaced_by_license_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_product_licenses_lookup 
    ON product_licenses (tenant_id, status, expires_at);

-- 8. License Activations (Hardware & Installation binding with challenge verification)
CREATE TABLE IF NOT EXISTS license_activations (
    id VARCHAR(64) PRIMARY KEY,
    license_id VARCHAR(64) NOT NULL REFERENCES product_licenses(id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    installation_id VARCHAR(128) NOT NULL,
    device_identity VARCHAR(128) NOT NULL,
    certificate_fingerprint VARCHAR(128) NOT NULL,
    platform VARCHAR(32) NOT NULL DEFAULT 'linux', -- linux, windows, macos
    product_version VARCHAR(32) NOT NULL DEFAULT '2.4.0',
    activation_state VARCHAR(32) NOT NULL DEFAULT 'active', -- active, past_due, suspended, revoked, deactivated
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    deactivation_reason TEXT,
    UNIQUE (tenant_id, installation_id),
    UNIQUE (tenant_id, device_identity)
);

CREATE INDEX IF NOT EXISTS idx_license_activations_lookup 
    ON license_activations (tenant_id, license_id, activation_state);

-- 9. Durable Stripe Webhook Inbox
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id VARCHAR(64) PRIMARY KEY,
    stripe_event_id VARCHAR(128) NOT NULL UNIQUE,
    event_type VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, processing, processed, failed, duplicate
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    retry_count INTEGER NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_inbox_processing 
    ON stripe_webhook_events (status, created_at ASC);






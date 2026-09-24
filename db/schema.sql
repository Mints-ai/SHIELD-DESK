-- ShieldDesk schema — designed as part of this build, since the platform
-- itself doesn't exist yet (the chat widget is the first component).
-- Nothing here is "the real schema handed down from elsewhere" — this IS
-- the real schema, for now. Revise freely once the actual incidents/assets
-- pages (later phases) impose their own requirements.

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Identity: who is asking, and what tenant/role do they have.
-- No Firebase / external IdP — see lib/auth/session.ts for the dev-mode
-- bypass this backs. Swap in real credential storage when ShieldDesk has
-- its own login flow.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            text PRIMARY KEY,   -- opaque user id
  tenant_id     text NOT NULL,
  role          text NOT NULL CHECK (role IN ('system_admin', 'super_admin', 'user')),
  email         text UNIQUE,
  password_hash text,
  created_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email text UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;


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
  status        text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'in_progress', 'completed')),
  blast_radius  text,
  cve_id        text,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mitigation_tasks_plan ON mitigation_tasks (plan_id);

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
  approved_by      text REFERENCES users(id),
  rejection_reason text,
  blast_radius     text,
  model_confidence numeric(4,2) DEFAULT 0.95,   -- e.g. 0.95 (95% confidence)
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT check_separation_of_duties CHECK (approved_by IS NULL OR requested_by <> approved_by)
);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_tenant ON approval_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS idx_approval_tokens_status ON approval_tokens (status);

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
  token_id      uuid REFERENCES approval_tokens(id),
  status        text NOT NULL CHECK (status IN ('pending', 'executing', 'succeeded', 'failed', 'rolled_back')),
  output        text,
  executed_by   text NOT NULL,
  executed_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_command_logs_agent ON agent_command_logs (agent_id);

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
ALTER TABLE hash_chain_audit ENABLE ROW LEVEL SECURITY;

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

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_endpoint_agents') THEN
    CREATE POLICY tenant_isolation_endpoint_agents ON endpoint_agents
      USING (
        current_setting('app.current_tenant', true) IS NULL OR
        current_setting('app.current_tenant', true) = '' OR
        current_setting('app.user_role', true) IN ('system_admin', 'super_admin') OR
        tenant_id = current_setting('app.current_tenant', true)
      );
  END IF;
END $$;





-- ==============================================================================
-- ShieldDesk Master Enterprise Database Schema (PostgreSQL 16)
-- Architecture: Hybrid Global (Public) + Schema-Per-Tenant Isolation
-- Includes: TimescaleDB Hypertables + pgvector Embedding Tables
-- ==============================================================================

-- 1. Required Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";    -- uuid utilities
CREATE EXTENSION IF NOT EXISTS vector;         -- pgvector for semantic search (if installed)
-- TimescaleDB is enabled if running on TimescaleDB-enabled engine:
-- CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ==============================================================================
-- 2. Global Public Schema (Shared across all tenants)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.tenants (
  id          TEXT PRIMARY KEY,                  -- e.g. 'ten_acme123'
  name        TEXT NOT NULL,
  plan        TEXT NOT NULL DEFAULT 'starter' CHECK (plan IN ('starter', 'growth', 'enterprise')),
  region      TEXT NOT NULL DEFAULT 'us-east-1',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tenants_created ON public.tenants (created_at DESC);

CREATE TABLE IF NOT EXISTS public.users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     TEXT NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  mfa_enabled   BOOLEAN NOT NULL DEFAULT false,
  mfa_secret    TEXT,                            -- Encrypted base32 TOTP secret
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON public.users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users (email);

CREATE TABLE IF NOT EXISTS public.sessions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT NOT NULL,
  user_agent         TEXT,
  ip_address         TEXT,
  expires_at         TIMESTAMPTZ NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON public.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON public.sessions (expires_at);

CREATE TABLE IF NOT EXISTS public.audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   TEXT NOT NULL,
  user_id     UUID,
  action      TEXT NOT NULL,                     -- e.g. 'auth.login', 'policy.update', 'lockdown.activate'
  resource    TEXT NOT NULL,                     -- e.g. 'asset:123', 'tenant:ten_acme'
  payload     JSONB DEFAULT '{}'::jsonb,
  timestamp   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON public.audit_log (tenant_id, timestamp DESC);

-- ==============================================================================
-- 3. TimescaleDB Telemetry Hypertable (High Throughput Event Store)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.security_events (
  time        TIMESTAMPTZ NOT NULL,
  tenant_id   TEXT NOT NULL,
  asset_id    TEXT NOT NULL,
  event_type  TEXT NOT NULL,                     -- process | file | network | auth | inventory
  payload     JSONB NOT NULL,
  PRIMARY KEY (time, tenant_id, asset_id, event_type)
);
CREATE INDEX IF NOT EXISTS idx_sec_events_tenant_time ON public.security_events (tenant_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_asset ON public.security_events (asset_id, time DESC);

-- If TimescaleDB is loaded, convert to hypertable with 1-week partition chunks:
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    PERFORM create_hypertable('public.security_events', 'time', chunk_time_interval => INTERVAL '1 week', if_not_exists => TRUE);
  END IF;
END $$;

-- ==============================================================================
-- 4. Vector Embeddings (pgvector Semantic Knowledge Store)
-- ==============================================================================

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
    CREATE TABLE IF NOT EXISTS public.cve_embeddings (
      cve_id        TEXT PRIMARY KEY,
      description   TEXT NOT NULL,
      cvss          NUMERIC(3,1),
      embedding     vector(1536),                -- text-embedding-3-small dimension
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS public.incident_embeddings (
      incident_id   TEXT PRIMARY KEY,
      tenant_id     TEXT NOT NULL,
      summary       TEXT NOT NULL,
      embedding     vector(1536),
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_inc_embed_tenant ON public.incident_embeddings (tenant_id);
  END IF;
END $$;

-- ==============================================================================
-- 5. Automated Per-Tenant Schema Provisioning Function
-- Call: SELECT public.provision_tenant_schema('ten_acme123');
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.provision_tenant_schema(p_tenant_id TEXT)
RETURNS VOID AS $$
DECLARE
  v_schema TEXT := quote_ident(p_tenant_id);
BEGIN
  -- Create isolated tenant schema
  EXECUTE 'CREATE SCHEMA IF NOT EXISTS ' || v_schema;

  -- 1. Assets Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type        TEXT NOT NULL,                   -- server | workstation | container | cloud_instance
    name        TEXT NOT NULL,
    ip          TEXT,
    os          TEXT,
    tags        JSONB DEFAULT ''[]''::jsonb,
    risk_score  NUMERIC(4,1) DEFAULT 0.0,
    owner_id    UUID,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  )';

  -- 2. Alerts Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID REFERENCES ' || v_schema || '.assets(id) ON DELETE SET NULL,
    severity    TEXT NOT NULL CHECK (severity IN (''critical'', ''high'', ''medium'', ''low'', ''info'')),
    type        TEXT NOT NULL,                   -- malware | intrusion | anomaly | policy | vuln
    status      TEXT NOT NULL DEFAULT ''open'' CHECK (status IN (''open'', ''acknowledged'', ''resolved'', ''false_positive'')),
    rule_id     TEXT,
    rule_name   TEXT,
    ai_summary  TEXT,
    payload     JSONB DEFAULT ''{}''::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  )';

  -- 3. Vulnerabilities Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.vulnerabilities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID REFERENCES ' || v_schema || '.assets(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    cvss        NUMERIC(3,1) NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN (''critical'', ''high'', ''medium'', ''low'')),
    package_name TEXT,
    fixed_version TEXT,
    status      TEXT NOT NULL DEFAULT ''open'' CHECK (status IN (''open'', ''accepted_risk'', ''resolved'')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fixed_at    TIMESTAMPTZ
  )';

  -- 4. Policies Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    rule_dsl          JSONB NOT NULL,
    enforcement_mode  TEXT NOT NULL DEFAULT ''audit'' CHECK (enforcement_mode IN (''audit'', ''block'', ''remediate'')),
    scope             TEXT NOT NULL DEFAULT ''fleet'',
    created_by        UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
  )';

  -- 5. Policy Violations Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.policy_violations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id     UUID REFERENCES ' || v_schema || '.policies(id) ON DELETE CASCADE,
    asset_id      UUID REFERENCES ' || v_schema || '.assets(id) ON DELETE CASCADE,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ
  )';

  -- 6. Secrets Findings Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.secrets_findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id      UUID REFERENCES ' || v_schema || '.assets(id) ON DELETE CASCADE,
    source        TEXT NOT NULL,                 -- git_repo | env_file | docker_config
    secret_type   TEXT NOT NULL,                 -- aws_iam_key | github_token | stripe_key | private_key
    hash          TEXT NOT NULL,                 -- SHA-256 hash (never store plaintext)
    location      TEXT,                          -- file path or repo URL
    status        TEXT NOT NULL DEFAULT ''active'' CHECK (status IN (''active'', ''rotated'', ''revoked'')),
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now()
  )';

  -- 7. Compliance Evidence Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.compliance_evidence (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework     TEXT NOT NULL,                 -- SOC2 | ISO27001 | GDPR | HIPAA
    control_id    TEXT NOT NULL,                 -- e.g. 'CC6.1', 'A.12.1'
    status        TEXT NOT NULL DEFAULT ''compliant'' CHECK (status IN (''compliant'', ''non_compliant'', ''in_progress'')),
    evidence_url  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
  )';

  -- 8. Employees / Identity Table
  EXECUTE 'CREATE TABLE IF NOT EXISTS ' || v_schema || '.employees (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL,
    risk_score    NUMERIC(4,1) DEFAULT 0.0,
    mfa_status    BOOLEAN NOT NULL DEFAULT true,
    last_login    TIMESTAMPTZ,
    breach_count  INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
  )';
END;
$$ LANGUAGE plpgsql;

-- Provision Default Development Tenants for Immediate Readiness
SELECT public.provision_tenant_schema('acme_tenant');
SELECT public.provision_tenant_schema('globex_tenant');

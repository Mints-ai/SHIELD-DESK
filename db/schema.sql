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
  id         text PRIMARY KEY,   -- opaque user id (dev mode: whatever the caller sends)
  tenant_id  text NOT NULL,
  role       text NOT NULL CHECK (role IN ('system_admin', 'super_admin', 'user')),
  created_at timestamptz NOT NULL DEFAULT now()
);

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

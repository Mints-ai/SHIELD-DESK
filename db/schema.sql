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
CREATE TABLE users (
  id         text PRIMARY KEY,   -- opaque user id (dev mode: whatever the caller sends)
  tenant_id  text NOT NULL,
  role       text NOT NULL CHECK (role IN ('system_admin', 'super_admin', 'user')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Incidents
-- ---------------------------------------------------------------------------
CREATE TABLE incidents (
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
CREATE INDEX idx_incidents_tenant ON incidents (tenant_id);

CREATE TABLE incident_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  description text NOT NULL
);
CREATE INDEX idx_incident_events_incident ON incident_events (incident_id);

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
CREATE TABLE assets (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  text NOT NULL,
  hostname   text NOT NULL,
  asset_type text NOT NULL DEFAULT 'workstation'
);
CREATE INDEX idx_assets_tenant ON assets (tenant_id);

CREATE TABLE incident_assets (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  asset_id    uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, asset_id)
);

-- ---------------------------------------------------------------------------
-- Incident <-> CVE linkage — the design decision from this conversation.
-- Many-to-many: one incident can involve several CVEs (e.g. a chained
-- exploit), and one CVE can show up across multiple incidents/tenants.
-- cve_id is a plain text column (not a foreign key) because the CVE
-- knowledge base lives in the separate Python engine (cve_ai_engine.py),
-- not in this database — this table just records which CVE ids are
-- relevant to which incident, and generateMitigationPlan looks each one
-- up via GET /api/lookup at request time.
-- ---------------------------------------------------------------------------
CREATE TABLE incident_cves (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  cve_id      text NOT NULL,   -- e.g. 'CVE-2024-3400'
  PRIMARY KEY (incident_id, cve_id)
);

-- ---------------------------------------------------------------------------
-- Audit log for chat requests (Phase 8)
-- ---------------------------------------------------------------------------
CREATE TABLE chat_audit_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  uid         text NOT NULL,
  role        text NOT NULL,
  tenant_id   text NOT NULL,
  question    text NOT NULL,
  tool_called text,
  answer      text,
  outcome     text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

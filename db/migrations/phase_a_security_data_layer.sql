-- ============================================================
-- ShieldDesk Phase A: Security Data Layer
-- Universal event schema, asset criticality, vulnerability
-- normalization, connector configuration and cursor tracking.
--
-- All statements are additive and idempotent (IF NOT EXISTS).
-- Safe to run on an existing database without data loss.
-- ============================================================

-- ---------------------------------------------------------------------------
-- 1. security_events — canonical normalized security event store
--    Supersedes raw connector buffers; one row per deduplicated alert.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
  id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           text         NOT NULL,
  source              text         NOT NULL,           -- wazuh | trivy | openvas | defender | crowdstrike | ...
  external_id         text         NOT NULL,           -- original vendor event/alert ID
  dedup_fingerprint   text         NOT NULL,           -- SHA-256 of (tenant+source+external_id+asset+rule)
  timestamp           timestamptz  NOT NULL,
  ingest_at           timestamptz  NOT NULL DEFAULT now(),

  -- Severity and categorisation
  severity            text         NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  category            text         NOT NULL DEFAULT 'alert',
                                   -- alert | vulnerability | compliance | anomaly | audit
  event_type          text         NOT NULL DEFAULT 'generic',  -- process_create | net_connect | cve_finding | ...
  title               text         NOT NULL,
  description         text,

  -- Asset reference (denormalised for query performance)
  asset_id            uuid         REFERENCES assets(id) ON DELETE SET NULL,
  asset_hostname      text,
  asset_ip            text,
  asset_os            text,
  asset_criticality   text         CHECK (asset_criticality IN ('critical', 'high', 'medium', 'low')),
  business_impact     text         CHECK (business_impact IN ('revenue', 'compliance', 'operational', 'reputational', 'low')),

  -- Vulnerability intelligence (CVSS/EPSS/KEV) — NULL for non-CVE events
  cve_id              text,
  cvss_score          numeric(4,1),           -- e.g. 9.8
  cvss_vector         text,                   -- CVSS:3.1/AV:N/AC:L/...
  epss_score          numeric(7,6),           -- 0.000000 – 1.000000
  epss_percentile     numeric(5,2),           -- 0.00 – 100.00
  kev_listed          boolean      NOT NULL DEFAULT false,  -- in CISA KEV catalogue
  kev_date_added      date,
  vendor_severity     text,                   -- raw severity string from vendor

  -- Context blobs
  process_context     jsonb,
  network_context     jsonb,
  auth_context        jsonb,
  file_context        jsonb,
  finding_context     jsonb,                  -- vulnerability-specific details

  -- Finding lifecycle
  status              text         NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open', 'investigating', 'remediated', 'closed', 'suppressed', 'false_positive')),
  incident_id         uuid         REFERENCES incidents(id) ON DELETE SET NULL,
  closed_at           timestamptz,
  recheck_at          timestamptz,            -- scheduled continuous recheck time

  -- Evidence
  tags                text[]       NOT NULL DEFAULT '{}',
  evidence_ids        text[]       NOT NULL DEFAULT '{}',   -- refs to hash_chain_audit
  raw_payload         jsonb        NOT NULL DEFAULT '{}',

  created_at          timestamptz  NOT NULL DEFAULT now(),
  updated_at          timestamptz  NOT NULL DEFAULT now(),

  -- Deduplication: one fingerprint per tenant
  UNIQUE (tenant_id, dedup_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_security_events_tenant_ts
  ON security_events (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_status
  ON security_events (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_security_events_cve
  ON security_events (cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_asset
  ON security_events (asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_incident
  ON security_events (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_kev
  ON security_events (tenant_id, kev_listed) WHERE kev_listed = true;
CREATE INDEX IF NOT EXISTS idx_security_events_recheck
  ON security_events (recheck_at) WHERE recheck_at IS NOT NULL AND status = 'remediated';

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'security_events' AND policyname = 'tenant_isolation_security_events'
  ) THEN
    CREATE POLICY tenant_isolation_security_events
      ON security_events
      USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. connector_config — per-tenant connector registration and health state
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS connector_config (
  id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     text         NOT NULL,
  connector_id  text         NOT NULL,          -- unique slug: wazuh-prod, trivy-ci, openvas-dmz
  connector_type text        NOT NULL,          -- wazuh | trivy | openvas | defender | crowdstrike
  display_name  text         NOT NULL,
  enabled       boolean      NOT NULL DEFAULT true,

  -- Connection parameters (stored encrypted at rest via Supabase column encryption or Vault)
  base_url      text,
  auth_type     text         NOT NULL DEFAULT 'api_key'
                CHECK (auth_type IN ('api_key', 'basic', 'bearer', 'oauth2', 'mtls')),
  auth_config   jsonb        NOT NULL DEFAULT '{}',  -- encrypted credentials reference

  -- Health
  last_health_check_at  timestamptz,
  last_health_status    text CHECK (last_health_status IN ('healthy', 'degraded', 'unreachable', 'auth_failed', 'unknown')),
  last_health_message   text,

  -- Tuning
  poll_interval_seconds integer     NOT NULL DEFAULT 300,
  max_events_per_poll   integer     NOT NULL DEFAULT 1000,

  created_at    timestamptz  NOT NULL DEFAULT now(),
  updated_at    timestamptz  NOT NULL DEFAULT now(),

  UNIQUE (tenant_id, connector_id)
);

CREATE INDEX IF NOT EXISTS idx_connector_config_tenant
  ON connector_config (tenant_id);

ALTER TABLE connector_config ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'connector_config' AND policyname = 'tenant_isolation_connector_config'
  ) THEN
    CREATE POLICY tenant_isolation_connector_config
      ON connector_config
      USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 3. connector_cursors — incremental collection state per connector
--    Persists the last-seen cursor so restarts are resumable without gaps.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS connector_cursors (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       text        NOT NULL,
  connector_id    text        NOT NULL,
  cursor_type     text        NOT NULL DEFAULT 'timestamp'
                  CHECK (cursor_type IN ('timestamp', 'offset', 'sequence', 'bookmark')),
  cursor_value    text        NOT NULL,           -- opaque; interpreted by connector
  events_fetched  bigint      NOT NULL DEFAULT 0,
  last_collect_at timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),

  UNIQUE (tenant_id, connector_id)
);

CREATE INDEX IF NOT EXISTS idx_connector_cursors_tenant
  ON connector_cursors (tenant_id);

ALTER TABLE connector_cursors ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'connector_cursors' AND policyname = 'tenant_isolation_connector_cursors'
  ) THEN
    CREATE POLICY tenant_isolation_connector_cursors
      ON connector_cursors
      USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 4. asset_vulnerabilities — normalised vulnerability findings per asset
--    One row per (asset × CVE). Supports dedup and correlation across
--    multiple scanners reporting the same finding.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           text        NOT NULL,
  asset_id            uuid        REFERENCES assets(id) ON DELETE CASCADE,
  asset_hostname      text        NOT NULL,
  cve_id              text        NOT NULL,
  package_name        text,
  installed_version   text,
  fixed_version       text,
  cvss_score          numeric(4,1),
  cvss_vector         text,
  epss_score          numeric(7,6),
  epss_percentile     numeric(5,2),
  kev_listed          boolean     NOT NULL DEFAULT false,
  kev_date_added      date,
  vendor_severity     text,
  scanner_source      text        NOT NULL,       -- trivy | openvas | wazuh | defender
  first_seen_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  status              text        NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open', 'remediated', 'suppressed', 'false_positive', 'accepted_risk')),
  remediated_at       timestamptz,
  security_event_ids  text[]      NOT NULL DEFAULT '{}',  -- linked security_events.id values

  UNIQUE (tenant_id, asset_hostname, cve_id, scanner_source)
);

CREATE INDEX IF NOT EXISTS idx_asset_vuln_tenant
  ON asset_vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_vuln_cve
  ON asset_vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_asset_vuln_asset
  ON asset_vulnerabilities (asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_vuln_kev
  ON asset_vulnerabilities (tenant_id, kev_listed) WHERE kev_listed = true;
CREATE INDEX IF NOT EXISTS idx_asset_vuln_status
  ON asset_vulnerabilities (tenant_id, status);

ALTER TABLE asset_vulnerabilities ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'asset_vulnerabilities' AND policyname = 'tenant_isolation_asset_vulnerabilities'
  ) THEN
    CREATE POLICY tenant_isolation_asset_vulnerabilities
      ON asset_vulnerabilities
      USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 5. Additive columns on assets table: criticality and business impact
--    These fields are used by the attack-path and blast-radius engines.
-- ---------------------------------------------------------------------------
ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality    text CHECK (criticality IN ('critical', 'high', 'medium', 'low'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_impact text CHECK (business_impact IN ('revenue', 'compliance', 'operational', 'reputational', 'low'));
ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_value_usd integer;  -- estimated annual business value
ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_family      text;       -- windows | linux | macos | other
ALTER TABLE assets ADD COLUMN IF NOT EXISTS tags           text[]  NOT NULL DEFAULT '{}';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at     timestamptz NOT NULL DEFAULT now();

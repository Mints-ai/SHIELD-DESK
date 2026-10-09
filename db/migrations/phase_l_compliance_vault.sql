-- =============================================================================
-- ShieldDesk SD-028: Enterprise Compliance & Audit Platform
-- Schema Migration: compliance_policies, cve_vulnerabilities view, & audit indexes
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Compliance Policies Table
-- Stores internal governance, risk, and compliance policies linked to controls
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_policies (
  id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           VARCHAR(64)   NOT NULL,
  policy_code         VARCHAR(64)   NOT NULL,
  title               VARCHAR(255)  NOT NULL,
  category            VARCHAR(64)   NOT NULL,
  status              VARCHAR(32)   NOT NULL DEFAULT 'active', -- active, draft, archived
  version             VARCHAR(32)   NOT NULL DEFAULT '1.0',
  description         TEXT,
  document_url        TEXT,
  control_mappings    TEXT[]        NOT NULL DEFAULT '{}',
  uploaded_by         VARCHAR(128)  NOT NULL,
  effective_date      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  review_date         TIMESTAMPTZ   NOT NULL DEFAULT (NOW() + INTERVAL '1 year'),
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_policies_tenant
  ON compliance_policies (tenant_id);

CREATE INDEX IF NOT EXISTS idx_compliance_policies_code
  ON compliance_policies (policy_code);

CREATE INDEX IF NOT EXISTS idx_compliance_policies_status
  ON compliance_policies (tenant_id, status);

-- Enable Row Level Security on compliance_policies
ALTER TABLE compliance_policies ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'compliance_policies'
      AND policyname = 'compliance_policies_tenant_isolation'
  ) THEN
    CREATE POLICY compliance_policies_tenant_isolation ON compliance_policies
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Optimization Indexes for Hash-Chain Audit Ledger Isolation
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_hash_chain_tenant_created
  ON hash_chain_audit (tenant_id, created_at ASC, id ASC);

CREATE INDEX IF NOT EXISTS idx_hash_chain_event_type
  ON hash_chain_audit (tenant_id, event_type);

-- ---------------------------------------------------------------------------
-- View: cve_vulnerabilities (Unified vulnerability mapping across assets)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW cve_vulnerabilities AS
SELECT
  id,
  tenant_id,
  cve_id,
  asset_hostname,
  package_name,
  installed_version,
  fixed_version,
  cvss_score,
  cvss_vector,
  epss_score,
  kev_listed,
  vendor_severity,
  scanner_source,
  status,
  first_seen_at,
  last_seen_at,
  remediated_at
FROM asset_vulnerabilities;

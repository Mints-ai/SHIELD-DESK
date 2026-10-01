-- =============================================================================
-- ShieldDesk Phase F: Evidence Vault
-- Additive Schema Migration: compliance_export_bundles
-- =============================================================================

CREATE TABLE IF NOT EXISTS compliance_export_bundles (
  id                  VARCHAR(64)   PRIMARY KEY,
  tenant_id           VARCHAR(64)   NOT NULL,
  format              VARCHAR(16)   NOT NULL DEFAULT 'json', -- json, csv
  exported_by         VARCHAR(128)  NOT NULL,
  total_events        INTEGER       NOT NULL DEFAULT 0,
  chain_head_hash     VARCHAR(64)   NOT NULL,
  merkle_root         VARCHAR(64)   NOT NULL,
  signature           VARCHAR(128)  NOT NULL,
  exported_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_export_tenant
  ON compliance_export_bundles (tenant_id);

CREATE INDEX IF NOT EXISTS idx_compliance_export_date
  ON compliance_export_bundles (tenant_id, exported_at DESC);

-- Enable Row Level Security
ALTER TABLE compliance_export_bundles ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'compliance_export_bundles'
      AND policyname = 'compliance_export_bundles_tenant_isolation'
  ) THEN
    CREATE POLICY compliance_export_bundles_tenant_isolation ON compliance_export_bundles
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

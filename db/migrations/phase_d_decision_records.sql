-- =============================================================================
-- ShieldDesk Phase D: Risk and Decision Engine
-- Additive Schema Migration: decision_records
-- =============================================================================

CREATE TABLE IF NOT EXISTS decision_records (
  id                    VARCHAR(64)   PRIMARY KEY,
  tenant_id             VARCHAR(64)   NOT NULL,
  incident_id           VARCHAR(128),
  asset_id              VARCHAR(128),
  action                VARCHAR(128)  NOT NULL,
  decision              VARCHAR(32)   NOT NULL,
  autonomy_tier         VARCHAR(16)   NOT NULL DEFAULT 'Tier 1',
  autonomy_mode         VARCHAR(16)   NOT NULL DEFAULT 'assist',
  security_confidence   NUMERIC(4,2)  NOT NULL DEFAULT 0.85,
  ai_confidence         NUMERIC(4,2),
  risk_score            NUMERIC(5,2)  NOT NULL DEFAULT 0.0,
  risk_factors          JSONB         NOT NULL DEFAULT '[]'::jsonb,
  blast_radius_score    INTEGER       NOT NULL DEFAULT 0,
  evidence_ids          JSONB         NOT NULL DEFAULT '[]'::jsonb,
  evidence              JSONB         NOT NULL DEFAULT '[]'::jsonb,
  reason                TEXT          NOT NULL,
  required_approvals    INTEGER       NOT NULL DEFAULT 0,
  enforce_mfa           BOOLEAN       NOT NULL DEFAULT FALSE,
  actor                 JSONB         NOT NULL DEFAULT '{}'::jsonb,
  decision_hash         VARCHAR(64)   NOT NULL,
  evaluated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_decision_records_tenant
  ON decision_records (tenant_id);

CREATE INDEX IF NOT EXISTS idx_decision_records_asset
  ON decision_records (tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_decision_records_decision
  ON decision_records (tenant_id, decision);

CREATE INDEX IF NOT EXISTS idx_decision_records_created
  ON decision_records (created_at DESC);

-- Enable Row-Level Security
ALTER TABLE decision_records ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'decision_records'
      AND policyname = 'decision_records_tenant_isolation'
  ) THEN
    CREATE POLICY decision_records_tenant_isolation ON decision_records
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

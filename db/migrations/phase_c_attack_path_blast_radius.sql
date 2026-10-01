-- =============================================================================
-- ShieldDesk Phase C: Attack-Path & Blast-Radius Engines
-- Additive Schema Migration
-- =============================================================================

-- 1. Attack Path Analysis Reports Table
CREATE TABLE IF NOT EXISTS attack_path_reports (
  id                      VARCHAR(64)   PRIMARY KEY,
  tenant_id               VARCHAR(64)   NOT NULL,
  target_asset_id         VARCHAR(128)  NOT NULL,
  paths_found_count       INTEGER       NOT NULL DEFAULT 0,
  highest_risk_score      INTEGER       NOT NULL DEFAULT 0,
  critical_choke_points   JSONB         NOT NULL DEFAULT '[]'::jsonb,
  paths                   JSONB         NOT NULL DEFAULT '[]'::jsonb,
  summary                 TEXT,
  analyzed_at             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_path_reports_tenant
  ON attack_path_reports (tenant_id);

CREATE INDEX IF NOT EXISTS idx_attack_path_reports_target
  ON attack_path_reports (tenant_id, target_asset_id);

CREATE INDEX IF NOT EXISTS idx_attack_path_reports_created
  ON attack_path_reports (created_at DESC);

-- Enable RLS on attack_path_reports
ALTER TABLE attack_path_reports ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'attack_path_reports'
      AND policyname = 'attack_path_reports_tenant_isolation'
  ) THEN
    CREATE POLICY attack_path_reports_tenant_isolation ON attack_path_reports
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;


-- 2. Blast Radius Reports Table
CREATE TABLE IF NOT EXISTS blast_radius_reports (
  id                      VARCHAR(64)   PRIMARY KEY,
  tenant_id               VARCHAR(64)   NOT NULL,
  target_asset_id         VARCHAR(128)  NOT NULL,
  action                  VARCHAR(128)  NOT NULL,
  score                   INTEGER       NOT NULL DEFAULT 0,
  exceeded                BOOLEAN       NOT NULL DEFAULT FALSE,
  calculation_mode        VARCHAR(32)   NOT NULL DEFAULT 'measured',
  confidence              NUMERIC(4,2)  NOT NULL DEFAULT 0.90,
  affected_assets         JSONB         NOT NULL DEFAULT '[]'::jsonb,
  affected_services       JSONB         NOT NULL DEFAULT '[]'::jsonb,
  affected_apps           JSONB         NOT NULL DEFAULT '[]'::jsonb,
  affected_users          JSONB         NOT NULL DEFAULT '[]'::jsonb,
  sensitive_systems       JSONB         NOT NULL DEFAULT '{}'::jsonb,
  estimated_downtime      JSONB         NOT NULL DEFAULT '{}'::jsonb,
  rollback_availability   JSONB         NOT NULL DEFAULT '{}'::jsonb,
  security_impact         JSONB         NOT NULL DEFAULT '{}'::jsonb,
  business_impact         JSONB         NOT NULL DEFAULT '{}'::jsonb,
  evidence                JSONB         NOT NULL DEFAULT '[]'::jsonb,
  created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blast_radius_reports_tenant
  ON blast_radius_reports (tenant_id);

CREATE INDEX IF NOT EXISTS idx_blast_radius_reports_target
  ON blast_radius_reports (tenant_id, target_asset_id);

CREATE INDEX IF NOT EXISTS idx_blast_radius_reports_created
  ON blast_radius_reports (created_at DESC);

-- Enable RLS on blast_radius_reports
ALTER TABLE blast_radius_reports ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'blast_radius_reports'
      AND policyname = 'blast_radius_reports_tenant_isolation'
  ) THEN
    CREATE POLICY blast_radius_reports_tenant_isolation ON blast_radius_reports
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

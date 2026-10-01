-- =============================================================================
-- ShieldDesk Phase E: Remediation Simulator & Verification Engine
-- Additive Schema Migration
-- =============================================================================

-- 1. Remediation Simulation Plans Table (Root-cause grouping & predictive simulations)
CREATE TABLE IF NOT EXISTS remediation_simulation_plans (
  id                      VARCHAR(64)   PRIMARY KEY,
  tenant_id               VARCHAR(64)   NOT NULL,
  root_cause_id           VARCHAR(128)  NOT NULL,
  title                   VARCHAR(256)  NOT NULL,
  findings_count          INTEGER       NOT NULL DEFAULT 1,
  affected_assets         JSONB         NOT NULL DEFAULT '[]'::jsonb,
  simulation_results      JSONB         NOT NULL DEFAULT '{}'::jsonb,
  recommended_action      VARCHAR(128)  NOT NULL,
  maintenance_window      VARCHAR(64)   NOT NULL DEFAULT 'scheduled_off_peak',
  status                  VARCHAR(32)   NOT NULL DEFAULT 'simulated',
  created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_sim_tenant
  ON remediation_simulation_plans (tenant_id);

CREATE INDEX IF NOT EXISTS idx_remediation_sim_root_cause
  ON remediation_simulation_plans (tenant_id, root_cause_id);

-- Enable RLS
ALTER TABLE remediation_simulation_plans ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'remediation_simulation_plans'
      AND policyname = 'remediation_simulation_plans_tenant_isolation'
  ) THEN
    CREATE POLICY remediation_simulation_plans_tenant_isolation ON remediation_simulation_plans
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;


-- 2. Remediation Verifications Table (Proofs of post-execution state & rollbacks)
CREATE TABLE IF NOT EXISTS remediation_verifications (
  id                      VARCHAR(64)   PRIMARY KEY,
  tenant_id               VARCHAR(64)   NOT NULL,
  command_id              VARCHAR(128)  NOT NULL,
  agent_id                VARCHAR(128)  NOT NULL,
  finding_id              VARCHAR(128),
  status                  VARCHAR(32)   NOT NULL, -- VERIFIED, FAILED, ROLLBACK_TRIGGERED
  checks                  JSONB         NOT NULL DEFAULT '[]'::jsonb,
  proof_of_state          JSONB         NOT NULL DEFAULT '{}'::jsonb,
  rollback_executed       BOOLEAN       NOT NULL DEFAULT FALSE,
  failure_reason          TEXT,
  verification_hash       VARCHAR(64)   NOT NULL,
  verified_at             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remediation_verif_tenant
  ON remediation_verifications (tenant_id);

CREATE INDEX IF NOT EXISTS idx_remediation_verif_command
  ON remediation_verifications (tenant_id, command_id);

CREATE INDEX IF NOT EXISTS idx_remediation_verif_status
  ON remediation_verifications (tenant_id, status);

-- Enable RLS
ALTER TABLE remediation_verifications ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'remediation_verifications'
      AND policyname = 'remediation_verifications_tenant_isolation'
  ) THEN
    CREATE POLICY remediation_verifications_tenant_isolation ON remediation_verifications
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;


-- 3. Continuous Recheck Schedules Table (Drift detection for closed findings)
CREATE TABLE IF NOT EXISTS continuous_recheck_schedules (
  id                      VARCHAR(64)   PRIMARY KEY,
  tenant_id               VARCHAR(64)   NOT NULL,
  finding_id              VARCHAR(128)  NOT NULL,
  asset_id                VARCHAR(128)  NOT NULL,
  action                  VARCHAR(128)  NOT NULL,
  check_spec              JSONB         NOT NULL DEFAULT '{}'::jsonb,
  frequency_hours         INTEGER       NOT NULL DEFAULT 24,
  last_recheck_at         TIMESTAMPTZ,
  next_recheck_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  consecutive_passes      INTEGER       NOT NULL DEFAULT 0,
  status                  VARCHAR(32)   NOT NULL DEFAULT 'active', -- active, drift_detected, completed
  created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_continuous_recheck_tenant
  ON continuous_recheck_schedules (tenant_id);

CREATE INDEX IF NOT EXISTS idx_continuous_recheck_next
  ON continuous_recheck_schedules (status, next_recheck_at);

CREATE INDEX IF NOT EXISTS idx_continuous_recheck_finding
  ON continuous_recheck_schedules (tenant_id, finding_id);

-- Enable RLS
ALTER TABLE continuous_recheck_schedules ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE tablename = 'continuous_recheck_schedules'
      AND policyname = 'continuous_recheck_schedules_tenant_isolation'
  ) THEN
    CREATE POLICY continuous_recheck_schedules_tenant_isolation ON continuous_recheck_schedules
      FOR ALL
      USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

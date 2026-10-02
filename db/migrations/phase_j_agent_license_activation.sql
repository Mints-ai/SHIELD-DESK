CREATE TABLE IF NOT EXISTS agent_license_activations (
  tenant_id VARCHAR(64) NOT NULL,
  installation_id VARCHAR(128) NOT NULL,
  device_identity VARCHAR(128) NOT NULL,
  certificate_fingerprint VARCHAR(64) NOT NULL,
  license_id VARCHAR(128) NOT NULL,
  license_expires_at TIMESTAMPTZ NOT NULL,
  state VARCHAR(16) NOT NULL CHECK (state IN ('TRIAL','ACTIVE','PAST_DUE','SUSPENDED','EXPIRED','REVOKED')),
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_heartbeat_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, installation_id),
  UNIQUE (tenant_id, device_identity)
);

ALTER TABLE agent_license_activations ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'agent_license_activations' AND policyname = 'agent_license_activations_tenant_isolation') THEN
    CREATE POLICY agent_license_activations_tenant_isolation ON agent_license_activations
      FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
      WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END $$;

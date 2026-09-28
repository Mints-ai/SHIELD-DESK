-- ============================================================
-- ShieldDesk Launch-Readiness SQL Migration
-- Run this in the Supabase SQL Editor:
-- https://supabase.com/dashboard/project/dpuotfxyfqvwggewczhs/sql/new
-- ============================================================

-- 1. TOTP / MFA columns on users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

-- 2. Tier 3 dual-approval: second approver column on approval_tokens
ALTER TABLE approval_tokens ADD COLUMN IF NOT EXISTS secondary_approved_by text REFERENCES users(id);

-- 3. DB-level constraint: two approvers for Tier 3 must be distinct people
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'check_tier3_dual_approval_separation'
  ) THEN
    ALTER TABLE approval_tokens
      ADD CONSTRAINT check_tier3_dual_approval_separation
        CHECK (secondary_approved_by IS NULL OR approved_by <> secondary_approved_by);
  END IF;
END
$$;

-- 4. agent_commands table (from automated-remediation pass — run if not already applied)
CREATE TABLE IF NOT EXISTS agent_commands (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id      uuid NOT NULL REFERENCES endpoint_agents(id) ON DELETE CASCADE,
  tenant_id     text NOT NULL,
  command       text NOT NULL,
  tier          text NOT NULL CHECK (tier IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')),
  token_id      uuid REFERENCES approval_tokens(id),
  signature     text NOT NULL,
  status        text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'delivered', 'executed', 'failed', 'rolled_back')),
  result        jsonb,
  snapshot_id   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  delivered_at  timestamptz,
  completed_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_status ON agent_commands (agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_commands_tenant_created ON agent_commands (tenant_id, created_at);
ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;

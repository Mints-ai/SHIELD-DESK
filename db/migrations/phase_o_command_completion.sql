BEGIN;

-- Bind a task to its current dispatch, including Tier 1 commands without tokens.
ALTER TABLE mitigation_tasks ADD COLUMN IF NOT EXISTS execution_command_id uuid;
CREATE INDEX IF NOT EXISTS idx_mitigation_tasks_execution_command
    ON mitigation_tasks (execution_command_id) WHERE execution_command_id IS NOT NULL;

ALTER TABLE mitigation_tasks DROP CONSTRAINT IF EXISTS mitigation_tasks_status_check;
ALTER TABLE mitigation_tasks ADD CONSTRAINT mitigation_tasks_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'in_progress', 'completed', 'failed'));

ALTER TABLE agent_commands DROP CONSTRAINT IF EXISTS agent_commands_status_check;
ALTER TABLE agent_commands ADD CONSTRAINT agent_commands_status_check CHECK (status IN (
    'requested', 'authorised', 'signed', 'queued', 'delivered', 'acknowledged',
    'executing', 'executed', 'verified', 'failed', 'rolled_back', 'cancelled',
    'expired', 'delivery_failed', 'execution_failed', 'verification_failed'
));

COMMIT;

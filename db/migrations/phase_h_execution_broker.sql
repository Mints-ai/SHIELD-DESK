-- ============================================================================
-- Phase H: Execution Broker, Hardened Agent & mTLS Lifecycle Schema Migration
-- Strictly Additive & Reversible
-- ============================================================================

-- 1. Ephemeral Execution Dispatch Tokens (Short-Lived Credentials)
CREATE TABLE IF NOT EXISTS execution_dispatch_tokens (
    id VARCHAR(64) PRIMARY KEY,
    command_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    tier VARCHAR(16) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- active, consumed, expired, revoked
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dispatch_tokens_lookup 
    ON execution_dispatch_tokens (command_id, agent_id, status);

-- 2. Signed Agent Update Manifests
CREATE TABLE IF NOT EXISTS agent_update_manifests (
    id VARCHAR(64) PRIMARY KEY,
    version VARCHAR(32) NOT NULL,
    platform VARCHAR(32) NOT NULL, -- linux_amd64, windows_amd64, etc.
    binary_url TEXT NOT NULL,
    sha256_checksum VARCHAR(64) NOT NULL,
    min_agent_version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    signature TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_manifest_ver_platform UNIQUE (version, platform)
);

CREATE INDEX IF NOT EXISTS idx_agent_manifests_active 
    ON agent_update_manifests (platform, is_active);

-- 3. Agent Update Audit Ledger & Rollback Events
CREATE TABLE IF NOT EXISTS agent_update_events (
    id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    from_version VARCHAR(32) NOT NULL,
    target_version VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL, -- initiated, canary_healthy, verified, rolled_back, failed
    checksum_verified BOOLEAN NOT NULL DEFAULT false,
    signature_verified BOOLEAN NOT NULL DEFAULT false,
    canary_latency_ms INTEGER,
    rollback_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_update_events_agent 
    ON agent_update_events (agent_id, created_at DESC);

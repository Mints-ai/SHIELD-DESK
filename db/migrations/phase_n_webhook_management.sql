-- ============================================================================
-- Phase N: Tenant Webhook Endpoints & Delivery Audit Ledger
-- Strictly Additive, Idempotent, and Reversible
-- ============================================================================

-- 1. Tenant Webhook Endpoints Table (Dynamic UI & DB Configuration)
CREATE TABLE IF NOT EXISTS tenant_webhook_endpoints (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL, -- 'slack', 'discord', 'teams', 'generic'
    destination TEXT NOT NULL,
    secret_key TEXT,
    events TEXT[] NOT NULL DEFAULT ARRAY['threat_detected', 'approval_required', 'incident_created', 'lockdown.activated'],
    min_severity VARCHAR(16) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_webhook_endpoints_tenant 
    ON tenant_webhook_endpoints (tenant_id, enabled);

-- 2. Webhook Delivery Logs Table (Audit Trail & DLQ Retry Ledger)
CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id VARCHAR(64) PRIMARY KEY,
    delivery_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    endpoint_id VARCHAR(64) NOT NULL,
    endpoint_name VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16),
    status_code INT,
    latency_ms INT,
    payload JSONB,
    response_body TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_tenant_created 
    ON webhook_delivery_logs (tenant_id, created_at DESC);

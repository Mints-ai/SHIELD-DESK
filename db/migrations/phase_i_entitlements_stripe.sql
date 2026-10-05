-- ============================================================================
-- Phase I: SaaS Licensing, Entitlements, Offline Cache & Stripe Webhook Schema
-- Strictly Additive & Reversible
-- ============================================================================

-- 1. Tenant Commercial Licenses
CREATE TABLE IF NOT EXISTS tenant_licenses (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    license_key TEXT NOT NULL,
    tier VARCHAR(32) NOT NULL DEFAULT 'community', -- community, professional, enterprise
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- draft, active, suspended, grace_period, expired, revoked
    max_endpoints INTEGER NOT NULL DEFAULT 5,
    max_users INTEGER NOT NULL DEFAULT 10,
    features TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    activated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    grace_period_days INTEGER NOT NULL DEFAULT 7,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_licenses_tenant_status 
    ON tenant_licenses (tenant_id, status);

-- 2. Stripe Webhook Events Idempotency & Queue Ledger
CREATE TABLE IF NOT EXISTS stripe_events_processed (
    id VARCHAR(64) PRIMARY KEY,
    stripe_event_id VARCHAR(128) NOT NULL UNIQUE,
    event_type VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, processing, processed, failed, duplicate
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_stripe_events_status 
    ON stripe_events_processed (status, created_at DESC);

-- 3. Signed Offline Entitlement Caches (Air-Gapped / Disconnected Environments)
CREATE TABLE IF NOT EXISTS offline_entitlement_caches (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    tier VARCHAR(32) NOT NULL,
    max_endpoints INTEGER NOT NULL,
    allowed_features TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    cache_token TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    grace_until TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_offline_caches_lookup 
    ON offline_entitlement_caches (tenant_id, is_revoked, expires_at);

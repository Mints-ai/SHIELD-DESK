-- ============================================================================
-- Phase M: Commercial Licensing, Stripe Billing & Customer Purchase Schema
-- Strictly Additive, Idempotent, and Reversible
-- ============================================================================

-- 1. Billing Customers (Binds authenticated tenant to Stripe Customer)
CREATE TABLE IF NOT EXISTS billing_customers (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL UNIQUE,
    stripe_customer_id VARCHAR(128) NOT NULL UNIQUE,
    billing_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_customers_lookup 
    ON billing_customers (tenant_id, stripe_customer_id);

-- 2. Product Catalogue and Price Mappings
CREATE TABLE IF NOT EXISTS product_catalog_prices (
    id VARCHAR(64) PRIMARY KEY,
    plan_id VARCHAR(32) NOT NULL, -- community, professional, enterprise
    billing_interval VARCHAR(16) NOT NULL, -- month, year
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    stripe_price_id VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    entitlement_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (plan_id, billing_interval, currency)
);

CREATE INDEX IF NOT EXISTS idx_product_catalog_prices_lookup 
    ON product_catalog_prices (plan_id, billing_interval, is_active);

-- 3. Checkout Attempts (Pre-checkout ledger and correlation)
CREATE TABLE IF NOT EXISTS checkout_attempts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    initiating_user_id VARCHAR(64) NOT NULL,
    stripe_checkout_session_id VARCHAR(128) UNIQUE,
    plan_id VARCHAR(32) NOT NULL,
    billing_interval VARCHAR(16) NOT NULL DEFAULT 'month',
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    deployment_type VARCHAR(32) NOT NULL DEFAULT 'saas', -- saas, customer-hosted
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, completed, expired, failed
    idempotency_key VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_checkout_attempts_tenant 
    ON checkout_attempts (tenant_id, status, created_at DESC);

-- 4. Tenant Subscriptions (Canonical state of tenant subscription)
CREATE TABLE IF NOT EXISTS tenant_subscriptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL UNIQUE,
    stripe_customer_id VARCHAR(128),
    stripe_subscription_id VARCHAR(128) UNIQUE,
    tier VARCHAR(32) NOT NULL DEFAULT 'community', -- community, professional, enterprise
    billing_interval VARCHAR(16) NOT NULL DEFAULT 'month',
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- trialing, active, past_due, grace_period, suspended, cancelled, expired
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    canceled_at TIMESTAMPTZ,
    grace_period_until TIMESTAMPTZ,
    entitlement_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- In case tenant_subscriptions already exists from previous phases, ensure required columns exist:
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenant_subscriptions' AND column_name = 'stripe_customer_id') THEN
        ALTER TABLE tenant_subscriptions ADD COLUMN stripe_customer_id VARCHAR(128);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenant_subscriptions' AND column_name = 'billing_interval') THEN
        ALTER TABLE tenant_subscriptions ADD COLUMN billing_interval VARCHAR(16) NOT NULL DEFAULT 'month';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenant_subscriptions' AND column_name = 'cancel_at_period_end') THEN
        ALTER TABLE tenant_subscriptions ADD COLUMN cancel_at_period_end BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenant_subscriptions' AND column_name = 'canceled_at') THEN
        ALTER TABLE tenant_subscriptions ADD COLUMN canceled_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenant_subscriptions' AND column_name = 'grace_period_until') THEN
        ALTER TABLE tenant_subscriptions ADD COLUMN grace_period_until TIMESTAMPTZ;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tenant_subscriptions_tenant_status 
    ON tenant_subscriptions (tenant_id, status);

-- 5. Subscription Status Transition Audit History
CREATE TABLE IF NOT EXISTS subscription_status_history (
    id VARCHAR(64) PRIMARY KEY,
    subscription_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    reason VARCHAR(255),
    actor_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    transitioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sub_history_tenant 
    ON subscription_status_history (tenant_id, transitioned_at DESC);

-- 6. Invoices
CREATE TABLE IF NOT EXISTS invoices (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subscription_id VARCHAR(64),
    stripe_invoice_id VARCHAR(128) NOT NULL UNIQUE,
    invoice_number VARCHAR(64),
    currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    amount_due_cents INTEGER NOT NULL DEFAULT 0,
    amount_paid_cents INTEGER NOT NULL DEFAULT 0,
    amount_remaining_cents INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'draft', -- draft, open, paid, void, uncollectible, failed
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    hosted_invoice_url TEXT,
    invoice_pdf_url TEXT,
    paid_at TIMESTAMPTZ,
    due_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_tenant 
    ON invoices (tenant_id, status, created_at DESC);

-- 7. Product Licenses (Never persists raw secret; stores keyed digest & safe display hints)
CREATE TABLE IF NOT EXISTS product_licenses (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subscription_id VARCHAR(64),
    license_key_hash VARCHAR(128) NOT NULL UNIQUE, -- SHA-256(pepper + key)
    display_prefix VARCHAR(16) NOT NULL, -- e.g. 'SD-PRO'
    display_suffix VARCHAR(16) NOT NULL, -- e.g. '9F2B'
    tier VARCHAR(32) NOT NULL DEFAULT 'community',
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- draft, active, grace_period, suspended, expired, revoked
    max_endpoints INTEGER NOT NULL DEFAULT 5,
    max_users INTEGER NOT NULL DEFAULT 10,
    features TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    signing_key_id VARCHAR(64) NOT NULL DEFAULT 'sd-k1',
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    grace_period_days INTEGER NOT NULL DEFAULT 14,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    replaces_license_id VARCHAR(64),
    replaced_by_license_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_product_licenses_lookup 
    ON product_licenses (tenant_id, status, expires_at);

-- 8. License Activations (Hardware & Installation binding with challenge verification)
CREATE TABLE IF NOT EXISTS license_activations (
    id VARCHAR(64) PRIMARY KEY,
    license_id VARCHAR(64) NOT NULL REFERENCES product_licenses(id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    installation_id VARCHAR(128) NOT NULL,
    device_identity VARCHAR(128) NOT NULL,
    certificate_fingerprint VARCHAR(128) NOT NULL,
    platform VARCHAR(32) NOT NULL DEFAULT 'linux', -- linux, windows, macos
    product_version VARCHAR(32) NOT NULL DEFAULT '2.4.0',
    activation_state VARCHAR(32) NOT NULL DEFAULT 'active', -- active, past_due, suspended, revoked, deactivated
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    deactivation_reason TEXT,
    UNIQUE (tenant_id, installation_id),
    UNIQUE (tenant_id, device_identity)
);

CREATE INDEX IF NOT EXISTS idx_license_activations_lookup 
    ON license_activations (tenant_id, license_id, activation_state);

-- 9. Durable Stripe Webhook Inbox (Replacing process-local Maps)
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id VARCHAR(64) PRIMARY KEY,
    stripe_event_id VARCHAR(128) NOT NULL UNIQUE,
    event_type VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, processing, processed, failed, duplicate
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    retry_count INTEGER NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_stripe_inbox_queue 
    ON stripe_webhook_events (status, lease_expires_at, created_at ASC);

-- 10. Notification Outbox (Transactional outbox for reliable asynchronous side effects)
CREATE TABLE IF NOT EXISTS notification_outbox (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    topic VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending, delivered, failed
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notification_outbox_pending 
    ON notification_outbox (status, created_at ASC);

-- 11. Row-Level Security Enablement
ALTER TABLE billing_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkout_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_status_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE product_licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;

-- 12. RLS Tenant Isolation Policies
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'billing_customers' AND policyname = 'billing_customers_tenant_isolation') THEN
        CREATE POLICY billing_customers_tenant_isolation ON billing_customers
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'checkout_attempts' AND policyname = 'checkout_attempts_tenant_isolation') THEN
        CREATE POLICY checkout_attempts_tenant_isolation ON checkout_attempts
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'tenant_subscriptions' AND policyname = 'tenant_subscriptions_tenant_isolation') THEN
        CREATE POLICY tenant_subscriptions_tenant_isolation ON tenant_subscriptions
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'invoices' AND policyname = 'invoices_tenant_isolation') THEN
        CREATE POLICY invoices_tenant_isolation ON invoices
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'product_licenses' AND policyname = 'product_licenses_tenant_isolation') THEN
        CREATE POLICY product_licenses_tenant_isolation ON product_licenses
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'license_activations' AND policyname = 'license_activations_tenant_isolation') THEN
        CREATE POLICY license_activations_tenant_isolation ON license_activations
            FOR ALL USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;
END $$;

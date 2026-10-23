-- ============================================================================
-- Phase P: Webhook Delivery DLQ, Latency Tracking & Audit Ledger
-- Strictly Additive, Idempotent, and Reversible
-- ============================================================================

ALTER TABLE webhook_delivery_logs
  ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS is_dlq BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'DELIVERED',
  ADD COLUMN IF NOT EXISTS error_message TEXT,
  ADD COLUMN IF NOT EXISTS destination TEXT,
  ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_dlq 
  ON webhook_delivery_logs (tenant_id, is_dlq, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_status 
  ON webhook_delivery_logs (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_endpoint 
  ON webhook_delivery_logs (endpoint_id);

-- ============================================================================
-- Phase G: AI Layer, Governance & Evaluation Lab Schema Migration
-- Strictly Additive & Reversible
-- ============================================================================

-- 1. AI Prompt & Model Versioning Table
CREATE TABLE IF NOT EXISTS ai_prompt_versions (
    id VARCHAR(64) PRIMARY KEY,
    prompt_name VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    provider VARCHAR(64) NOT NULL DEFAULT 'ollama',
    model_name VARCHAR(128) NOT NULL DEFAULT 'qwen3:4b',
    system_prompt TEXT NOT NULL,
    user_template TEXT NOT NULL,
    temperature NUMERIC(3,2) NOT NULL DEFAULT 0.10,
    schema_definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    sha256_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ai_prompt_name_version UNIQUE (prompt_name, version)
);

CREATE INDEX IF NOT EXISTS idx_ai_prompt_versions_active 
    ON ai_prompt_versions (prompt_name, is_active);

-- 2. AI Agent Identities & Permission Scopes
CREATE TABLE IF NOT EXISTS ai_agent_identities (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'ai_agent',
    is_ai_agent BOOLEAN NOT NULL DEFAULT true,
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['tools:read', 'incident:propose', 'twin:query'],
    max_risk_tier VARCHAR(16) NOT NULL DEFAULT 'Tier 2',
    cannot_approve BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_agent_identities_tenant 
    ON ai_agent_identities (tenant_id, is_active);

-- 3. AI Evaluation Lab Permanent Benchmark Dataset
CREATE TABLE IF NOT EXISTS ai_eval_benchmark_dataset (
    id VARCHAR(64) PRIMARY KEY,
    category VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    input_telemetry JSONB NOT NULL DEFAULT '[]'::jsonb,
    expected_severity VARCHAR(16) NOT NULL,
    expected_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    expected_evidence_keys TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    injection_payload TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_eval_benchmark_category 
    ON ai_eval_benchmark_dataset (category, is_active);

-- 4. AI Evaluation Runs & Quality Metrics Ledger
CREATE TABLE IF NOT EXISTS ai_eval_runs (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    run_by VARCHAR(64) NOT NULL,
    model_name VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    prompt_version VARCHAR(32) NOT NULL,
    total_cases INTEGER NOT NULL DEFAULT 0,
    passed_cases INTEGER NOT NULL DEFAULT 0,
    hallucination_rate NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
    remediation_accuracy NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
    tool_call_error_rate NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
    avg_latency_ms INTEGER NOT NULL DEFAULT 0,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_eval_runs_tenant 
    ON ai_eval_runs (tenant_id, created_at DESC);

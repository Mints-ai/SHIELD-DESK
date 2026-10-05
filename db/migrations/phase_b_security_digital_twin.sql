-- ============================================================
-- ShieldDesk Phase B: Security Digital Twin — Postgres Graph
--
-- Adds twin_nodes and twin_edges tables backed by a recursive
-- CTE query engine. The in-memory SecurityDigitalTwin remains
-- the hot path; Postgres is the persistent, durable source
-- of truth for cross-restart and multi-process consistency.
--
-- All statements are additive and idempotent (IF NOT EXISTS).
-- ============================================================

-- ---------------------------------------------------------------------------
-- 1. twin_nodes — one row per vertex in the security knowledge graph
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS twin_nodes (
  id              text          NOT NULL,          -- caller-assigned stable ID (e.g. "ep-api-gw")
  tenant_id       text          NOT NULL,

  -- Classification
  name            text          NOT NULL,
  node_type       text          NOT NULL,
  -- endpoint | server | device | application | api | container |
  -- cloud_resource | network_segment | database | user | identity |
  -- secret | vulnerability | business_service
  criticality     text          NOT NULL DEFAULT 'low'
                  CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
  status          text          NOT NULL DEFAULT 'healthy'
                  CHECK (status IN ('healthy', 'compromised', 'isolated', 'degraded', 'offline')),
  environment     text          CHECK (environment IN ('production', 'staging', 'development', 'dmz', 'internal')),

  -- Network identifiers
  ip_address      text,
  hostname        text,
  os              text,

  -- Phase A linkage
  asset_id        uuid          REFERENCES assets(id) ON DELETE SET NULL,
  security_event_ids text[]     NOT NULL DEFAULT '{}',

  -- Extensible bag of properties
  tags            text[]        NOT NULL DEFAULT '{}',
  metadata        jsonb         NOT NULL DEFAULT '{}',

  created_at      timestamptz   NOT NULL DEFAULT now(),
  updated_at      timestamptz   NOT NULL DEFAULT now(),

  PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_twin_nodes_tenant_type
  ON twin_nodes (tenant_id, node_type);
CREATE INDEX IF NOT EXISTS idx_twin_nodes_criticality
  ON twin_nodes (tenant_id, criticality);
CREATE INDEX IF NOT EXISTS idx_twin_nodes_status
  ON twin_nodes (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_twin_nodes_hostname
  ON twin_nodes (tenant_id, hostname) WHERE hostname IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_twin_nodes_ip
  ON twin_nodes (tenant_id, ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_twin_nodes_asset
  ON twin_nodes (asset_id) WHERE asset_id IS NOT NULL;

ALTER TABLE twin_nodes ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'twin_nodes' AND policyname = 'tenant_isolation_twin_nodes'
  ) THEN
    CREATE POLICY tenant_isolation_twin_nodes
      ON twin_nodes USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 2. twin_edges — directed edges between twin_nodes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS twin_edges (
  id              text          NOT NULL,          -- caller-assigned stable ID
  tenant_id       text          NOT NULL,
  source_id       text          NOT NULL,
  target_id       text          NOT NULL,
  relation_type   text          NOT NULL,
  -- depends_on | runs_on | can_reach | authenticates_as |
  -- has_vulnerability | stores_secret | connects_to | manages | member_of
  bidirectional   boolean       NOT NULL DEFAULT false,
  port            integer,
  protocol        text,
  metadata        jsonb         NOT NULL DEFAULT '{}',
  created_at      timestamptz   NOT NULL DEFAULT now(),
  updated_at      timestamptz   NOT NULL DEFAULT now(),

  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, source_id) REFERENCES twin_nodes(tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, target_id) REFERENCES twin_nodes(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_twin_edges_source
  ON twin_edges (tenant_id, source_id);
CREATE INDEX IF NOT EXISTS idx_twin_edges_target
  ON twin_edges (tenant_id, target_id);
CREATE INDEX IF NOT EXISTS idx_twin_edges_relation
  ON twin_edges (tenant_id, relation_type);
-- Composite covering index for inbound reachability queries
CREATE INDEX IF NOT EXISTS idx_twin_edges_target_relation
  ON twin_edges (tenant_id, target_id, relation_type);

ALTER TABLE twin_edges ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'twin_edges' AND policyname = 'tenant_isolation_twin_edges'
  ) THEN
    CREATE POLICY tenant_isolation_twin_edges
      ON twin_edges USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 3. twin_sync_log — audit trail for Phase A event → graph sync operations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS twin_sync_log (
  id              uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       text          NOT NULL,
  source          text          NOT NULL,           -- 'security_event' | 'manual' | 'asset_import'
  source_id       text,                             -- security_events.id or assets.id
  nodes_upserted  integer       NOT NULL DEFAULT 0,
  edges_upserted  integer       NOT NULL DEFAULT 0,
  duration_ms     integer,
  error           text,
  synced_at       timestamptz   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_twin_sync_log_tenant
  ON twin_sync_log (tenant_id, synced_at DESC);

ALTER TABLE twin_sync_log ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'twin_sync_log' AND policyname = 'tenant_isolation_twin_sync_log'
  ) THEN
    CREATE POLICY tenant_isolation_twin_sync_log
      ON twin_sync_log USING (tenant_id = current_setting('app.current_tenant', true));
  END IF;
END
$$;

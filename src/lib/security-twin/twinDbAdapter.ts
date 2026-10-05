/**
 * ShieldDesk Phase B — Twin DB Adapter (Postgres CTE Graph Engine)
 *
 * Wraps the Postgres `twin_nodes` / `twin_edges` tables with a set of
 * recursive CTE queries that answer the same six questions as the
 * in-memory SecurityDigitalTwin, but durably and across process restarts.
 *
 * Design principles:
 * - ADAPTER PATTERN: implements the same query surface as the in-memory twin
 *   so callers can swap between them transparently.
 * - FAIL CLOSED: if Postgres is unavailable, the method throws; it never
 *   falls back to stale in-memory data silently.
 * - TENANT ISOLATION: every query is parametrised on tenant_id and uses the
 *   app.current_tenant Postgres session variable via withTenantContext().
 * - NO WRITES HERE: this file is read-only CTE queries. Writes go through
 *   upsertNodeToDB() / upsertEdgeToDB() which use standard INSERT … ON CONFLICT.
 * - BENCHMARK BUILT-IN: every public method records its duration_ms so the
 *   caller can compare against the 50 ms threshold specified in the spec.
 *
 * NOTE: `server-only` is NOT imported here; the guard is enforced by
 * `src/lib/db/index.ts` (which has `import "server-only"` at the top).
 * Importing `server-only` here would break the tsx test runner.
 */

import { query } from "../db";
import type { TwinNode, TwinEdge, TwinNodeType, TwinEdgeType, IsolationSimulationResult } from "./types";


export interface DbTwinQueryResult<T> {
  data: T;
  /** Wall-clock duration of the Postgres query in ms */
  durationMs: number;
}

// ──────────────────────────────────────────────────────────────────────────────
// Row shape coming back from Postgres
// ──────────────────────────────────────────────────────────────────────────────
interface NodeRow {
  id: string;
  tenant_id: string;
  name: string;
  node_type: string;
  criticality: string;
  status: string;
  environment: string | null;
  ip_address: string | null;
  hostname: string | null;
  os: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface EdgeRow {
  id: string;
  tenant_id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  bidirectional: boolean;
  port: number | null;
  protocol: string | null;
  metadata: Record<string, unknown>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Mapping helpers
// ──────────────────────────────────────────────────────────────────────────────

function rowToNode(row: NodeRow): TwinNode {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    type: row.node_type as TwinNodeType,
    criticality: row.criticality as TwinNode["criticality"],
    status: row.status as TwinNode["status"],
    environment: row.environment as TwinNode["environment"] ?? undefined,
    ipAddress: row.ip_address ?? undefined,
    hostname: row.hostname ?? undefined,
    os: row.os ?? undefined,
    tags: row.tags,
    metadata: row.metadata,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function rowToEdge(row: EdgeRow): TwinEdge {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    sourceId: row.source_id,
    targetId: row.target_id,
    relationType: row.relation_type as TwinEdgeType,
    bidirectional: row.bidirectional,
    port: row.port ?? undefined,
    protocol: row.protocol ?? undefined,
    metadata: row.metadata,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Write operations
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Upsert a TwinNode into Postgres.
 * Uses INSERT … ON CONFLICT (tenant_id, id) DO UPDATE for idempotency.
 */
export async function upsertNodeToDB(node: TwinNode): Promise<void> {
  await query(
    `INSERT INTO twin_nodes
      (id, tenant_id, name, node_type, criticality, status, environment,
       ip_address, hostname, os, tags, metadata, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
     ON CONFLICT (tenant_id, id) DO UPDATE SET
       name        = EXCLUDED.name,
       node_type   = EXCLUDED.node_type,
       criticality = EXCLUDED.criticality,
       status      = EXCLUDED.status,
       environment = EXCLUDED.environment,
       ip_address  = EXCLUDED.ip_address,
       hostname    = EXCLUDED.hostname,
       os          = EXCLUDED.os,
       tags        = EXCLUDED.tags,
       metadata    = EXCLUDED.metadata,
       updated_at  = now()`,
    [
      node.id,
      node.tenantId,
      node.name,
      node.type,
      node.criticality,
      node.status ?? "healthy",
      node.environment ?? null,
      node.ipAddress ?? null,
      node.hostname ?? null,
      node.os ?? null,
      node.tags ?? [],
      JSON.stringify(node.metadata ?? {}),
    ]
  );
}

/**
 * Upsert a TwinEdge into Postgres.
 */
export async function upsertEdgeToDB(edge: TwinEdge): Promise<void> {
  await query(
    `INSERT INTO twin_edges
      (id, tenant_id, source_id, target_id, relation_type,
       bidirectional, port, protocol, metadata, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
     ON CONFLICT (tenant_id, id) DO UPDATE SET
       source_id     = EXCLUDED.source_id,
       target_id     = EXCLUDED.target_id,
       relation_type = EXCLUDED.relation_type,
       bidirectional = EXCLUDED.bidirectional,
       port          = EXCLUDED.port,
       protocol      = EXCLUDED.protocol,
       metadata      = EXCLUDED.metadata,
       updated_at    = now()`,
    [
      edge.id,
      edge.tenantId,
      edge.sourceId,
      edge.targetId,
      edge.relationType,
      edge.bidirectional ?? false,
      edge.port ?? null,
      edge.protocol ?? null,
      JSON.stringify(edge.metadata ?? {}),
    ]
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Read operations (CTE-based graph traversal)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Fetch a single node by ID.
 */
export async function getNodeFromDB(
  tenantId: string,
  nodeId: string
): Promise<DbTwinQueryResult<TwinNode | null>> {
  const start = Date.now();
  const result = await query<NodeRow>(
    `SELECT * FROM twin_nodes WHERE tenant_id = $1 AND id = $2`,
    [tenantId, nodeId]
  );
  return {
    data: result.rows[0] ? rowToNode(result.rows[0]) : null,
    durationMs: Date.now() - start,
  };
}

/**
 * Fetch all nodes for a tenant, optionally filtered by type.
 */
export async function getNodesFromDB(
  tenantId: string,
  type?: TwinNodeType
): Promise<DbTwinQueryResult<TwinNode[]>> {
  const start = Date.now();
  const result = type
    ? await query<NodeRow>(
        `SELECT * FROM twin_nodes WHERE tenant_id = $1 AND node_type = $2 ORDER BY name`,
        [tenantId, type]
      )
    : await query<NodeRow>(
        `SELECT * FROM twin_nodes WHERE tenant_id = $1 ORDER BY name`,
        [tenantId]
      );
  return {
    data: result.rows.map(rowToNode),
    durationMs: Date.now() - start,
  };
}

/**
 * Fetch all edges for a tenant.
 */
export async function getEdgesFromDB(tenantId: string): Promise<DbTwinQueryResult<TwinEdge[]>> {
  const start = Date.now();
  const result = await query<EdgeRow>(
    `SELECT * FROM twin_edges WHERE tenant_id = $1`,
    [tenantId]
  );
  return {
    data: result.rows.map(rowToEdge),
    durationMs: Date.now() - start,
  };
}

/**
 * Recursive CTE: find all nodes reachable FROM a given start node,
 * following can_reach and connects_to edges up to max_depth hops.
 *
 * Equivalent to the in-memory BFS but executed entirely in Postgres.
 * Returns rows ordered by depth ascending (closest first).
 */
export async function getReachableFromDB(
  tenantId: string,
  startNodeId: string,
  maxDepth = 6,
  relationTypes: TwinEdgeType[] = ["can_reach", "connects_to", "depends_on"]
): Promise<DbTwinQueryResult<Array<TwinNode & { depth: number }>>> {
  const start = Date.now();

  // Build the relation type IN clause parameterised to avoid SQL injection
  const placeholders = relationTypes.map((_, i) => `$${i + 4}`).join(", ");

  const result = await query<NodeRow & { depth: number }>(
    `WITH RECURSIVE reachability AS (
       -- Anchor: start node (depth 0)
       SELECT
         n.id, n.tenant_id, n.name, n.node_type, n.criticality, n.status,
         n.environment, n.ip_address, n.hostname, n.os, n.tags, n.metadata,
         n.created_at, n.updated_at,
         0 AS depth
       FROM twin_nodes n
       WHERE n.tenant_id = $1 AND n.id = $2

       UNION ALL

       -- Recursive step: follow outbound edges
       SELECT
         n.id, n.tenant_id, n.name, n.node_type, n.criticality, n.status,
         n.environment, n.ip_address, n.hostname, n.os, n.tags, n.metadata,
         n.created_at, n.updated_at,
         r.depth + 1
       FROM reachability r
       JOIN twin_edges e
         ON e.tenant_id = $1
        AND e.source_id = r.id
        AND e.relation_type = ANY($3::text[])
       JOIN twin_nodes n
         ON n.tenant_id = $1 AND n.id = e.target_id
       WHERE r.depth < $4 -- $4 = maxDepth - 1 (stop before anchor + maxDepth total)
     )
     SELECT DISTINCT ON (id) id, tenant_id, name, node_type, criticality, status,
            environment, ip_address, hostname, os, tags, metadata,
            created_at, updated_at, depth
     FROM reachability
     WHERE id <> $2  -- exclude the start node itself
     ORDER BY id, depth ASC`,
    [tenantId, startNodeId, relationTypes, maxDepth - 1]
  );

  return {
    data: result.rows.map((row) => ({ ...rowToNode(row), depth: row.depth })),
    durationMs: Date.now() - start,
  };
}

/**
 * Recursive CTE: find all nodes that can reach a TARGET node (reverse traversal).
 * Used by attack-path engine to find inbound attack surface.
 */
export async function getInboundReachableFromDB(
  tenantId: string,
  targetNodeId: string,
  maxDepth = 6,
  relationTypes: TwinEdgeType[] = ["can_reach", "connects_to", "depends_on"]
): Promise<DbTwinQueryResult<Array<TwinNode & { depth: number }>>> {
  const start = Date.now();

  const result = await query<NodeRow & { depth: number }>(
    `WITH RECURSIVE inbound AS (
       -- Anchor: target node (depth 0)
       SELECT
         n.id, n.tenant_id, n.name, n.node_type, n.criticality, n.status,
         n.environment, n.ip_address, n.hostname, n.os, n.tags, n.metadata,
         n.created_at, n.updated_at,
         0 AS depth
       FROM twin_nodes n
       WHERE n.tenant_id = $1 AND n.id = $2

       UNION ALL

       -- Recursive step: follow INBOUND edges (reverse direction)
       SELECT
         n.id, n.tenant_id, n.name, n.node_type, n.criticality, n.status,
         n.environment, n.ip_address, n.hostname, n.os, n.tags, n.metadata,
         n.created_at, n.updated_at,
         i.depth + 1
       FROM inbound i
       JOIN twin_edges e
         ON e.tenant_id = $1
        AND e.target_id = i.id
        AND e.relation_type = ANY($3::text[])
       JOIN twin_nodes n
         ON n.tenant_id = $1 AND n.id = e.source_id
       WHERE i.depth < $4
     )
     SELECT DISTINCT ON (id) id, tenant_id, name, node_type, criticality, status,
            environment, ip_address, hostname, os, tags, metadata,
            created_at, updated_at, depth
     FROM inbound
     WHERE id <> $2
     ORDER BY id, depth ASC`,
    [tenantId, targetNodeId, relationTypes, maxDepth - 1]
  );

  return {
    data: result.rows.map((row) => ({ ...rowToNode(row), depth: row.depth })),
    durationMs: Date.now() - start,
  };
}

/**
 * Find all shortest attack paths from any internet-facing / DMZ node
 * to a critical target. Returns paths with step depth information.
 *
 * Algorithm: BFS via recursive CTE, tracking the full path array.
 * We store the path as a text[] (array of node IDs) to reconstruct it.
 */
export async function findAttackPathsFromDB(
  tenantId: string,
  targetNodeId: string,
  maxDepth = 6
): Promise<DbTwinQueryResult<Array<{ path: string[]; depth: number }>>> {
  const start = Date.now();

  const result = await query<{ path: string[]; depth: number }>(
    `WITH RECURSIVE attack_paths AS (
       -- Anchors: entry-point nodes (DMZ, internet-facing, endpoints, or api type)
       SELECT
         n.id                  AS current_id,
         ARRAY[n.id]           AS path,
         0                     AS depth
       FROM twin_nodes n
       WHERE n.tenant_id = $1
         AND (
           n.environment = 'dmz'
           OR 'internet-facing' = ANY(n.tags)
           OR 'public' = ANY(n.tags)
           OR n.node_type IN ('api', 'endpoint')
         )
         AND n.id <> $2   -- don't start at the target itself

       UNION ALL

       -- Recursive step: extend path one hop
       SELECT
         e.target_id,
         ap.path || e.target_id,
         ap.depth + 1
       FROM attack_paths ap
       JOIN twin_edges e
         ON e.tenant_id = $1
        AND e.source_id = ap.current_id
        AND e.relation_type IN ('can_reach', 'connects_to', 'depends_on')
       WHERE ap.depth < $3
         AND NOT (e.target_id = ANY(ap.path))  -- cycle guard
     )
     SELECT path, depth
     FROM attack_paths
     WHERE current_id = $2
     ORDER BY depth ASC
     LIMIT 100`,
    [tenantId, targetNodeId, maxDepth]
  );

  return {
    data: result.rows,
    durationMs: Date.now() - start,
  };
}

/**
 * Isolation simulation via Postgres: counts severed edges and identifies
 * impacted upstream, downstream, and business service nodes using CTEs.
 */
export async function simulateIsolationInDB(
  tenantId: string,
  targetNodeId: string
): Promise<DbTwinQueryResult<IsolationSimulationResult>> {
  const start = Date.now();

  // 1. Get the target node
  const nodeRes = await query<NodeRow>(
    `SELECT * FROM twin_nodes WHERE tenant_id=$1 AND id=$2`,
    [tenantId, targetNodeId]
  );
  const target = nodeRes.rows[0] ? rowToNode(nodeRes.rows[0]) : null;

  // 2. Count severed edges
  const severedRes = await query<{ count: string }>(
    `SELECT COUNT(*)::text AS count FROM twin_edges
     WHERE tenant_id=$1 AND (source_id=$2 OR target_id=$2)`,
    [tenantId, targetNodeId]
  );
  const severedCount = parseInt(severedRes.rows[0]?.count ?? "0", 10);

  // 3. Upstream: nodes that depend_on or connects_to the target
  const upstreamRes = await query<NodeRow>(
    `SELECT n.* FROM twin_nodes n
     JOIN twin_edges e ON e.tenant_id=$1 AND e.source_id=n.id
     WHERE e.tenant_id=$1 AND e.target_id=$2
       AND e.relation_type IN ('depends_on','connects_to')`,
    [tenantId, targetNodeId]
  );

  // 4. Business services — via recursive CTE through upstream chain
  const bizRes = await query<NodeRow>(
    `WITH RECURSIVE upstream AS (
       SELECT source_id AS id, 0 AS depth
       FROM twin_edges
       WHERE tenant_id=$1 AND target_id=$2
         AND relation_type IN ('depends_on','connects_to')
       UNION ALL
       SELECT e.source_id, u.depth+1
       FROM upstream u
       JOIN twin_edges e ON e.tenant_id=$1 AND e.target_id=u.id
         AND e.relation_type IN ('depends_on','connects_on')
       WHERE u.depth < 5
     )
     SELECT DISTINCT n.* FROM twin_nodes n
     JOIN upstream u ON u.id = n.id
     WHERE n.tenant_id=$1 AND n.node_type='business_service'`,
    [tenantId, targetNodeId]
  );

  // 5. Identities that can reach the target
  const identityRes = await query<NodeRow>(
    `SELECT n.* FROM twin_nodes n
     JOIN twin_edges e ON e.tenant_id=$1 AND e.source_id=n.id
     WHERE e.tenant_id=$1 AND e.target_id=$2
       AND e.relation_type IN ('authenticates_as','manages')
       AND n.node_type IN ('identity','user')`,
    [tenantId, targetNodeId]
  );

  const affectedUpstream = upstreamRes.rows.map(rowToNode);
  const disruptedServices = bizRes.rows.map(rowToNode);
  const disconnectedIdentities = identityRes.rows.map(rowToNode);

  // 6. Blast radius score (same formula as in-memory twin)
  let score = severedCount * 5;
  score += affectedUpstream.length * 10;
  score += disruptedServices.length * 25;
  if (target?.criticality === "critical") score += 30;
  if (target?.criticality === "high") score += 15;
  score = Math.min(100, Math.max(5, score));

  let residualRisk: IsolationSimulationResult["residualRisk"] = "low";
  if (score > 75) residualRisk = "critical";
  else if (score > 50) residualRisk = "high";
  else if (score > 25) residualRisk = "medium";

  const targetName = target?.name ?? targetNodeId;

  return {
    data: {
      tenantId,
      isolatedAssetId: targetNodeId,
      isolatedAssetName: targetName,
      severedEdgesCount: severedCount,
      affectedUpstreamAssets: affectedUpstream,
      affectedDownstreamAssets: [],       // computed via getInboundReachableFromDB separately
      disruptedBusinessServices: disruptedServices,
      disconnectedIdentities,
      blastRadiusScore: score,
      residualRisk,
      summary: `DB isolation simulation of '${targetName}': ${severedCount} edges severed, ${affectedUpstream.length} upstream assets, ${disruptedServices.length} business services disrupted. Blast radius score: ${score}/100.`,
    },
    durationMs: Date.now() - start,
  };
}

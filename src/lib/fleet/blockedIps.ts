import { query } from "@/lib/db";
import {
  blockIp as syncThreatAlertBlock,
  unblockIp as syncThreatAlertUnblock,
  isIpBlocked as threatAlertIsBlocked,
} from "@/lib/alerts/threatAlertStore";

export interface BlockedIpRecord {
  id: string;
  tenant_id: string;
  ip_address: string;
  agent_id?: string | null;
  hostname?: string | null;
  reason?: string | null;
  tier: string;
  blocked_by: string;
  blocked_at: string;
  unblocked_at?: string | null;
  status: "blocked" | "unblocked";
}

// In-memory fallback if PostgreSQL is temporarily unreachable
export const MOCK_FLEET_BLOCKED_IPS: BlockedIpRecord[] = [];

let tableInitialized = false;

/**
 * Ensures the fleet_blocked_ips table and indexes exist in PostgreSQL.
 */
export async function ensureBlockedIpsTable(): Promise<void> {
  if (tableInitialized) return;
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS fleet_blocked_ips (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id text NOT NULL,
        ip_address text NOT NULL,
        agent_id text,
        hostname text,
        reason text,
        tier text DEFAULT 'Tier 1',
        blocked_by text,
        blocked_at timestamptz NOT NULL DEFAULT now(),
        unblocked_at timestamptz,
        status text NOT NULL DEFAULT 'blocked' CHECK (status IN ('blocked', 'unblocked'))
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_active_fleet_blocked_ip 
        ON fleet_blocked_ips (tenant_id, ip_address) 
        WHERE status = 'blocked';
      CREATE INDEX IF NOT EXISTS idx_fleet_blocked_tenant 
        ON fleet_blocked_ips (tenant_id);
    `);
    tableInitialized = true;
  } catch (err) {
    // If DB is offline, continue with in-memory store
    console.warn("[FleetBlockedIPs] DB table init warning:", err);
  }
}

/**
 * Normalizes an IP address for consistent storage and comparison.
 */
export function sanitizeIp(ip?: string | null): string {
  if (!ip) return "";
  let clean = ip.trim();
  if (clean === "::1" || clean === "localhost") return "127.0.0.1";
  if (clean.startsWith("::ffff:")) clean = clean.replace("::ffff:", "");
  if (clean.includes(":") && clean.includes(".")) clean = clean.split(":")[0];
  return clean;
}

/**
 * Records an IP address as blocked in the persistent registry,
 * syncs with threatAlertStore, and maintains in-memory fallback.
 */
export async function recordBlockedIp({
  tenantId,
  ip,
  agentId,
  hostname,
  reason,
  tier = "Tier 1",
  blockedBy,
}: {
  tenantId: string;
  ip: string;
  agentId?: string | null;
  hostname?: string | null;
  reason?: string | null;
  tier?: string;
  blockedBy: string;
}): Promise<BlockedIpRecord> {
  const cleanIp = sanitizeIp(ip);
  if (!cleanIp) throw new Error("INVALID_IP: Target IP address cannot be empty.");

  await ensureBlockedIpsTable();

  const nowIso = new Date().toISOString();
  const effectiveReason = reason || "Host containment applied via Fleet Console";

  // 1. Sync with Threat Alert Containment Store
  syncThreatAlertBlock(cleanIp, effectiveReason, 1, tenantId);

  // 2. Synchronize with adminDisconnectedAgents and disconnect target endpoints in database ONLY if their registered IP matches the blocked IP
  try {
    const { adminDisconnectedAgents } = await import("@/lib/fleet/liveTelemetry");

    const { rows: matchedAgents } = await query<{ id: string; hostname: string }>(
      `UPDATE endpoint_agents
       SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
       WHERE (tenant_id = $1 OR $1 = 'mints-global')
         AND ip_address = $2
       RETURNING id, hostname;`,
      [tenantId, cleanIp]
    );

    for (const a of matchedAgents) {
      adminDisconnectedAgents.add(a.id);
      if (a.hostname) adminDisconnectedAgents.add(a.hostname);
    }
  } catch (syncErr) {
    console.warn("[recordBlockedIp] Agent disconnect sync warning:", syncErr);
  }

  // 3. Persist to PostgreSQL
  try {
    // Check if an active record already exists
    const existing = await query<BlockedIpRecord>(
      `SELECT * FROM fleet_blocked_ips 
       WHERE tenant_id = $1 AND ip_address = $2 AND status = 'blocked' 
       LIMIT 1`,
      [tenantId, cleanIp]
    );

    if (existing.rows.length > 0) {
      const updated = await query<BlockedIpRecord>(
        `UPDATE fleet_blocked_ips
         SET agent_id = COALESCE($1, agent_id),
             hostname = COALESCE($2, hostname),
             reason = $3,
             tier = $4,
             blocked_by = $5,
             blocked_at = now()
         WHERE id = $6
         RETURNING *;`,
        [agentId || null, hostname || null, effectiveReason, tier, blockedBy, existing.rows[0].id]
      );
      if (updated.rows.length > 0) {
        updateMockRecord(updated.rows[0]);
        return updated.rows[0];
      }
    } else {
      const inserted = await query<BlockedIpRecord>(
        `INSERT INTO fleet_blocked_ips (
           tenant_id, ip_address, agent_id, hostname, reason, tier, blocked_by, blocked_at, status
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, now(), 'blocked')
         RETURNING *;`,
        [tenantId, cleanIp, agentId || null, hostname || null, effectiveReason, tier, blockedBy]
      );
      if (inserted.rows.length > 0) {
        updateMockRecord(inserted.rows[0]);
        return inserted.rows[0];
      }
    }
  } catch (err) {
    console.warn("[recordBlockedIp] DB write warning, using in-memory store:", err);
  }

  // 4. Fallback in-memory record
  const mockRecord: BlockedIpRecord = {
    id: `blk-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    tenant_id: tenantId,
    ip_address: cleanIp,
    agent_id: agentId || null,
    hostname: hostname || null,
    reason: effectiveReason,
    tier,
    blocked_by: blockedBy,
    blocked_at: nowIso,
    status: "blocked",
  };
  updateMockRecord(mockRecord);
  return mockRecord;
}

/**
 * Records an IP address as unblocked, removes it from threat containment,
 * and updates the registry status.
 */
export async function recordUnblockedIp({
  tenantId,
  ip,
  unblockedBy,
}: {
  tenantId: string;
  ip: string;
  unblockedBy: string;
}): Promise<boolean> {
  const cleanIp = sanitizeIp(ip);
  if (!cleanIp) return false;

  await ensureBlockedIpsTable();

  // 1. Lift containment in Threat Alert Store
  syncThreatAlertUnblock(cleanIp, tenantId);

  // 2. Clear admin disconnected locks and restore connectivity in database
  try {
    const { adminDisconnectedAgents } = await import("@/lib/fleet/liveTelemetry");
    const { rows: affectedAgents } = await query<{ id: string; hostname: string }>(
      `UPDATE endpoint_agents
       SET status = 'connected', last_seen_at = now()
       WHERE (tenant_id = $1 OR $1 = 'mints-global' OR tenant_id IS NULL)
         AND (
           ip_address = $2
           OR id::text IN (SELECT agent_id FROM fleet_blocked_ips WHERE ip_address = $2 AND agent_id IS NOT NULL)
           OR hostname IN (SELECT hostname FROM fleet_blocked_ips WHERE ip_address = $2 AND hostname IS NOT NULL)
         )
       RETURNING id, hostname;`,
      [tenantId, cleanIp]
    );

    for (const a of affectedAgents) {
      adminDisconnectedAgents.delete(a.id);
      if (a.hostname) adminDisconnectedAgents.delete(a.hostname);
    }

    // Direct sweep for any agent registered under cleanIp
    const { rows: directAgents } = await query<{ id: string; hostname: string }>(
      `SELECT id, hostname FROM endpoint_agents WHERE ip_address = $1;`,
      [cleanIp]
    ).catch(() => ({ rows: [] }));

    for (const a of directAgents) {
      adminDisconnectedAgents.delete(a.id);
      if (a.hostname) adminDisconnectedAgents.delete(a.hostname);
    }
  } catch (unblockSyncErr) {
    console.warn("[recordUnblockedIp] Agent reconnect sync warning:", unblockSyncErr);
  }

  // 3. Update PostgreSQL
  let dbUpdated = false;
  try {
    const res = await query(
      `UPDATE fleet_blocked_ips
       SET status = 'unblocked', unblocked_at = now()
       WHERE (tenant_id = $1 OR $1 = 'mints-global' OR tenant_id IS NULL)
         AND (
           ip_address = $2
           OR ($2 = '127.0.0.1' AND ip_address IN ('127.0.0.1', '::1', 'localhost'))
         )
         AND status = 'blocked';`,
      [tenantId, cleanIp]
    );
    dbUpdated = (res.rowCount || 0) > 0;
  } catch (err) {
    console.warn("[recordUnblockedIp] DB update warning:", err);
  }

  // 4. Update in-memory fallback
  for (const r of MOCK_FLEET_BLOCKED_IPS) {
    if (
      (r.tenant_id === tenantId || tenantId === "mints-global") &&
      (r.ip_address === cleanIp || (cleanIp === "127.0.0.1" && ["127.0.0.1", "::1", "localhost"].includes(r.ip_address))) &&
      r.status === "blocked"
    ) {
      r.status = "unblocked";
      r.unblocked_at = new Date().toISOString();
    }
  }

  try {
    const { adminDisconnectedAgents } = await import("@/lib/fleet/liveTelemetry");
    const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
    for (const a of MOCK_ENDPOINT_AGENTS) {
      if (
        (a.tenant_id === tenantId || tenantId === "mints-global") &&
        (a.ip_address === cleanIp || (cleanIp === "127.0.0.1" && ["127.0.0.1", "::1", "localhost"].includes(a.ip_address)))
      ) {
        adminDisconnectedAgents.delete(a.id);
        if (a.hostname) adminDisconnectedAgents.delete(a.hostname);
      }
    }
  } catch {}

  return dbUpdated || true;
}

/**
 * Checks whether an IP is currently marked as blocked in the fleet.
 */
export async function isIpBlockedInFleet(ip: string, tenantId?: string): Promise<boolean> {
  const cleanIp = sanitizeIp(ip);
  if (!cleanIp) return false;

  // 1. Check in-memory threatAlertStore
  if (threatAlertIsBlocked(cleanIp)) {
    return true;
  }

  // 2. Check PostgreSQL registry
  try {
    await ensureBlockedIpsTable();
    const isLoopback = cleanIp === "127.0.0.1";
    const res = await query<{ count: string }>(
      `SELECT count(*) FROM fleet_blocked_ips 
       WHERE (
         ip_address = $1
         OR ($3 = true AND ip_address IN ('127.0.0.1', '::1', 'localhost'))
       )
         AND status = 'blocked'
         AND ($2::text IS NULL OR tenant_id = $2)`,
      [cleanIp, tenantId || null, isLoopback]
    );
    if (res.rows.length > 0 && parseInt(res.rows[0].count, 10) > 0) {
      return true;
    }
  } catch (err) {
    console.warn("[isIpBlockedInFleet] DB query warning:", err);
  }

  // 3. Check in-memory store fallback
  const inMock = MOCK_FLEET_BLOCKED_IPS.some(
    (r) =>
      (r.ip_address === cleanIp || (cleanIp === "127.0.0.1" && ["127.0.0.1", "::1", "localhost"].includes(r.ip_address))) &&
      r.status === "blocked" &&
      (!tenantId || r.tenant_id === tenantId)
  );
  return inMock;
}

/**
 * Lists all actively blocked IPs for a tenant (and optionally filtered by agent).
 */
export async function listActiveBlockedIps(
  tenantId?: string,
  agentId?: string
): Promise<BlockedIpRecord[]> {
  await ensureBlockedIpsTable();

  const resultsMap = new Map<string, BlockedIpRecord>();

  // 1. Query PostgreSQL
  try {
    const sql = `
      SELECT id, tenant_id, ip_address, agent_id, hostname, reason, tier, blocked_by, blocked_at, unblocked_at, status
      FROM fleet_blocked_ips
      WHERE status = 'blocked'
        AND ($1::text IS NULL OR tenant_id = $1)
        AND ($2::text IS NULL OR agent_id = $2 OR hostname = $2)
      ORDER BY blocked_at DESC;
    `;
    const res = await query<BlockedIpRecord>(sql, [tenantId || null, agentId || null]);
    for (const row of res.rows) {
      resultsMap.set(row.ip_address, row);
    }
  } catch {}

  // 2. Merge in-memory fallback
  for (const r of MOCK_FLEET_BLOCKED_IPS) {
    if (r.status === "blocked") {
      if (tenantId && r.tenant_id !== tenantId) continue;
      if (agentId && r.agent_id !== agentId && r.hostname !== agentId) continue;
      if (!resultsMap.has(r.ip_address)) {
        resultsMap.set(r.ip_address, r);
      }
    }
  }

  return Array.from(resultsMap.values());
}

function updateMockRecord(record: BlockedIpRecord): void {
  const idx = MOCK_FLEET_BLOCKED_IPS.findIndex(
    (r) => r.tenant_id === record.tenant_id && r.ip_address === record.ip_address
  );
  if (idx !== -1) {
    MOCK_FLEET_BLOCKED_IPS[idx] = record;
  } else {
    MOCK_FLEET_BLOCKED_IPS.unshift(record);
  }
}

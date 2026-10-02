import "server-only";
import { Pool, type QueryResultRow } from "pg";
import { MetricsRegistry } from "@/lib/observability/metrics";

/**
 * ShieldDesk PostgreSQL connection.
 *
 * SECURITY: Gemini must never receive a direct handle to this pool.
 * All queries are issued from the Tool Gateway / service layer (Phase 4),
 * after authentication + RBAC + tenant checks have passed (Phase 3).
 */

declare global {
  var __shieldDeskPgPool: Pool | undefined;
}

function createPool(): Pool {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error(
      "DATABASE_URL is not set. Add it to your server-side environment " +
        "(.env.local) — see .env.example."
    );
  }
     return new Pool({
       connectionString,
       connectionTimeoutMillis: 2000,
       ssl: connectionString.includes("localhost")
         ? false
         : { rejectUnauthorized: false },
     });
}

// Reuse the pool across hot reloads in dev. Created lazily (on first real
// query) so simply importing this module — e.g. during a build's route
// data collection — never throws for a missing DATABASE_URL.
function getPool(): Pool {
  if (!global.__shieldDeskPgPool) {
    global.__shieldDeskPgPool = createPool();
  }
  return global.__shieldDeskPgPool;
}

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[]
) {
  const startedAt = Date.now();
  const operation = /^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)/i.exec(text)?.[1]?.toLowerCase() || "other";
  try {
    return await getPool().query<T>(text, params);
  } catch (error) {
    MetricsRegistry.increment("shielddesk_db_query_errors_total", 1, { operation });
    throw error;
  } finally {
    MetricsRegistry.observe("shielddesk_db_query_duration_ms", Date.now() - startedAt, { operation });
  }
}

/**
 * Executes a callback within a connection where `app.current_tenant` and `app.user_role`
 * are strictly set via `set_config(...)`, activating Postgres Row-Level Security (RLS).
 */
export async function withTenantContext<T>(
  tenantId: string,
  role: string,
  fn: (clientQuery: <R extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) => Promise<{ rows: R[]; rowCount: number | null }>) => Promise<T>
): Promise<T> {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query("BEGIN;");
    await client.query("SELECT set_config('app.current_tenant', $1, true);", [tenantId]);
    await client.query("SELECT set_config('app.user_role', $2, true);", [role]);

    const scopedQuery = async <R extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) => {
      const res = await client.query<R>(text, params);
      return { rows: res.rows, rowCount: res.rowCount };
    };

    const result = await fn(scopedQuery);
    await client.query("COMMIT;");
    return result;
  } catch (err) {
    await client.query("ROLLBACK;").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Issues a single query scoped under PostgreSQL Row-Level Security (RLS) for the specified tenant.
 */
export async function tenantQuery<T extends QueryResultRow = QueryResultRow>(
  tenantId: string,
  role: string,
  text: string,
  params?: unknown[]
) {
  return withTenantContext(tenantId, role, async (scopedQuery) => {
    return scopedQuery<T>(text, params);
  });
}

export async function checkDatabaseConnection(): Promise<boolean> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) return false;
  // Use a dedicated one-shot Client (not the shared pool) so pgBouncer
  // cold-pool slot acquisition doesn't inflate the latency unpredictably.
  const { Client } = await import("pg");
  const client = new Client({
    connectionString,
    connectionTimeoutMillis: 8000,
    ssl: connectionString.includes("localhost")
      ? false
      : { rejectUnauthorized: false },
  });
  try {
    await client.connect();
    await client.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => {});
  }
}


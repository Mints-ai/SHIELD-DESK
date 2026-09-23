import "server-only";
import { Pool, type QueryResultRow } from "pg";

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
  return getPool().query<T>(text, params);
}

export async function checkDatabaseConnection(): Promise<boolean> {
  if (!process.env.DATABASE_URL) return false;
  try {
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), 1500)
    );
    await Promise.race([getPool().query("SELECT 1"), timeout]);
    return true;
  } catch {
    return false;
  }
}

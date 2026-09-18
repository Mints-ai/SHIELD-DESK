import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/**
 * ShieldDesk Supabase connection.
 *
 * Uses the publishable key for server-side queries. Application-layer RBAC
 * and tenant isolation are enforced in the Tool Gateway
 * (lib/tools/shieldDeskChatTools.ts) — Supabase RLS is not relied upon here
 * so that the existing canAccess() / tenant-scoping logic continues to work
 * unchanged.
 *
 * SECURITY: Never expose this module or its client to the browser.
 * All queries go through the Tool Gateway after auth + RBAC checks.
 */

declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskSupabase: SupabaseClient | undefined;
}

function createAdminClient(): SupabaseClient {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) {
    throw new Error(
      "NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY " +
        "must be set in .env.local — see the Supabase project settings."
    );
  }
  return createClient(url, key);
}

// Reuse the client across hot reloads in dev. Created lazily (on first real
// query) so simply importing this module never throws for missing env vars.
export function getSupabase(): SupabaseClient {
  if (!global.__shieldDeskSupabase) {
    global.__shieldDeskSupabase = createAdminClient();
  }
  return global.__shieldDeskSupabase;
}

export async function checkDatabaseConnection(): Promise<boolean> {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) return false;
  try {
    const { error } = await getSupabase()
      .from("users")
      .select("id")
      .limit(1);
    return !error;
  } catch {
    return false;
  }
}

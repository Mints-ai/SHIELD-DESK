import { NextResponse } from "next/server";
import { checkDatabaseConnection } from "@/lib/db";

/**
 * GET /api/health
 *
 * Lightweight check used to verify done-criteria across phases:
 * - application starts
 * - PostgreSQL connection works
 * - the local Ollama instance is actually reachable (unlike a cloud API
 *   key, there's nothing to "configure" here — either Ollama is running
 *   at OLLAMA_BASE_URL or it isn't)
 */
export async function GET() {
  const databaseConfigured = Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const databaseConnected = databaseConfigured
    ? await checkDatabaseConnection()
    : false;

  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434/v1";
  let ollamaReachable = false;
  try {
    const res = await fetch(`${ollamaBaseUrl}/models`, {
      signal: AbortSignal.timeout(2000),
    });
    ollamaReachable = res.ok;
  } catch {
    ollamaReachable = false;
  }

  return NextResponse.json({
    status: "ok",
    ollama: { baseUrl: ollamaBaseUrl, reachable: ollamaReachable },
    database: { configured: databaseConfigured, connected: databaseConnected },
  });
}

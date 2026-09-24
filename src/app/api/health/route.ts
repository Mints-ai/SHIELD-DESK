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
  const databaseConfigured = Boolean(process.env.DATABASE_URL);
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

  const pythonAiServiceUrl = process.env.PYTHON_AI_SERVICE_URL || "http://localhost:8000";
  let pythonAiReachable = false;
  try {
    const res = await fetch(`${pythonAiServiceUrl}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    if (res.ok) {
      pythonAiReachable = true;
    } else {
      const fallbackRes = await fetch(`${pythonAiServiceUrl}/api/samples`, {
        signal: AbortSignal.timeout(2000),
      });
      pythonAiReachable = fallbackRes.ok;
    }
  } catch {
    pythonAiReachable = false;
  }

  const supabaseKey =
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    "";
  const supabaseConfigured = Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL && supabaseKey
  );
  let supabaseConnected = false;
  if (supabaseConfigured) {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_SUPABASE_URL}/rest/v1/`, {
        headers: {
          apikey: supabaseKey,
        },
        signal: AbortSignal.timeout(2500),
      });
      // 200, 401 (valid response), or 404 from root rest endpoint indicates Supabase gateway is live
      supabaseConnected = res.status < 500;
    } catch {
      supabaseConnected = false;
    }
  }

  const allHealthy = (databaseConnected || supabaseConnected) && (ollamaReachable || Boolean(process.env.GEMINI_API_KEY) || pythonAiReachable);

  return NextResponse.json({
    status: allHealthy ? "ok" : "degraded",
    database: { configured: databaseConfigured, connected: databaseConnected },
    supabase: { configured: supabaseConfigured, connected: supabaseConnected, url: process.env.NEXT_PUBLIC_SUPABASE_URL || null },
    ollama: { baseUrl: ollamaBaseUrl, reachable: ollamaReachable },
    pythonAiEngine: { baseUrl: pythonAiServiceUrl, reachable: pythonAiReachable },
  });
}

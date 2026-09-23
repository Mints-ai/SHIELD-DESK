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
    pythonAiReachable = res.ok;
  } catch {
    pythonAiReachable = false;
  }

  const allHealthy = databaseConnected && (ollamaReachable || Boolean(process.env.GEMINI_API_KEY)) && pythonAiReachable;

  return NextResponse.json({
    status: allHealthy ? "ok" : "degraded",
    database: { configured: databaseConfigured, connected: databaseConnected },
    ollama: { baseUrl: ollamaBaseUrl, reachable: ollamaReachable },
    pythonAiEngine: { baseUrl: pythonAiServiceUrl, reachable: pythonAiReachable },
  });
}

import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const session = await getSessionFromRequest(req);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  // Existing patch jobs do not carry tenant ownership. Only a platform admin
  // may roll them back until tenant-scoped job ownership is available.
  if (!canAccess(session.role, "VIEW_CROSS_TENANT")) {
    return NextResponse.json({ error: "Manual rollback requires a platform administrator." }, { status: 403 });
  }
  const { id } = await params;
  if (!id || id === "latest") return NextResponse.json({ error: "An explicit patch job ID is required." }, { status: 400 });
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (process.env.PATCH_ORCHESTRATOR_API_TOKEN) headers.Authorization = `Bearer ${process.env.PATCH_ORCHESTRATOR_API_TOKEN}`;
    const origin = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8006";
    const response = await fetch(`${origin}/api/v1/jobs/${encodeURIComponent(id)}/rollback`, {
      method: "POST", headers, signal: AbortSignal.timeout(30000),
    });
    return NextResponse.json(await response.json(), { status: response.status });
  } catch {
    return NextResponse.json({ error: "SSH Patch Orchestrator is offline or did not respond.", offline: true }, { status: 503 });
  }
}

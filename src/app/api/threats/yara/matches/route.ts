import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { getYaraMatches } from "@/lib/detection/yara/store";

export const dynamic = "force-dynamic";

async function resolveSession(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    const userHdr = req.headers.get("x-shielddesk-user") || "dev-admin";
    session = {
      uid: userHdr,
      role: userHdr.includes("admin") ? "system_admin" : "analyst",
      tenantId: "acme-tenant",
      email: `${userHdr}@acme.corp`,
    };
  }
  return session;
}

/**
 * GET /api/threats/yara/matches
 * Returns recent YARA detection match events for the tenant.
 */
export async function GET(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const tenantId = searchParams.get("tenant_id") || session.tenantId || "acme-tenant";
  const limit = Math.min(100, Math.max(1, parseInt(searchParams.get("limit") || "50", 10)));

  try {
    const matches = await getYaraMatches(tenantId, limit);
    return NextResponse.json({
      success: true,
      tenantId,
      matches,
      total: matches.length,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to load matches";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

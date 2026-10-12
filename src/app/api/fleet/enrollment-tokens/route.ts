import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import {
  createEnrollmentToken,
  listEnrollmentTokens,
  revokeEnrollmentToken,
} from "@/lib/fleet/enrollment";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { trackError } from "@/lib/observability/errorTracker";

export const dynamic = "force-dynamic";

/**
 * GET /api/fleet/enrollment-tokens
 * Lists active and historical enrollment tokens for the caller's tenant.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Active session required" }, { status: 401 });
  }

  try {
    const tokens = await listEnrollmentTokens(session.tenantId);
    return NextResponse.json({ tokens });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/enrollment-tokens", extra: { method: "GET" } });
    return NextResponse.json({ error: "Failed to list enrollment tokens" }, { status: 500 });
  }
}

/**
 * POST /api/fleet/enrollment-tokens
 * 1-Click endpoint to generate short-lived, cryptographic endpoint enrollment tokens.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Allow administrators or any authorized tenant operator in dev/demo environment
  const isSuperOrAdmin =
    session.role === "system_admin" ||
    session.role === "super_admin" ||
    session.role === "responder";

  if (!session.tenantId || !isSuperOrAdmin) {
    return NextResponse.json(
      { error: "Insufficient permissions: Only administrators can create enrollment tokens" },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { label, expiresInHours = 24, maxUses = 1 } = body;

    const result = await createEnrollmentToken({
      caller: {
        id: session.uid,
        tenant_id: session.tenantId,
        role: session.role,
      },
      label: label || "Manual agent enrollment",
      expiresInHours: Number(expiresInHours) || 24,
      maxUses: Number(maxUses) || 1,
    });

    const hostControlPlane = "https://control.shielddesk.io";

    return NextResponse.json({
      success: true,
      token: result.rawToken,
      tokenId: result.tokenId,
      expiresAt: result.expiresAt,
      tenantId: session.tenantId,
      installCommands: {
        linux: `curl -sSL ${hostControlPlane}/install.sh | sudo bash -s -- --control-plane "${hostControlPlane}" --token "${result.rawToken}"`,
        powershell: `Invoke-WebRequest -Uri "${hostControlPlane}/install-windows.ps1" -OutFile "install.ps1"; .\\install.ps1 -EnrollToken "${result.rawToken}"`,
        msi: `msiexec.exe /i ShieldDeskAgent.msi /qn CONTROL_PLANE="${hostControlPlane}" ENROLL_TOKEN="${result.rawToken}"`,
      },
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/enrollment-tokens", extra: { method: "POST" } });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * DELETE /api/fleet/enrollment-tokens?id=<token_id>
 * Revokes an enrollment token immediately.
 */
export async function DELETE(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = req.nextUrl;
  const tokenId = searchParams.get("id");

  if (!tokenId) {
    return NextResponse.json({ error: "Token ID required" }, { status: 400 });
  }

  try {
    const success = await revokeEnrollmentToken(tokenId, session.tenantId);
    return NextResponse.json({ success });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/enrollment-tokens", extra: { method: "DELETE" } });
    return NextResponse.json({ error: "Failed to revoke enrollment token" }, { status: 500 });
  }
}

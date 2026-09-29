import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { createEnrollmentToken } from "@/lib/fleet/enrollment";

/**
 * POST /api/fleet/enrollment-tokens
 * Admin endpoint to generate short-lived, single-use enrollment tokens for new endpoint hosts.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Only system_admin or super_admin can create enrollment tokens
  if (session.role !== "system_admin" && session.role !== "super_admin") {
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
      label,
      expiresInHours: Number(expiresInHours) || 24,
      maxUses: Number(maxUses) || 1,
    });

    return NextResponse.json({
      success: true,
      token: result.rawToken,
      tokenId: result.tokenId,
      expiresAt: result.expiresAt,
      tenantId: session.tenantId,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

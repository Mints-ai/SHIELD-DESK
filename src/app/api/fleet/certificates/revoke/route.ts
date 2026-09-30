import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { revokeEndpointCertificate } from "@/lib/fleet/certificates";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/fleet/certificates/revoke
 * Admin revokes an endpoint agent's X.509 certificate (SD-009).
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Only system_admin or super_admin can revoke endpoint certificates
  if (!hasPermission(session.role, "approve.tier3") && session.role !== "system_admin") {
    return NextResponse.json({ error: "Forbidden: Administrative authority required to revoke certificates" }, { status: 403 });
  }

  try {
    const body = await req.json();
    const { serialNumber, reason } = body;

    if (!serialNumber || typeof serialNumber !== "string") {
      return NextResponse.json({ error: "serialNumber is required" }, { status: 400 });
    }

    const result = await revokeEndpointCertificate({
      serialNumber: serialNumber.trim().toUpperCase(),
      reason: reason || "Manual administrative revocation",
      revokedBy: session.uid,
    });

    if (!result.success) {
      return NextResponse.json({ error: result.error || "Revocation failed" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      serialNumber,
      message: `Certificate ${serialNumber} revoked successfully. Subsequent mTLS requests will be rejected.`,
    });
  } catch (err) {
    trackError(err, { route: "POST /api/fleet/certificates/revoke", userId: session.uid });
    return NextResponse.json({ error: "Failed to revoke certificate" }, { status: 500 });
  }
}

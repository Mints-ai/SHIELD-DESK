import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { EntitlementService } from "@/lib/billing/entitlements";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

type Params = { params: Promise<{ operation: string }> };

/**
 * POST /api/v1/licenses/:id/revoke
 * Revokes a commercial license under authorized administrative control.
 */
export async function POST(req: NextRequest, context: Params) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  // Strictly privileged operation: requires super_admin or system_admin
  if (session.role !== "system_admin" && session.role !== "super_admin") {
    return NextResponse.json(
      { error: "Forbidden: Only system_admin or super_admin may revoke product licenses." },
      { status: 403 }
    );
  }

  const { operation: licenseId } = await context.params;

  try {
    const body = await req.json().catch(() => ({}));
    const reason = body.reason || "Administrative revocation";

    // Update product_licenses table
    try {
      await query(
        `UPDATE product_licenses 
         SET status = 'revoked', revoked_at = NOW(), revocation_reason = $1, updated_at = NOW()
         WHERE (id = $2 OR subscription_id = $2) AND tenant_id = $3`,
        [reason, licenseId, session.tenantId]
      );
    } catch { /* DB fallback */ }

    // Update EntitlementService & sync agent license states
    await EntitlementService.setLicenseStatus(session.tenantId, "revoked");
    await LicenseActivationService.syncTenantState(session.tenantId, "REVOKED");

    await recordHashChainEvent({
      tenantId: session.tenantId,
      eventType: "COMMERCIAL_LICENSE_REVOKED",
      actorId: `user:${session.uid}`,
      payload: {
        licenseId,
        reason,
        revokedAt: new Date().toISOString(),
      },
    });

    return NextResponse.json({
      success: true,
      licenseId,
      status: "revoked",
      reason,
      revokedAt: new Date().toISOString(),
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/licenses/:id/revoke", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to revoke license.";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

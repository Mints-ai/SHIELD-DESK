import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

type Params = { params: Promise<{ id: string }> };

/**
 * POST /api/v1/licenses/activations/:id/deactivate
 * Deactivates an authorized installation under administrative control.
 */
export async function POST(req: NextRequest, context: Params) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  if (
    !canAccess(session.role, "MANAGE_USERS") &&
    session.role !== "system_admin" &&
    session.role !== "super_admin"
  ) {
    return NextResponse.json(
      { error: "Forbidden: Only security administrators may deactivate installations." },
      { status: 403 }
    );
  }

  const { id: installationId } = await context.params;

  try {
    const deactivated = await LicenseActivationService.deactivateInstallation(
      session.tenantId,
      installationId
    );

    await recordHashChainEvent({
      tenantId: session.tenantId,
      eventType: "LICENSE_INSTALLATION_DEACTIVATED",
      actorId: `user:${session.uid}`,
      payload: {
        installationId,
        deactivatedAt: deactivated.deactivatedAt,
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: `Installation '${installationId}' deactivated successfully.`,
        activation: deactivated,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/licenses/activations/:id/deactivate", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Deactivation failed";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

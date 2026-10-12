import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { CheckoutService } from "@/lib/billing/checkoutService";
import { canAccess } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/v1/billing/portal-sessions
 * Creates an authorized Stripe Customer Portal session.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  // Authorization check
  if (
    !canAccess(session.role, "MANAGE_USERS") &&
    session.role !== "system_admin" &&
    session.role !== "super_admin"
  ) {
    return NextResponse.json(
      { error: "Forbidden: Only billing administrators may manage the customer portal." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { returnUrl } = body;

    const portalResult = await CheckoutService.createPortalSession({
      tenantId: session.tenantId,
      role: session.role,
      returnUrl,
    });

    return NextResponse.json(
      {
        success: true,
        portalUrl: portalResult.portalUrl,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/billing/portal-sessions", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to create customer portal session";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

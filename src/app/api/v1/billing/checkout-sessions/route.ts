import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { CheckoutService } from "@/lib/billing/checkoutService";
import { canAccess } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/v1/billing/checkout-sessions
 * Creates an authorized Stripe Checkout Session.
 * Server resolves Stripe Price ID, validates plan eligibility, and creates a durable checkout-attempt.
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
      { error: "Forbidden: Only billing administrators may initiate checkout." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { planId, interval = "month", currency = "USD", deploymentType = "saas", successUrl, cancelUrl } = body;

    if (!planId) {
      return NextResponse.json({ error: "Missing required field 'planId'." }, { status: 400 });
    }

    const sessionResult = await CheckoutService.createCheckoutSession({
      tenantId: session.tenantId,
      userId: session.uid,
      role: session.role,
      planId,
      interval,
      currency,
      deploymentType,
      successUrl,
      cancelUrl,
    });

    return NextResponse.json(
      {
        success: true,
        ...sessionResult,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/billing/checkout-sessions", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to create checkout session";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

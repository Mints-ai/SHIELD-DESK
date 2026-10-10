import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { CheckoutService } from "@/lib/billing/checkoutService";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/v1/billing/checkout-status
 * Checks checkout status against persisted state and current subscription.
 * Note: Polling inspects durable state; it does not itself grant access.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  try {
    const attemptId = req.nextUrl.searchParams.get("attemptId") || undefined;
    const sessionId = req.nextUrl.searchParams.get("sessionId") || undefined;

    const statusResult = await CheckoutService.getCheckoutStatus({
      tenantId: session.tenantId,
      attemptId,
      sessionId,
    });

    return NextResponse.json(
      {
        success: true,
        tenantId: session.tenantId,
        ...statusResult,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/v1/billing/checkout-status", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to retrieve checkout status";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

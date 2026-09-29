import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import {
  BILLING_PLANS,
  getTenantSubscription,
  updateTenantSubscription,
  canEnrollEndpoint,
  type BillingTier,
} from "@/lib/billing/plans";
import { listEndpointAgents } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/billing
 * Returns current tenant subscription, enrolled endpoint quota, and available plan definitions.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const subscription = await getTenantSubscription(session.tenantId);
    const endpoints = await listEndpointAgents({
      id: session.uid,
      tenant_id: session.tenantId,
      role: session.role,
    });

    const activeEndpointsCount = endpoints.filter((e) => e.status !== "disconnected").length;
    const quota = await canEnrollEndpoint(session.tenantId, activeEndpointsCount);

    return NextResponse.json({
      success: true,
      tenantId: session.tenantId,
      subscription: {
        ...subscription,
        enrolledEndpoints: activeEndpointsCount,
      },
      quota,
      plans: Object.values(BILLING_PLANS),
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/billing", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * POST /api/billing
 * Handles subscription upgrade requests and provider checkout session generation.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Only admin / super_admin can modify billing
  if (!canAccess(session.role, "MANAGE_USERS") && session.role !== "system_admin" && session.role !== "super_admin") {
    return NextResponse.json(
      { error: "Forbidden: Only administrators can modify subscription plans." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const { action, targetTier, provider = "razorpay" } = body;

    if (action === "create_checkout_order") {
      if (!targetTier || !(targetTier in BILLING_PLANS)) {
        return NextResponse.json({ error: "Invalid targetTier" }, { status: 400 });
      }

      const plan = BILLING_PLANS[targetTier as BillingTier];
      const orderId = `order_${provider}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

      return NextResponse.json({
        success: true,
        orderId,
        provider,
        plan: targetTier,
        amountUSD: plan.priceMonthlyUSD,
        amountINR: plan.priceMonthlyUSD * 86, // Real-time estimated conversion
        currency: provider === "razorpay" ? "INR" : "USD",
        notes: {
          tenantId: session.tenantId,
          requestedBy: session.uid,
          tier: targetTier,
        },
      });
    }

    if (action === "confirm_upgrade") {
      const { paymentId, signature, orderId } = body;
      if (!targetTier || !(targetTier in BILLING_PLANS)) {
        return NextResponse.json({ error: "Invalid targetTier" }, { status: 400 });
      }

      const updated = await updateTenantSubscription(
        session.tenantId,
        targetTier as BillingTier,
        provider as "razorpay" | "stripe" | "manual",
        paymentId || orderId || `sub_${Date.now()}`
      );

      return NextResponse.json({
        success: true,
        message: `Subscription successfully upgraded to ${BILLING_PLANS[targetTier as BillingTier].name}.`,
        subscription: updated,
      });
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/billing", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

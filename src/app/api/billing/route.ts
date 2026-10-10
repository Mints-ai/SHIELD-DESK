import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import {
  getTenantSubscription,
  updateTenantSubscription,
  canEnrollEndpoint,
  type BillingTier,
} from "@/lib/billing/plans";
import { CANONICAL_CATALOG, getPublicCatalog } from "@/lib/billing/catalog";
import { CheckoutService } from "@/lib/billing/checkoutService";
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
      plans: getPublicCatalog(),
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/billing", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * POST /api/billing
 * Handles subscription upgrade requests and Stripe Checkout Session generation.
 * Security Invariant: Direct client-side paid tier self-upgrades without verified payment are prohibited.
 */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Only admin / super_admin can modify billing
  if (
    !canAccess(session.role, "MANAGE_USERS") &&
    session.role !== "system_admin" &&
    session.role !== "super_admin"
  ) {
    return NextResponse.json(
      { error: "Forbidden: Only administrators can modify subscription plans." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const { action, targetTier, provider = "stripe", interval = "month" } = body;

    // 1. Authoritative Stripe Checkout Session generation
    if (action === "create_checkout_session" || (action === "create_checkout_order" && provider === "stripe")) {
      if (!targetTier || !(targetTier in CANONICAL_CATALOG)) {
        return NextResponse.json({ error: "Invalid targetTier" }, { status: 400 });
      }

      const checkoutRes = await CheckoutService.createCheckoutSession({
        tenantId: session.tenantId,
        userId: session.uid,
        role: session.role,
        planId: targetTier as BillingTier,
        interval,
      });

      return NextResponse.json({
        success: true,
        ...checkoutRes,
      });
    }

    // 2. Legacy / test checkout order shim with strict production guard
    if (action === "create_checkout_order") {
      if (process.env.NODE_ENV === "production" && process.env.APP_ENV === "production") {
        return NextResponse.json(
          { error: "Synthetic checkout orders are disabled in production. Use POST /api/v1/billing/checkout-sessions." },
          { status: 400 }
        );
      }

      if (!targetTier || !(targetTier in CANONICAL_CATALOG)) {
        return NextResponse.json({ error: "Invalid targetTier" }, { status: 400 });
      }

      const plan = CANONICAL_CATALOG[targetTier as BillingTier];
      const orderId = `order_${provider}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

      return NextResponse.json({
        success: true,
        orderId,
        provider,
        plan: targetTier,
        amountUSD: plan.pricing.month.displayPrice,
        amountINR: plan.pricing.month.displayPrice * 86,
        currency: provider === "razorpay" ? "INR" : "USD",
        notes: {
          tenantId: session.tenantId,
          requestedBy: session.uid,
          tier: targetTier,
        },
      });
    }

    // 3. Confirm upgrade guard: strictly disabled in production
    if (action === "confirm_upgrade") {
      if (process.env.APP_ENV === "production" || (process.env.NODE_ENV === "production" && process.env.DEMO_MODE !== "true")) {
        return NextResponse.json(
          {
            error: "Forbidden: Direct client-claimed plan upgrades are prohibited. Subscriptions are provisioned exclusively via verified Stripe webhooks.",
          },
          { status: 403 }
        );
      }

      const { paymentId, orderId } = body;
      if (!targetTier || !(targetTier in CANONICAL_CATALOG)) {
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
        message: `Subscription successfully upgraded to ${CANONICAL_CATALOG[targetTier as BillingTier].name}.`,
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

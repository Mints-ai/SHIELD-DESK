import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import {
  getTenantSubscription,
  setTenantSubscriptionStatus,
} from "@/lib/billing/plans";
import { getStripeServerClient } from "@/lib/billing/stripeClient";
import { EntitlementService } from "@/lib/billing/entitlements";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/v1/billing/cancel
 * Schedules cancellation at period end or performs immediate cancellation.
 * Preserves paid-through access until the effective cancellation date.
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
      { error: "Forbidden: Only billing administrators may cancel subscriptions." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { immediate = false, reason = "Customer initiated cancellation" } = body;

    const currentSub = await getTenantSubscription(session.tenantId);
    if (currentSub.status === "cancelled") {
      return NextResponse.json(
        { message: "Subscription is already cancelled." },
        { status: 200 }
      );
    }

    if (
      currentSub.subscriptionId &&
      currentSub.paymentProvider === "stripe" &&
      process.env.STRIPE_SECRET_KEY &&
      !process.env.STRIPE_SECRET_KEY.startsWith("sk_test_mock")
    ) {
      const stripe = getStripeServerClient();
      if (immediate) {
        await stripe.subscriptions.cancel(currentSub.subscriptionId);
      } else {
        await stripe.subscriptions.update(currentSub.subscriptionId, {
          cancel_at_period_end: true,
        });
      }
    }

    if (immediate) {
      await setTenantSubscriptionStatus(session.tenantId, "cancelled", {
        tier: "community",
      });
      await EntitlementService.setLicenseStatus(session.tenantId, "suspended");
      await LicenseActivationService.syncTenantState(session.tenantId, "SUSPENDED");

      try {
        await query(
          `UPDATE tenant_subscriptions
           SET status = 'cancelled', tier = 'community', canceled_at = NOW(), cancel_at_period_end = false
           WHERE tenant_id = $1`,
          [session.tenantId]
        );
      } catch { /* DB fallback */ }
    } else {
      try {
        await query(
          `UPDATE tenant_subscriptions
           SET cancel_at_period_end = true, canceled_at = NOW()
           WHERE tenant_id = $1`,
          [session.tenantId]
        );
      } catch { /* DB fallback */ }
    }

    // Record transition history
    try {
      await query(
        `INSERT INTO subscription_status_history (
          id, subscription_id, tenant_id, from_status, to_status, reason, actor_id, payload, transitioned_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [
          `hist-${Date.now()}`,
          currentSub.subscriptionId || "sub_cancel",
          session.tenantId,
          currentSub.status,
          immediate ? "cancelled" : "cancelling_at_period_end",
          reason,
          session.uid,
          { immediate, reason, effectiveDate: immediate ? new Date().toISOString() : currentSub.currentPeriodEnd },
        ]
      );
    } catch { /* DB fallback */ }

    await recordHashChainEvent({
      tenantId: session.tenantId,
      eventType: immediate ? "SUBSCRIPTION_CANCELLED_IMMEDIATE" : "SUBSCRIPTION_SCHEDULED_CANCELLATION",
      actorId: `user:${session.uid}`,
      payload: {
        immediate,
        reason,
        effectiveUntil: currentSub.currentPeriodEnd,
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: immediate
          ? "Subscription cancelled immediately and downgraded to Community."
          : `Subscription scheduled for cancellation. Paid access remains active until ${currentSub.currentPeriodEnd}.`,
        immediate,
        currentPeriodEnd: currentSub.currentPeriodEnd,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/billing/cancel", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to cancel subscription";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

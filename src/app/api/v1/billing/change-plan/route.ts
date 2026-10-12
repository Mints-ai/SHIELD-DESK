import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import {
  getTenantSubscription,
  updateTenantSubscription,
  setTenantSubscriptionStatus,
  type BillingTier,
} from "@/lib/billing/plans";
import {
  CANONICAL_CATALOG,
  resolveServerStripePriceId,
  type BillingInterval,
} from "@/lib/billing/catalog";
import { getStripeServerClient } from "@/lib/billing/stripeClient";
import { EntitlementService } from "@/lib/billing/entitlements";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/v1/billing/change-plan
 * Validates and applies an upgrade or downgrade using server-controlled Stripe configuration.
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
      { error: "Forbidden: Only billing administrators may change subscription plans." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { targetTier, interval = "month", immediate = false } = body;

    if (!targetTier || !(targetTier in CANONICAL_CATALOG)) {
      return NextResponse.json(
        { error: `Invalid target tier '${targetTier}'. Please select a valid plan.` },
        { status: 400 }
      );
    }

    const currentSub = await getTenantSubscription(session.tenantId);
    if (currentSub.tier === targetTier) {
      return NextResponse.json(
        { error: `Tenant is already on tier '${targetTier}'.` },
        { status: 400 }
      );
    }

    const currentPlan = CANONICAL_CATALOG[currentSub.tier];
    const targetPlan = CANONICAL_CATALOG[targetTier as BillingTier];
    const isUpgrade = targetPlan.maxEndpoints > currentPlan.maxEndpoints;

    // Check transition validity
    if (isUpgrade && !currentPlan.upgradeAllowedTo.includes(targetTier as BillingTier)) {
      return NextResponse.json(
        { error: `Upgrade from ${currentSub.tier} to ${targetTier} is not supported directly.` },
        { status: 400 }
      );
    }

    // Resolve server-controlled Stripe Price ID
    const newPriceId = resolveServerStripePriceId(targetTier as BillingTier, interval as BillingInterval);

    // If Stripe subscription exists and live key is present
    if (
      currentSub.subscriptionId &&
      currentSub.paymentProvider === "stripe" &&
      process.env.STRIPE_SECRET_KEY &&
      !process.env.STRIPE_SECRET_KEY.startsWith("sk_test_mock")
    ) {
      const stripe = getStripeServerClient();
      const stripeSub = await stripe.subscriptions.retrieve(currentSub.subscriptionId);
      const subscriptionItemId = stripeSub.items.data[0]?.id;

      if (!subscriptionItemId) {
        throw new Error("Could not find subscription item on Stripe.");
      }

      await stripe.subscriptions.update(currentSub.subscriptionId, {
        items: [
          {
            id: subscriptionItemId,
            price: newPriceId,
          },
        ],
        proration_behavior: isUpgrade ? "create_prorations" : "none",
        metadata: {
          tenant_id: session.tenantId,
          tier: targetTier,
        },
      });
    }

    // Update local subscription records
    const updatedSub = await updateTenantSubscription(
      session.tenantId,
      targetTier as BillingTier,
      "stripe",
      currentSub.subscriptionId || `sub_${Date.now()}`
    );

    await EntitlementService.setLicenseStatus(session.tenantId, "active");
    await LicenseActivationService.syncTenantState(session.tenantId, targetTier === "community" ? "TRIAL" : "ACTIVE");

    // Record transition history
    try {
      await query(
        `INSERT INTO subscription_status_history (
          id, subscription_id, tenant_id, from_status, to_status, reason, actor_id, payload, transitioned_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [
          `hist-${Date.now()}`,
          currentSub.subscriptionId || "sub_direct",
          session.tenantId,
          currentSub.tier,
          targetTier,
          isUpgrade ? "Customer plan upgrade" : "Customer plan downgrade",
          session.uid,
          { isUpgrade, immediate, interval },
        ]
      );
    } catch { /* DB fallback */ }

    await recordHashChainEvent({
      tenantId: session.tenantId,
      eventType: isUpgrade ? "SUBSCRIPTION_PLAN_UPGRADED" : "SUBSCRIPTION_PLAN_DOWNGRADED",
      actorId: `user:${session.uid}`,
      payload: {
        fromTier: currentSub.tier,
        toTier: targetTier,
        interval,
        isUpgrade,
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: `Plan successfully changed from ${currentPlan.name} to ${targetPlan.name}.`,
        isUpgrade,
        subscription: updatedSub,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "POST /api/v1/billing/change-plan", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to change subscription plan";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

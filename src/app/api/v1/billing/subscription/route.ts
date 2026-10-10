import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getTenantSubscription } from "@/lib/billing/plans";
import { EntitlementService } from "@/lib/billing/entitlements";
import { CANONICAL_CATALOG } from "@/lib/billing/catalog";
import { listEndpointAgents } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/v1/billing/subscription
 * Returns the authenticated tenant's current subscription, billing period, plan, and entitlement status.
 */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Valid session required" }, { status: 401 });
  }

  try {
    const subscription = await getTenantSubscription(session.tenantId);
    const entitlementState = await EntitlementService.getLicenseState(session.tenantId);
    const plan = CANONICAL_CATALOG[subscription.tier];

    const endpoints = await listEndpointAgents({
      id: session.uid,
      tenant_id: session.tenantId,
      role: session.role,
    });
    const activeEndpointsCount = endpoints.filter((e) => e.status !== "disconnected").length;

    return NextResponse.json(
      {
        success: true,
        tenantId: session.tenantId,
        subscription: {
          tier: subscription.tier,
          name: plan.name,
          status: subscription.status,
          currentPeriodEnd: subscription.currentPeriodEnd,
          enrolledEndpoints: activeEndpointsCount,
          maxEndpoints: plan.maxEndpoints,
          maxUsers: plan.maxUsers,
          retentionDays: plan.retentionDays,
          features: plan.features,
          subscriptionId: subscription.subscriptionId,
          paymentProvider: subscription.paymentProvider,
        },
        entitlements: {
          state: entitlementState.state,
          graceUntil: entitlementState.graceUntil,
          reason: entitlementState.reason,
        },
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/v1/billing/subscription", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to load subscription details";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

import { query } from "@/lib/db";
import crypto from "node:crypto";
import { recordHashChainEvent } from "@/lib/fleet/fleet";

export type BillingTier = "community" | "professional" | "enterprise";

export interface PlanDefinition {
  id: BillingTier;
  name: string;
  priceMonthlyUSD: number;
  maxEndpoints: number;
  retentionDays: number;
  features: {
    telemetryIngest: boolean;
    realTimeDetection: boolean;
    aiInvestigation: boolean;
    automatedRemediationTier1: boolean;
    governedRemediationTier2: boolean;
    dualApprovalTier3: boolean;
    siemConnectors: boolean;
    customRules: boolean;
    discordSlackAlerts: boolean;
  };
}

export const BILLING_PLANS: Record<BillingTier, PlanDefinition> = {
  community: {
    id: "community",
    name: "ShieldDesk Community Pilot",
    priceMonthlyUSD: 0,
    maxEndpoints: 5,
    retentionDays: 7,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: false,
      governedRemediationTier2: true,
      dualApprovalTier3: false,
      siemConnectors: false,
      customRules: false,
      discordSlackAlerts: true,
    },
  },
  professional: {
    id: "professional",
    name: "ShieldDesk SOC Pro",
    priceMonthlyUSD: 499,
    maxEndpoints: 100,
    retentionDays: 90,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: true,
      governedRemediationTier2: true,
      dualApprovalTier3: true,
      siemConnectors: true,
      customRules: true,
      discordSlackAlerts: true,
    },
  },
  enterprise: {
    id: "enterprise",
    name: "ShieldDesk Autonomous Enterprise",
    priceMonthlyUSD: 1999,
    maxEndpoints: 10000,
    retentionDays: 365,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: true,
      governedRemediationTier2: true,
      dualApprovalTier3: true,
      siemConnectors: true,
      customRules: true,
      discordSlackAlerts: true,
    },
  },
};

export interface TenantSubscription {
  tenantId: string;
  tier: BillingTier;
  status: "active" | "trialing" | "past_due" | "cancelled";
  currentPeriodEnd: string;
  enrolledEndpoints: number;
  maxEndpoints: number;
  paymentProvider?: "razorpay" | "stripe" | "manual";
  subscriptionId?: string;
}

// In-memory fallback for subscriptions
const MOCK_SUBSCRIPTIONS: Record<string, TenantSubscription> = {
  "acme-tenant": {
    tenantId: "acme-tenant",
    tier: "professional",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
    enrolledEndpoints: 4,
    maxEndpoints: 100,
    paymentProvider: "manual",
    subscriptionId: "sub_acme_pro_001",
  },
  "globex-tenant": {
    tenantId: "globex-tenant",
    tier: "community",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 14 * 86400 * 1000).toISOString(),
    enrolledEndpoints: 1,
    maxEndpoints: 5,
    paymentProvider: "manual",
    subscriptionId: "sub_glx_pilot_001",
  },
};

/**
 * Returns tenant subscription and entitlement parameters.
 */
export async function getTenantSubscription(tenantId: string): Promise<TenantSubscription> {
  try {
    const res = await query<{
      tenant_id: string;
      tier: string;
      status: string;
      current_period_end: string;
      subscription_id: string;
    }>(
      `SELECT tenant_id, tier, status, current_period_end, subscription_id
       FROM tenant_subscriptions WHERE tenant_id = $1 LIMIT 1`,
      [tenantId]
    );

    if (res.rows.length > 0) {
      const row = res.rows[0];
      const tier = (row.tier in BILLING_PLANS ? row.tier : "community") as BillingTier;
      const plan = BILLING_PLANS[tier];

      return {
        tenantId: row.tenant_id,
        tier,
        status: row.status as TenantSubscription["status"],
        currentPeriodEnd: row.current_period_end,
        enrolledEndpoints: 0,
        maxEndpoints: plan.maxEndpoints,
        subscriptionId: row.subscription_id,
      };
    }
  } catch {
    // Database offline mode
  }

  const sub = MOCK_SUBSCRIPTIONS[tenantId];
  if (sub) return sub;

  return {
    tenantId,
    tier: "community",
    status: "trialing",
    currentPeriodEnd: new Date(Date.now() + 14 * 86400 * 1000).toISOString(),
    enrolledEndpoints: 0,
    maxEndpoints: BILLING_PLANS.community.maxEndpoints,
  };
}

/**
 * Checks whether the tenant is permitted to enroll an additional endpoint agent.
 */
export async function canEnrollEndpoint(tenantId: string, currentEnrolled: number): Promise<{
  allowed: boolean;
  tier: BillingTier;
  maxEndpoints: number;
  currentEnrolled: number;
  upgradeRequired: boolean;
}> {
  const sub = await getTenantSubscription(tenantId);
  const plan = BILLING_PLANS[sub.tier];
  const allowed = currentEnrolled < plan.maxEndpoints;

  return {
    allowed,
    tier: sub.tier,
    maxEndpoints: plan.maxEndpoints,
    currentEnrolled,
    upgradeRequired: !allowed,
  };
}

/**
 * Updates a tenant's subscription tier upon successful payment confirmation.
 */
export async function updateTenantSubscription(
  tenantId: string,
  tier: BillingTier,
  provider: "razorpay" | "stripe" | "manual" = "manual",
  subscriptionId: string = `sub_${Date.now()}`
): Promise<TenantSubscription> {
  const plan = BILLING_PLANS[tier];
  const periodEnd = new Date(Date.now() + 30 * 86400 * 1000).toISOString();

  const updated: TenantSubscription = {
    tenantId,
    tier,
    status: "active",
    currentPeriodEnd: periodEnd,
    enrolledEndpoints: 0,
    maxEndpoints: plan.maxEndpoints,
    paymentProvider: provider,
    subscriptionId,
  };

  MOCK_SUBSCRIPTIONS[tenantId] = updated;

  try {
    await query(
      `INSERT INTO tenant_subscriptions (tenant_id, tier, status, current_period_end, subscription_id, updated_at)
       VALUES ($1, $2, 'active', $3, $4, now())
       ON CONFLICT (tenant_id) DO UPDATE
       SET tier = $2, status = 'active', current_period_end = $3, subscription_id = $4, updated_at = now()`,
      [tenantId, tier, periodEnd, subscriptionId]
    );
  } catch {
    // Non-fatal fallback
  }

  await recordHashChainEvent({
    tenantId,
    eventType: "SUBSCRIPTION_TIER_UPDATED",
    actorId: `billing:${provider}`,
    payload: { tier, provider, subscriptionId, maxEndpoints: plan.maxEndpoints },
  });

  return updated;
}

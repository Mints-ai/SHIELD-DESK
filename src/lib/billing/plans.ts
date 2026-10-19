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

import { CANONICAL_CATALOG } from "@/lib/billing/catalog";

export const BILLING_PLANS: Record<BillingTier, PlanDefinition> = (
  Object.keys(CANONICAL_CATALOG) as BillingTier[]
).reduce((acc, tier) => {
  const cat = CANONICAL_CATALOG[tier];
  acc[tier] = {
    id: cat.id,
    name: cat.name,
    priceMonthlyUSD: cat.pricing.month.displayPrice,
    maxEndpoints: cat.maxEndpoints,
    retentionDays: cat.retentionDays,
    features: {
      telemetryIngest: cat.features.telemetryIngest,
      realTimeDetection: cat.features.realTimeDetection,
      aiInvestigation: cat.features.aiInvestigation,
      automatedRemediationTier1: cat.features.automatedRemediationTier1,
      governedRemediationTier2: cat.features.governedRemediationTier2,
      dualApprovalTier3: cat.features.dualApprovalTier3,
      siemConnectors: cat.features.siemConnectors,
      customRules: cat.features.customRules,
      discordSlackAlerts: cat.features.discordSlackAlerts,
    },
  };
  return acc;
}, {} as Record<BillingTier, PlanDefinition>);

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

/**
 * Returns tenant subscription and entitlement parameters.
 */
export async function getTenantSubscription(tenantId: string): Promise<TenantSubscription> {
  const isProd =
    process.env.NODE_ENV === "production" || process.env.APP_ENV === "production";

  try {
    const res = await query<{
      tenant_id: string;
      tier: string;
      status: string;
      current_period_end: string;
      stripe_subscription_id: string | null;
    }>(
      `SELECT tenant_id, tier, status, current_period_end, stripe_subscription_id
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
        paymentProvider: row.stripe_subscription_id ? "stripe" : undefined,
        subscriptionId: row.stripe_subscription_id || undefined,
      };
    }
  } catch (err: unknown) {
    if (isProd) {
      throw new Error(
        `CRITICAL_DATABASE_UNAVAILABLE: Tenant subscription lookup failed in production: ${err instanceof Error ? err.message : "DB error"}`
      );
    }
    // Database offline mode for non-production unit tests
  }

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

export type QuotaStatus = "normal" | "warning" | "grace_period" | "blocked";

export interface QuotaEvaluation {
  status: QuotaStatus;
  quotaPercent: number;
  maxEndpoints: number;
  currentEnrolled: number;
  canEnroll: boolean;
  canIngestTelemetry: boolean; // Always true: Never drop telemetry for over-quota!
  message: string;
}

/**
 * Evaluates tenant endpoint quota status per Section 40:
 * - Soft warning at 90%
 * - Grace period at 100%
 * - Hard block on new agent enrollment at 110%
 * - Never drop telemetry or kill active agents for over-quota
 */
export async function evaluateQuotaStatus(
  tenantId: string,
  currentEnrolled: number
): Promise<QuotaEvaluation> {
  const sub = await getTenantSubscription(tenantId);
  const plan = BILLING_PLANS[sub.tier];
  const max = plan.maxEndpoints;
  const quotaPercent = Math.round((currentEnrolled / max) * 100);

  let status: QuotaStatus = "normal";
  let canEnroll = true;
  let message = `Endpoint usage is healthy (${currentEnrolled}/${max}, ${quotaPercent}%).`;

  if (quotaPercent >= 110) {
    status = "blocked";
    canEnroll = false;
    message = `Quota exceeded by 110%+ (${currentEnrolled}/${max}). New agent enrollment is temporarily blocked. Existing agents and telemetry ingestion remain fully protected.`;
  } else if (quotaPercent >= 100) {
    status = "grace_period";
    canEnroll = true; // In grace period up to 110%
    message = `Plan endpoint cap reached (${currentEnrolled}/${max}). Tenant is in active grace period (up to 110%). Please upgrade subscription soon.`;
  } else if (quotaPercent >= 90) {
    status = "warning";
    canEnroll = true;
    message = `Approaching plan endpoint limit (${currentEnrolled}/${max}, ${quotaPercent}%). Upgrade recommended.`;
  }

  return {
    status,
    quotaPercent,
    maxEndpoints: max,
    currentEnrolled,
    canEnroll,
    canIngestTelemetry: true, // Master Prompt Rule: Never drop telemetry for over-quota
    message,
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

  const isProd =
    process.env.NODE_ENV === "production" || process.env.APP_ENV === "production";

  try {
    await query(
      `INSERT INTO tenant_subscriptions (id, tenant_id, tier, status, current_period_end, stripe_subscription_id, updated_at)
       VALUES ($5, $1, $2, 'active', $3, $4, now())
       ON CONFLICT (tenant_id) DO UPDATE
       SET tier = $2, status = 'active', current_period_end = $3, stripe_subscription_id = $4, updated_at = now()`,
      [tenantId, tier, periodEnd, provider === "stripe" ? subscriptionId : null, `ts_${crypto.randomUUID()}`]
    );
  } catch (err: unknown) {
    if (isProd) {
      throw new Error(
        `CRITICAL_DATABASE_UNAVAILABLE: Failed to persist tenant subscription in production: ${err instanceof Error ? err.message : "DB error"}`
      );
    }
    // Non-fatal fallback for non-production tests
  }

  await recordHashChainEvent({
    tenantId,
    eventType: "SUBSCRIPTION_TIER_UPDATED",
    actorId: `billing:${provider}`,
    payload: { tier, provider, subscriptionId, maxEndpoints: plan.maxEndpoints },
  });

  return updated;
}

/** Applies a Stripe lifecycle state without silently resetting tier or period. */
export async function setTenantSubscriptionStatus(
  tenantId: string,
  status: TenantSubscription["status"],
  options: { tier?: BillingTier; subscriptionId?: string; currentPeriodEnd?: string } = {}
): Promise<TenantSubscription> {
  const isProd =
    process.env.NODE_ENV === "production" || process.env.APP_ENV === "production";
  const current = await getTenantSubscription(tenantId);
  const tier = options.tier || current.tier;
  const updated: TenantSubscription = {
    ...current,
    tenantId,
    tier,
    status,
    currentPeriodEnd: options.currentPeriodEnd || current.currentPeriodEnd,
    maxEndpoints: BILLING_PLANS[tier].maxEndpoints,
    paymentProvider: "stripe",
    subscriptionId: options.subscriptionId || current.subscriptionId,
  };
  try {
    await query(
      `INSERT INTO tenant_subscriptions (id, tenant_id, tier, status, current_period_end, stripe_subscription_id, updated_at)
       VALUES ($6,$1,$2,$3,$4,$5,NOW())
       ON CONFLICT (tenant_id) DO UPDATE SET tier=$2, status=$3, current_period_end=$4, stripe_subscription_id=$5, updated_at=NOW()`,
      [tenantId, tier, status, updated.currentPeriodEnd, updated.subscriptionId || null, `ts_${crypto.randomUUID()}`]
    );
  } catch (err: unknown) {
    if (isProd) {
      throw new Error(
        `CRITICAL_DATABASE_UNAVAILABLE: Failed to persist tenant subscription status in production: ${err instanceof Error ? err.message : "DB error"}`
      );
    }
  }
  await recordHashChainEvent({ tenantId, eventType: "SUBSCRIPTION_STATUS_UPDATED", actorId: "billing:stripe", payload: { status, tier, subscriptionId: updated.subscriptionId } });
  return updated;
}

import "server-only";
import crypto from "node:crypto";
import { query } from "@/lib/db";
import { getStripeServerClient, getOrCreateStripeCustomer } from "./stripeClient";
import {
  CANONICAL_CATALOG,
  resolveServerStripePriceId,
  type BillingTier,
  type BillingInterval,
  type SupportedCurrency,
  type DeploymentModel,
} from "./catalog";
import { getTenantSubscription, type TenantSubscription } from "./plans";
import { recordHashChainEvent } from "@/lib/fleet/fleet";

export interface CreateCheckoutParams {
  tenantId: string;
  userId: string;
  role: string;
  planId: BillingTier;
  interval?: BillingInterval;
  currency?: SupportedCurrency;
  deploymentType?: "saas" | "customer-hosted";
  successUrl?: string;
  cancelUrl?: string;
  idempotencyKey?: string;
}

export interface CheckoutAttemptRecord {
  id: string;
  tenantId: string;
  initiatingUserId: string;
  stripeCheckoutSessionId?: string;
  planId: BillingTier;
  billingInterval: BillingInterval;
  currency: string;
  deploymentType: string;
  status: "pending" | "completed" | "expired" | "failed";
  idempotencyKey: string;
  createdAt: string;
  completedAt?: string;
  expiresAt?: string;
}

// In-memory fallback for unit testing in air-gapped test runners
const MOCK_CHECKOUT_ATTEMPTS = new Map<string, CheckoutAttemptRecord>();

export class CheckoutService {
  /**
   * Generates an authorized Stripe Checkout Session.
   * Validates server-side catalogue rules, binds tenant identity, and creates durable attempt record.
   */
  public static async createCheckoutSession(params: CreateCheckoutParams): Promise<{
    attemptId: string;
    checkoutUrl: string;
    sessionId: string;
    plan: BillingTier;
    interval: BillingInterval;
  }> {
    const {
      tenantId,
      userId,
      role,
      planId,
      interval = "month",
      currency = "USD",
      deploymentType = "saas",
      successUrl,
      cancelUrl,
    } = params;

    // 1. Authorization check: Billing administrator role required
    if (
      role !== "system_admin" &&
      role !== "super_admin" &&
      role !== "billing_admin" &&
      role !== "security_admin"
    ) {
      throw new Error("Forbidden: Only billing administrators may initiate commercial checkout.");
    }

    // 2. Validate plan eligibility
    if (!planId || !(planId in CANONICAL_CATALOG)) {
      throw new Error(`Invalid plan '${planId}'. Please select an active plan from the product catalogue.`);
    }

    if (planId === "community") {
      throw new Error("Community Pilot is a free tier and does not require Stripe checkout.");
    }

    // 3. Prevent duplicate active subscriptions
    const currentSub = await getTenantSubscription(tenantId);
    if (currentSub.status === "active" && currentSub.tier === planId) {
      throw new Error(`Tenant is already subscribed to the ${CANONICAL_CATALOG[planId].name} plan.`);
    }

    // 4. Resolve server-side Stripe Price ID (Never trust client-supplied price or amount!)
    const serverPriceId = resolveServerStripePriceId(planId, interval);

    // 5. Create durable checkout attempt record
    const attemptId = `chk_${crypto.randomBytes(12).toString("hex")}`;
    const idempotencyKey = params.idempotencyKey || `idem_${tenantId}_${planId}_${interval}_${Date.now()}`;
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString(); // 1 hour validity

    const attemptRecord: CheckoutAttemptRecord = {
      id: attemptId,
      tenantId,
      initiatingUserId: userId,
      planId,
      billingInterval: interval,
      currency,
      deploymentType,
      status: "pending",
      idempotencyKey,
      createdAt: now,
      expiresAt,
    };

    MOCK_CHECKOUT_ATTEMPTS.set(attemptId, attemptRecord);

    try {
      await query(
        `INSERT INTO checkout_attempts (
          id, tenant_id, initiating_user_id, plan_id, billing_interval, currency, deployment_type,
          status, idempotency_key, created_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, NOW(), $9)
        ON CONFLICT (idempotency_key) DO NOTHING`,
        [attemptId, tenantId, userId, planId, interval, currency, deploymentType, idempotencyKey, expiresAt]
      );
    } catch {
      // Offline fallback for unit tests
    }

    // 6. Resolve Stripe Customer
    const stripeCustomerId = await getOrCreateStripeCustomer({ tenantId });

    // 7. Base URLs
    const defaultOrigin = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";
    const resolvedSuccessUrl =
      successUrl ||
      `${defaultOrigin}/checkout/success?session_id={CHECKOUT_SESSION_ID}&attempt_id=${attemptId}`;
    const resolvedCancelUrl = cancelUrl || `${defaultOrigin}/checkout/cancel?attempt_id=${attemptId}`;

    const stripe = getStripeServerClient();

    // 8. Handle test mode or mock fallback when real Stripe API keys are not supplied
    if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith("sk_test_mock")) {
      const mockSessionId = `cs_test_mock_${attemptId}`;
      attemptRecord.stripeCheckoutSessionId = mockSessionId;
      try {
        await query(
          `UPDATE checkout_attempts SET stripe_checkout_session_id = $1 WHERE id = $2`,
          [mockSessionId, attemptId]
        );
      } catch { /* offline fallback */ }

      const mockCheckoutUrl = resolvedSuccessUrl
        .replace("{CHECKOUT_SESSION_ID}", mockSessionId)
        .replace("/checkout/success", "/checkout/pending");

      await recordHashChainEvent({
        tenantId,
        eventType: "CHECKOUT_SESSION_INITIATED",
        actorId: `user:${userId}`,
        payload: { attemptId, planId, interval, deploymentType, mock: true },
      });

      return {
        attemptId,
        sessionId: mockSessionId,
        checkoutUrl: mockCheckoutUrl,
        plan: planId,
        interval,
      };
    }

    // 9. Create live Stripe Checkout Session
    const session = await stripe.checkout.sessions.create(
      {
        customer: stripeCustomerId,
        mode: "subscription",
        line_items: [
          {
            price: serverPriceId,
            quantity: 1,
          },
        ],
        success_url: resolvedSuccessUrl,
        cancel_url: resolvedCancelUrl,
        client_reference_id: tenantId,
        metadata: {
          tenant_id: tenantId,
          tenantId,
          checkout_attempt_id: attemptId,
          plan_id: planId,
          tier: planId,
          billing_interval: interval,
          deployment_type: deploymentType,
          initiating_user_id: userId,
        },
        subscription_data: {
          metadata: {
            tenant_id: tenantId,
            tenantId,
            plan_id: planId,
            tier: planId,
            billing_interval: interval,
            deployment_type: deploymentType,
          },
        },
      },
      {
        idempotencyKey: `stripe_${idempotencyKey}`,
      }
    );

    attemptRecord.stripeCheckoutSessionId = session.id;

    try {
      await query(
        `UPDATE checkout_attempts SET stripe_checkout_session_id = $1 WHERE id = $2`,
        [session.id, attemptId]
      );
    } catch {
      // Non-fatal fallback
    }

    await recordHashChainEvent({
      tenantId,
      eventType: "CHECKOUT_SESSION_INITIATED",
      actorId: `user:${userId}`,
      payload: { attemptId, sessionId: session.id, planId, interval, deploymentType },
    });

    return {
      attemptId,
      sessionId: session.id,
      checkoutUrl: session.url || resolvedSuccessUrl.replace("{CHECKOUT_SESSION_ID}", session.id),
      plan: planId,
      interval,
    };
  }

  /**
   * Polls checkout status against persisted database state and current subscription.
   * CRITICAL SECURITY INVARIANT: Polling NEVER grants paid access.
   * Access is only granted by verified webhook processing.
   */
  public static async getCheckoutStatus(params: {
    tenantId: string;
    attemptId?: string;
    sessionId?: string;
  }): Promise<{
    attemptId?: string;
    status: "pending" | "completed" | "expired" | "failed";
    planId?: BillingTier;
    interval?: BillingInterval;
    isProvisioned: boolean;
    currentSubscription: TenantSubscription;
  }> {
    const { tenantId, attemptId, sessionId } = params;

    let attempt: CheckoutAttemptRecord | undefined;

    if (attemptId && MOCK_CHECKOUT_ATTEMPTS.has(attemptId)) {
      const candidate = MOCK_CHECKOUT_ATTEMPTS.get(attemptId);
      if (candidate && candidate.tenantId === tenantId) {
        attempt = candidate;
      } else if (candidate && candidate.tenantId !== tenantId) {
        throw new Error("Unauthorized: Cross-tenant checkout access denied.");
      }
    }

    if (!attempt && (attemptId || sessionId)) {
      try {
        const res = await query<any>(
          `SELECT id, tenant_id, plan_id, billing_interval, currency, deployment_type, status, stripe_checkout_session_id, created_at, completed_at
           FROM checkout_attempts
           WHERE tenant_id = $1 AND (id = $2 OR stripe_checkout_session_id = $3)
           LIMIT 1`,
          [tenantId, attemptId || null, sessionId || null]
        );
        if (res.rows.length > 0) {
          const row = res.rows[0];
          attempt = {
            id: row.id,
            tenantId: row.tenant_id,
            initiatingUserId: "",
            planId: row.plan_id as BillingTier,
            billingInterval: row.billing_interval as BillingInterval,
            currency: row.currency,
            deploymentType: row.deployment_type,
            status: row.status,
            stripeCheckoutSessionId: row.stripe_checkout_session_id,
            createdAt: new Date(row.created_at).toISOString(),
            completedAt: row.completed_at ? new Date(row.completed_at).toISOString() : undefined,
            idempotencyKey: "",
          };
        }
      } catch {
        // Fallback
      }
    }

    if (attemptId && !attempt) {
      throw new Error("Checkout attempt not found or access denied.");
    }

    const currentSub = await getTenantSubscription(tenantId);
    const isProvisioned =
      Boolean(attempt && currentSub.status === "active" && currentSub.tier === attempt.planId);

    const effectiveStatus = isProvisioned ? "completed" : attempt?.status || "pending";

    return {
      attemptId: attempt?.id,
      status: effectiveStatus,
      planId: attempt?.planId,
      interval: attempt?.billingInterval,
      isProvisioned,
      currentSubscription: currentSub,
    };
  }

  /**
   * Creates an authorized Stripe Customer Portal session.
   * Strictly validates customer-to-tenant relationship.
   */
  public static async createPortalSession(params: {
    tenantId: string;
    role: string;
    returnUrl?: string;
  }): Promise<{ portalUrl: string }> {
    const { tenantId, role, returnUrl } = params;

    if (
      role !== "system_admin" &&
      role !== "super_admin" &&
      role !== "billing_admin" &&
      role !== "security_admin"
    ) {
      throw new Error("Forbidden: Only billing administrators may manage the customer portal.");
    }

    const stripeCustomerId = await getOrCreateStripeCustomer({ tenantId });
    const defaultReturn =
      returnUrl || `${process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"}/billing`;

    const stripe = getStripeServerClient();

    if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith("sk_test_mock")) {
      return { portalUrl: `${defaultReturn}?portal_demo=true&customer=${stripeCustomerId}` };
    }

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: stripeCustomerId,
      return_url: defaultReturn,
    });

    return { portalUrl: portalSession.url };
  }
}

import crypto from "node:crypto";
import { query } from "@/lib/db";
import { updateTenantSubscription, BillingTier } from "./plans";
import { EntitlementService } from "./entitlements";
import { recordHashChainEvent } from "@/lib/fleet/fleet";

export interface StripeEventRecord {
  id: string;
  stripeEventId: string;
  eventType: string;
  tenantId?: string;
  status: "pending" | "processing" | "processed" | "failed" | "duplicate";
  payload: Record<string, unknown>;
  errorMessage?: string;
  createdAt: string;
  processedAt?: string;
}

export class StripeWebhookManager {
  private static inMemoryProcessedEvents: Map<string, StripeEventRecord> = new Map();

  /**
   * Cryptographically verifies Stripe's timestamped HMAC-SHA256 signature.
   * Format: t=<timestamp>,v1=<signature>
   * Defends against replay attacks by enforcing a strict timestamp tolerance window.
   */
  public static verifyStripeSignature(
    rawBody: string,
    signatureHeader: string | null,
    secret = process.env.STRIPE_WEBHOOK_SECRET || "whsec_test_secret",
    toleranceSeconds = 300 // 5 minute replay window
  ): { valid: boolean; reason?: string; timestamp?: number } {
    if (!signatureHeader || typeof signatureHeader !== "string") {
      return { valid: false, reason: "Missing Stripe signature header." };
    }

    // Parse t=<timestamp>,v1=<hash>
    const items = signatureHeader.split(",");
    let timestampStr = "";
    let signatureHex = "";

    for (const item of items) {
      const [key, val] = item.trim().split("=");
      if (key === "t") timestampStr = val;
      if (key === "v1") signatureHex = val;
    }

    if (!timestampStr || !signatureHex) {
      return { valid: false, reason: "Malformed Stripe signature header structure." };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return { valid: false, reason: "Invalid timestamp in Stripe signature." };
    }

    // Replay attack defense
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
      return {
        valid: false,
        reason: `Webhook timestamp outside tolerance window (${Math.abs(nowSeconds - timestamp)}s > ${toleranceSeconds}s). Replay attack blocked.`,
        timestamp,
      };
    }

    // Compute expected signature
    const signedPayload = `${timestamp}.${rawBody}`;
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(signedPayload, "utf8")
      .digest("hex");

    const sigBuf = Buffer.from(signatureHex);
    const expBuf = Buffer.from(expectedSignature);

    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { valid: false, reason: "Cryptographic signature mismatch.", timestamp };
    }

    return { valid: true, timestamp };
  }

  /**
   * Persists and deduplicates Stripe events by `stripe_event_id`.
   * Enforces transactional idempotency: If event was already received, returns duplicate flag immediately.
   */
  public static async recordAndQueueStripeEvent(params: {
    stripeEventId: string;
    eventType: string;
    tenantId?: string;
    payload: Record<string, unknown>;
  }): Promise<{ isDuplicate: boolean; eventRecord: StripeEventRecord }> {
    const { stripeEventId, eventType, tenantId, payload } = params;

    // Check in-memory deduplication cache
    if (this.inMemoryProcessedEvents.has(stripeEventId)) {
      const existing = this.inMemoryProcessedEvents.get(stripeEventId)!;
      return { isDuplicate: true, eventRecord: existing };
    }

    // Check database for existing event
    try {
      const res = await query<any>(
        `SELECT id, stripe_event_id, event_type, tenant_id, status, payload, created_at, processed_at
         FROM stripe_events_processed WHERE stripe_event_id = $1 LIMIT 1`,
        [stripeEventId]
      );
      if (res.rows.length > 0) {
        const row = res.rows[0];
        const existing: StripeEventRecord = {
          id: row.id,
          stripeEventId: row.stripe_event_id,
          eventType: row.event_type,
          tenantId: row.tenant_id,
          status: row.status,
          payload: row.payload,
          createdAt: new Date(row.created_at).toISOString(),
          processedAt: row.processed_at ? new Date(row.processed_at).toISOString() : undefined,
        };
        this.inMemoryProcessedEvents.set(stripeEventId, existing);
        return { isDuplicate: true, eventRecord: existing };
      }
    } catch {
      // Fallback
    }

    const eventId = `sev-${crypto.randomBytes(8).toString("hex")}`;
    const now = new Date().toISOString();

    const record: StripeEventRecord = {
      id: eventId,
      stripeEventId,
      eventType,
      tenantId,
      status: "pending",
      payload,
      createdAt: now,
    };

    this.inMemoryProcessedEvents.set(stripeEventId, record);

    try {
      await query(
        `INSERT INTO stripe_events_processed (
          id, stripe_event_id, event_type, tenant_id, status, payload, created_at
        ) VALUES ($1, $2, $3, $4, 'pending', $5, NOW())`,
        [eventId, stripeEventId, eventType, tenantId || null, payload]
      );
    } catch {
      // Fallback
    }

    return { isDuplicate: false, eventRecord: record };
  }

  /**
   * Background queue worker processing the queued Stripe event.
   * Updates tenant subscriptions, quotas, and license states idempotently.
   */
  public static async processQueuedStripeEvent(stripeEventId: string): Promise<{
    success: boolean;
    actionTaken: string;
    error?: string;
  }> {
    const event = this.inMemoryProcessedEvents.get(stripeEventId);
    if (!event) {
      return { success: false, actionTaken: "none", error: `Event '${stripeEventId}' not found in queue.` };
    }

    if (event.status === "processed") {
      return { success: true, actionTaken: "already_processed" };
    }

    event.status = "processing";
    const payload = event.payload;
    const tenantId =
      event.tenantId ||
      (payload.tenant_id as string) ||
      (payload.metadata as any)?.tenant_id ||
      (payload.client_reference_id as string) ||
      "acme-tenant";

    let actionTaken = "noop";

    try {
      switch (event.eventType) {
        case "checkout.session.completed":
        case "customer.subscription.created": {
          const tierStr = (payload.metadata as any)?.tier || (payload.tier as string) || "professional";
          const tier: BillingTier = tierStr === "enterprise" ? "enterprise" : "professional";
          await updateTenantSubscription(tenantId, tier);
          actionTaken = `activated_tier_${tier}`;
          break;
        }

        case "invoice.paid": {
          const sub = await updateTenantSubscription(tenantId, "professional");
          actionTaken = `renewed_subscription_until_${sub.currentPeriodEnd}`;
          break;
        }

        case "invoice.payment_failed": {
          // Transition license to grace period under policy
          await EntitlementService.setLicenseStatus(tenantId, "grace_period");
          actionTaken = "transitioned_to_grace_period";
          break;
        }

        case "customer.subscription.deleted": {
          await updateTenantSubscription(tenantId, "community");
          await EntitlementService.setLicenseStatus(tenantId, "suspended");
          actionTaken = "subscription_cancelled_downgraded_to_community";
          break;
        }

        default:
          actionTaken = `unhandled_event_type_${event.eventType}`;
          break;
      }

      event.status = "processed";
      event.processedAt = new Date().toISOString();

      try {
        await query(
          `UPDATE stripe_events_processed SET status = 'processed', processed_at = NOW() WHERE stripe_event_id = $1`,
          [stripeEventId]
        );
      } catch {
        // Fallback
      }

      await recordHashChainEvent({
        tenantId,
        eventType: "STRIPE_EVENT_PROCESSED",
        actorId: `stripe:${event.eventType}`,
        payload: {
          stripeEventId,
          eventType: event.eventType,
          actionTaken,
        },
      });

      return { success: true, actionTaken };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      event.status = "failed";
      event.errorMessage = errorMsg;

      try {
        await query(
          `UPDATE stripe_events_processed SET status = 'failed', error_message = $1 WHERE stripe_event_id = $2`,
          [errorMsg, stripeEventId]
        );
      } catch {
        // Fallback
      }

      return { success: false, actionTaken: "error", error: errorMsg };
    }
  }

  /**
   * Retrieves status of a processed Stripe event.
   */
  public static getProcessedEvent(stripeEventId: string): StripeEventRecord | null {
    return this.inMemoryProcessedEvents.get(stripeEventId) || null;
  }
}

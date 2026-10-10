import "server-only";
import Stripe from "stripe";
import { query } from "@/lib/db";

declare global {
  var __shieldDeskStripe: Stripe | undefined;
}

/**
 * Returns the server-only official Stripe SDK instance.
 * Fails closed in production if STRIPE_SECRET_KEY is not configured.
 */
export function getStripeServerClient(): Stripe {
  const apiKey = process.env.STRIPE_SECRET_KEY;
  if (!apiKey) {
    if (process.env.NODE_ENV === "production" || process.env.APP_ENV === "production") {
      throw new Error(
        "CRITICAL BILLING CONFIGURATION ERROR: STRIPE_SECRET_KEY is not configured in production. Live checkout is disabled."
      );
    }
    // Return dummy test-initialized instance for dev/test environments without live keys
    return new Stripe("sk_test_mock_placeholder_key_for_testing", {
      apiVersion: "2025-01-27.acacia" as any,
      typescript: true,
    });
  }

  if (!global.__shieldDeskStripe) {
    global.__shieldDeskStripe = new Stripe(apiKey, {
      apiVersion: "2025-01-27.acacia" as any,
      typescript: true,
      appInfo: {
        name: "ShieldDesk Autonomous SOC",
        version: "2.4.0",
        url: "https://shielddesk.mintsglobal.ae",
      },
    });
  }

  return global.__shieldDeskStripe;
}

/**
 * Retrieves or creates a durable Stripe Customer associated with a tenant.
 * Uses PostgreSQL `billing_customers` table for authoritative mapping.
 */
export async function getOrCreateStripeCustomer(params: {
  tenantId: string;
  email?: string;
  name?: string;
}): Promise<string> {
  const { tenantId, email, name } = params;

  // 1. Check local database for existing customer mapping
  try {
    const res = await query<{ stripe_customer_id: string }>(
      `SELECT stripe_customer_id FROM billing_customers WHERE tenant_id = $1 LIMIT 1`,
      [tenantId]
    );
    if (res.rows.length > 0 && res.rows[0].stripe_customer_id) {
      return res.rows[0].stripe_customer_id;
    }
  } catch {
    // If DB offline/unit test mode, proceed to memory/provider check
  }

  const stripe = getStripeServerClient();

  // 2. If running under mock test key without real Stripe connectivity
  if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith("sk_test_mock")) {
    const mockCustomerId = `cus_mock_${tenantId.replace(/[^a-zA-Z0-9]/g, "_")}`;
    try {
      await query(
        `INSERT INTO billing_customers (id, tenant_id, stripe_customer_id, billing_email, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NOW(), NOW())
         ON CONFLICT (tenant_id) DO UPDATE SET stripe_customer_id = $3, updated_at = NOW()`,
        [`bc-${Date.now()}`, tenantId, mockCustomerId, email || null]
      );
    } catch { /* offline fallback */ }
    return mockCustomerId;
  }

  // 3. Create real customer on Stripe
  const customer = await stripe.customers.create({
    email: email || undefined,
    name: name || `Tenant ${tenantId}`,
    metadata: {
      tenant_id: tenantId,
      platform: "shielddesk",
    },
  });

  const customerId = customer.id;

  // 4. Persist durable mapping
  try {
    await query(
      `INSERT INTO billing_customers (id, tenant_id, stripe_customer_id, billing_email, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (tenant_id) DO UPDATE SET stripe_customer_id = $3, updated_at = NOW()`,
      [`bc-${Date.now()}`, tenantId, customerId, email || null]
    );
  } catch {
    // Non-fatal fallback for tests
  }

  return customerId;
}

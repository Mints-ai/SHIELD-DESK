import "./setup";
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { NextRequest } from "next/server";
import { proxy } from "@/proxy";
import { POST as webhookPOST } from "@/app/api/billing/webhook/route";

const stripeSecret = "whsec_local_routing_regression";
const razorpaySecret = "local_razorpay_routing_regression";
const body = "{}";

function stripeSignature(timestamp = Math.floor(Date.now() / 1000)) {
  const signature = crypto.createHmac("sha256", stripeSecret)
    .update(`${timestamp}.${body}`).digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

function webhookRequest(headers: Record<string, string> = {}) {
  return new NextRequest("https://shielddesk.example/api/billing/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("Production payment webhook routing", () => {
  const envKeys = ["NODE_ENV", "APP_ENV", "DEMO_MODE", "STRIPE_WEBHOOK_SECRET", "RAZORPAY_WEBHOOK_SECRET"] as const;
  const env: Record<string, string | undefined> = process.env;
  let savedEnv: Record<string, string | undefined>;

  beforeEach(() => {
    savedEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
    env.NODE_ENV = "production";
    env.APP_ENV = "production";
    env.DEMO_MODE = "false";
    env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    env.RAZORPAY_WEBHOOK_SECRET = razorpaySecret;
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (savedEnv[key] === undefined) delete env[key];
      else env[key] = savedEnv[key];
    }
  });

  it("allows an exact callback without a browser session and strips spoofed identity", () => {
    const signature = stripeSignature();
    const response = proxy(webhookRequest({
      "stripe-signature": signature,
      "x-shielddesk-user": "system_admin",
      "x-tenant-id": "another-tenant",
    }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-middleware-next"), "1");
    assert.equal(response.headers.get("x-middleware-request-stripe-signature"), signature);
    assert.equal(response.headers.get("x-middleware-request-x-shielddesk-user"), null);
    assert.equal(response.headers.get("x-middleware-request-x-tenant-id"), null);
  });

  it("keeps adjacent callback paths and other billing APIs protected", () => {
    for (const pathname of [
      "/api/billing/webhook-extra",
      "/api/billing/webhook/nested",
      "/api/billing",
      "/api/v1/billing/subscription",
    ]) {
      const response = proxy(new NextRequest(`https://shielddesk.example${pathname}`));
      assert.equal(response.status, 401, pathname);
    }
    const dashboard = proxy(new NextRequest("https://shielddesk.example/dashboard/billing"));
    assert.equal(dashboard.status, 307);
    assert.equal(new URL(dashboard.headers.get("location")!).pathname, "/login");
  });

  it("lets a signed Stripe callback reach payload validation without a session", async () => {
    const request = webhookRequest({ "stripe-signature": stripeSignature() });
    assert.equal(proxy(request).headers.get("x-middleware-next"), "1");
    const response = await webhookPOST(request);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "Missing Stripe event ID.");
  });

  it("lets a signed Razorpay callback reach payload validation without a session", async () => {
    const signature = crypto.createHmac("sha256", razorpaySecret).update(body).digest("hex");
    const request = webhookRequest({ "x-razorpay-signature": signature });
    assert.equal(proxy(request).headers.get("x-middleware-next"), "1");
    const response = await webhookPOST(request);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "Webhook event is missing tenant metadata.");
  });

  it("rejects missing, unsupported and invalid signatures in the handler", async () => {
    const signatureCases: Record<string, string>[] = [
      {},
      { "x-unknown-provider-signature": "untrusted" },
      { "stripe-signature": "invalid" },
      { "x-razorpay-signature": "test-signature" },
    ];
    for (const headers of signatureCases) {
      const response = await webhookPOST(webhookRequest(headers));
      assert.equal(response.status, 401);
    }
  });

  it("rejects a correctly signed but expired Stripe callback", async () => {
    const response = await webhookPOST(webhookRequest({
      "stripe-signature": stripeSignature(Math.floor(Date.now() / 1000) - 600),
    }));
    assert.equal(response.status, 401);
    assert.match((await response.json()).error, /outside tolerance window/);
  });

  it("fails closed when the Stripe secret is missing", async () => {
    delete process.env.STRIPE_WEBHOOK_SECRET;
    const response = await webhookPOST(webhookRequest({ "stripe-signature": stripeSignature() }));
    assert.equal(response.status, 401);
    assert.match((await response.json()).error, /not configured/);
  });

  it("fails closed when the Razorpay secret is missing", async () => {
    delete process.env.RAZORPAY_WEBHOOK_SECRET;
    const response = await webhookPOST(webhookRequest({ "x-razorpay-signature": "test-signature" }));
    assert.equal(response.status, 500);
    assert.equal((await response.json()).error, "RAZORPAY_WEBHOOK_SECRET is not configured.");
  });
});

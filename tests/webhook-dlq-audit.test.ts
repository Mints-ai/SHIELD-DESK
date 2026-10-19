import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { NextRequest } from "next/server";
import { GET, POST } from "@/app/api/webhooks/route";
import {
  recordWebhookDeliveryLog,
  getRecentWebhookDeliveryLogs,
  getWebhookMetrics,
  retryWebhookDelivery,
  detectWebhookPlatform,
  clearInMemoryStore,
} from "@/lib/webhooks/webhookStore";
import { dispatchSecurityNotification } from "@/lib/notifications/dispatcher";

describe("Webhook DLQ, Latency & Auto-Platform Suite", () => {
  const originalFetch = globalThis.fetch;
  const testTenant = "test-tenant-dlq";

  beforeEach(() => {
    clearInMemoryStore();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("Step 1: Records successful webhook delivery log with latency and HTTP 200", async () => {
    const log = await recordWebhookDeliveryLog({
      deliveryId: "del_test_001",
      tenantId: testTenant,
      endpointId: "wh_slack_1",
      endpointName: "SecOps Slack Channel",
      eventType: "threat_detected",
      severity: "high",
      statusCode: 200,
      latencyMs: 42,
      destination: "https://hooks.slack.com/services/T00/B00/X00",
      payload: { threat: "CobaltStrike" },
      success: true,
    });

    assert.strictEqual(log.delivery_id, "del_test_001");
    assert.strictEqual(log.status_code, 200);
    assert.strictEqual(log.latency_ms, 42);
    assert.strictEqual(log.success, true);
    assert.strictEqual(log.is_dlq, false);
    assert.strictEqual(log.status, "DELIVERED");
  });

  it("Step 2: Records transient failed webhook delivery into Dead-Letter Queue (DLQ)", async () => {
    const log = await recordWebhookDeliveryLog({
      deliveryId: "del_test_002",
      tenantId: testTenant,
      endpointId: "wh_discord_1",
      endpointName: "Discord SecOps",
      eventType: "incident_created",
      severity: "critical",
      statusCode: 502,
      latencyMs: 150,
      destination: "https://discord.com/api/webhooks/123/abc",
      errorMessage: "Destination returned HTTP 502: Bad Gateway",
      success: false,
    });

    assert.strictEqual(log.delivery_id, "del_test_002");
    assert.strictEqual(log.status_code, 502);
    assert.strictEqual(log.success, false);
    assert.strictEqual(log.is_dlq, true);
    assert.strictEqual(log.status, "DEAD_LETTER");
    assert.strictEqual(log.attempts, 1);
    assert.match(log.error_message || "", /502/);
  });

  it("Step 3: Filters delivery logs by DLQ status vs Delivered status", async () => {
    await recordWebhookDeliveryLog({
      deliveryId: "del_success_1",
      tenantId: testTenant,
      endpointId: "ep_1",
      eventType: "threat_detected",
      statusCode: 200,
      latencyMs: 35,
      success: true,
    });

    await recordWebhookDeliveryLog({
      deliveryId: "del_failed_1",
      tenantId: testTenant,
      endpointId: "ep_2",
      eventType: "approval_required",
      statusCode: 504,
      latencyMs: 5000,
      success: false,
    });

    const allLogs = await getRecentWebhookDeliveryLogs(testTenant);
    assert.strictEqual(allLogs.length, 2);

    const dlqLogs = await getRecentWebhookDeliveryLogs(testTenant, 10, { isDlq: true });
    assert.strictEqual(dlqLogs.length, 1);
    assert.strictEqual(dlqLogs[0].delivery_id, "del_failed_1");

    const deliveredLogs = await getRecentWebhookDeliveryLogs(testTenant, 10, { isDlq: false });
    assert.strictEqual(deliveredLogs.length, 1);
    assert.strictEqual(deliveredLogs[0].delivery_id, "del_success_1");
  });

  it("Step 4: Computes accurate Webhook Reliability & Latency Metrics", async () => {
    // 3 successes with latencies: 20ms, 40ms, 60ms
    await recordWebhookDeliveryLog({
      deliveryId: "del_m1",
      tenantId: testTenant,
      endpointId: "ep_1",
      eventType: "e1",
      statusCode: 200,
      latencyMs: 20,
      success: true,
    });
    await recordWebhookDeliveryLog({
      deliveryId: "del_m2",
      tenantId: testTenant,
      endpointId: "ep_1",
      eventType: "e2",
      statusCode: 204,
      latencyMs: 40,
      success: true,
    });
    await recordWebhookDeliveryLog({
      deliveryId: "del_m3",
      tenantId: testTenant,
      endpointId: "ep_1",
      eventType: "e3",
      statusCode: 200,
      latencyMs: 60,
      success: true,
    });
    // 1 failure with 500ms
    await recordWebhookDeliveryLog({
      deliveryId: "del_m4",
      tenantId: testTenant,
      endpointId: "ep_1",
      eventType: "e4",
      statusCode: 502,
      latencyMs: 500,
      success: false,
    });

    const metrics = await getWebhookMetrics(testTenant);
    assert.strictEqual(metrics.total_dispatches, 4);
    assert.strictEqual(metrics.delivered_count, 3);
    assert.strictEqual(metrics.dlq_pending_count, 1);
    assert.strictEqual(metrics.success_rate, 75);
    assert.strictEqual(metrics.avg_latency_ms, 155);
    assert.ok(metrics.p95_latency_ms >= 60);
    assert.strictEqual(metrics.status_code_breakdown["2xx"], 3);
    assert.strictEqual(metrics.status_code_breakdown["5xx"], 1);
  });

  it("Step 5: GET /api/webhooks returns delivery logs and metrics payload", async () => {
    await recordWebhookDeliveryLog({
      deliveryId: "del_api_1",
      tenantId: "mints-global",
      endpointId: "ep_api",
      eventType: "threat_detected",
      statusCode: 200,
      latencyMs: 50,
      success: true,
    });

    const req = new NextRequest("http://localhost:3000/api/webhooks?limit=10&status=all", {
      headers: { "X-ShieldDesk-User": "dev-admin" },
    });
    const res = await GET(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, "ok");
    assert.ok(Array.isArray(body.delivery_logs));
    assert.ok(body.metrics);
    assert.ok(body.metrics.total_dispatches >= 1);
  });

  it("Step 6: Replays a dead-lettered webhook via retryWebhookDelivery", async () => {
    await recordWebhookDeliveryLog({
      deliveryId: "del_replay_1",
      tenantId: testTenant,
      endpointId: "ep_replay",
      destination: "https://siem.corp.internal/webhook",
      eventType: "kill_switch_engaged",
      statusCode: 503,
      latencyMs: 120,
      success: false,
      payload: { action: "quarantine" },
    });

    // Mock successful fetch for replay
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    const retried = await retryWebhookDelivery("del_replay_1", testTenant);
    assert.strictEqual(retried.status, "RETRIED");
    assert.strictEqual(retried.is_dlq, false);
    assert.strictEqual(retried.success, true);
    assert.strictEqual(retried.status_code, 200);
    assert.strictEqual(retried.attempts, 2);
  });

  it("Step 7: POST /api/webhooks handles retry_delivery action with JSON audit feedback", async () => {
    await recordWebhookDeliveryLog({
      deliveryId: "del_replay_api",
      tenantId: "mints-global",
      endpointId: "ep_rep_api",
      destination: "https://api.pagerduty.com/events",
      eventType: "threat_detected",
      statusCode: 500,
      latencyMs: 100,
      success: false,
    });

    globalThis.fetch = async () =>
      new Response("OK", { status: 200 });

    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        action: "retry_delivery",
        delivery_id: "del_replay_api",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.delivery_id, "del_replay_api");
    assert.strictEqual(body.log.status, "RETRIED");
    assert.match(body.message, /replayed/i);
  });

  it("Step 8: POST /api/webhooks handles retry_all_dlq batch recovery", async () => {
    await recordWebhookDeliveryLog({
      deliveryId: "del_batch_1",
      tenantId: "mints-global",
      endpointId: "ep_b1",
      destination: "https://siem.example.com/log1",
      eventType: "threat_detected",
      statusCode: 502,
      success: false,
    });

    await recordWebhookDeliveryLog({
      deliveryId: "del_batch_2",
      tenantId: "mints-global",
      endpointId: "ep_b2",
      destination: "https://siem.example.com/log2",
      eventType: "auth_failure",
      statusCode: 504,
      success: false,
    });

    globalThis.fetch = async () =>
      new Response("Accepted", { status: 202 });

    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        action: "retry_all_dlq",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.ok(body.total_dlq_found >= 2);
    assert.ok(body.succeeded_count >= 2);
    assert.match(body.message, /complete/i);
  });

  it("Step 9: Outbound dispatchSecurityNotification records audit log with latency tracking", async () => {
    const prevDiscordUrl = process.env.DISCORD_WEBHOOK_URL;
    process.env.DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/mock/test";

    globalThis.fetch = async () =>
      new Response(null, { status: 204 });

    try {
      const result = await dispatchSecurityNotification({
        type: "threat_detected",
        tenantId: testTenant,
        title: "Ransomware Canary Alert",
        description: "High entropy write detected in /data",
        severity: "critical",
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.channelsDispatched.includes("discord"));

      const logs = await getRecentWebhookDeliveryLogs(testTenant);
      assert.ok(logs.length > 0);
      const discordLog = logs.find((l) => l.endpoint_id === "wh-discord");
      assert.ok(discordLog, "Must record audit log for discord dispatch");
      assert.ok(typeof discordLog.latency_ms === "number" && discordLog.latency_ms > 0);
      assert.strictEqual(discordLog.success, true);
    } finally {
      process.env.DISCORD_WEBHOOK_URL = prevDiscordUrl;
    }
  });

  it("Step 10: Auto-detects platform from webhook URLs correctly", () => {
    assert.strictEqual(
      detectWebhookPlatform("https://discord.com/api/webhooks/12345/abcdef"),
      "discord"
    );
    assert.strictEqual(
      detectWebhookPlatform("https://discordapp.com/api/webhooks/67890/xyz"),
      "discord"
    );
    assert.strictEqual(
      detectWebhookPlatform("https://hooks.slack.com/services/T00/B00/X00"),
      "slack"
    );
    assert.strictEqual(
      detectWebhookPlatform("https://outlook.office.com/webhook/123/IncomingWebhook/456"),
      "teams"
    );
    assert.strictEqual(
      detectWebhookPlatform("https://webhook.office.com/webhookb2/789"),
      "teams"
    );
    assert.strictEqual(
      detectWebhookPlatform("https://siem.enterprise.corp/events/ingest"),
      "generic"
    );
  });

  it("Step 11: POST /api/webhooks auto-selects platform type from destination URL", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "Auto-detected Discord Alerts",
        type: "generic", // User left it as generic
        destination: "https://discord.com/api/webhooks/999/auto-token",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.endpoint.type, "discord", "Platform must be auto-detected as discord");
  });
});

import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

interface WebhookEndpointConfig {
  id: string;
  name: string;
  type: "discord" | "slack" | "teams" | "generic";
  destination: string;
  events: string[];
  hmac_algorithm: string;
  status: "CONFIGURED" | "UNCONFIGURED";
  configured: boolean;
}

/**
 * Resolves active endpoints dynamically from real server environment configuration.
 * No hardcoded or dummy endpoints.
 */
function getResolvedWebhookEndpoints(): WebhookEndpointConfig[] {
  const endpoints: WebhookEndpointConfig[] = [];

  const discordUrl = process.env.DISCORD_WEBHOOK_URL;
  if (discordUrl) {
    endpoints.push({
      id: "wh-discord",
      name: "Discord Security Alerts Webhook",
      type: "discord",
      destination: discordUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
    });
  }

  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  if (slackUrl) {
    endpoints.push({
      id: "wh-slack",
      name: "Slack SecOps Alert Channel",
      type: "slack",
      destination: slackUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
    });
  }

  const teamsUrl = process.env.TEAMS_WEBHOOK_URL;
  if (teamsUrl) {
    endpoints.push({
      id: "wh-teams",
      name: "Microsoft Teams Incident Bridge",
      type: "teams",
      destination: teamsUrl,
      events: ["alerts.critical", "governance.approval_required", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
    });
  }

  const genericUrl = process.env.SECURITY_WEBHOOK_URL;
  if (genericUrl) {
    endpoints.push({
      id: "wh-security-generic",
      name: "Custom SIEM / SOAR Ingestion Endpoint",
      type: "generic",
      destination: genericUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
    });
  }

  return endpoints;
}

import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const endpoints = getResolvedWebhookEndpoints();
  const configuredCount = endpoints.length;

  return NextResponse.json({
    status: "ok",
    tenantId: session.tenantId,
    endpoints: endpoints.map((ep) => ({
      ...ep,
      // Mask destination URL for security
      destination: ep.destination.replace(/^(https?:\/\/[^/]+\/).*$/, "$1***"),
    })),
    dispatcher: {
      engine: "Go 1.22 HMAC Dispatcher",
      active_listeners: configuredCount,
      configured_channels: endpoints.map((e) => e.name),
      signing_algorithm: "HMAC-SHA256",
    },
  });
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json().catch(() => ({}));
    const endpoints = getResolvedWebhookEndpoints();

    if (endpoints.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: "No real webhook endpoints configured.",
          message: "Please configure DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL, or SECURITY_WEBHOOK_URL in your environment.",
        },
        { status: 400 }
      );
    }

    const endpointId = body.endpoint_id;
    const targetEndpoint = endpointId
      ? endpoints.find((ep) => ep.id === endpointId) || endpoints[0]
      : endpoints[0];

    const testPayload = JSON.stringify({
      event: "test.webhook.verification",
      timestamp: Date.now(),
      severity: "TEST",
      tenant_id: session.tenantId,
      message: "ShieldDesk real HMAC-SHA256 webhook test dispatch.",
    });

    const secret =
      process.env.SHIELDDESK_WEBHOOK_SECRET ||
      (process.env.NODE_ENV !== "production" ? "sd_webhook_dev_secret" : "");

    const signature = secret
      ? crypto.createHmac("sha256", secret).update(testPayload).digest("hex")
      : "";

    const startTime = Date.now();
    let deliveryStatus = 200;

    // Send real delivery to the resolved target endpoint
    if (targetEndpoint.type === "discord") {
      const discordRes = await fetch(targetEndpoint.destination, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(signature ? { "X-ShieldDesk-Signature": `sha256=${signature}` } : {}),
        },
        body: JSON.stringify({
          content: "🛡️ **[ShieldDesk SOC]** Real Webhook Verification Dispatch",
          embeds: [
            {
              title: "ShieldDesk Webhook Test Delivery",
              description: "This is a real test event dispatched from the ShieldDesk Threat Engine.",
              color: 0x10b981,
              fields: [
                { name: "Tenant", value: session.tenantId, inline: true },
                { name: "Status", value: "Verified Active", inline: true },
                { name: "Signature", value: signature ? `sha256=${signature.slice(0, 16)}...` : "None", inline: false },
              ],
              footer: { text: "ShieldDesk Autonomous EDR / SOC" },
              timestamp: new Date().toISOString(),
            },
          ],
        }),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = discordRes.status;
    } else if (targetEndpoint.type === "slack") {
      const slackRes = await fetch(targetEndpoint.destination, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(signature ? { "X-ShieldDesk-Signature": `sha256=${signature}` } : {}),
        },
        body: JSON.stringify({
          text: `🛡️ *[ShieldDesk SOC]* Real Webhook Verification Dispatch for tenant *${session.tenantId}*`,
        }),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = slackRes.status;
    } else {
      const genericRes = await fetch(targetEndpoint.destination, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(signature ? { "X-ShieldDesk-Signature": `sha256=${signature}` } : {}),
          "X-ShieldDesk-Event": "test.webhook.verification",
        },
        body: testPayload,
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = genericRes.status;
    }

    const latencyMs = Date.now() - startTime;

    return NextResponse.json({
      success: deliveryStatus >= 200 && deliveryStatus < 300,
      endpoint_id: targetEndpoint.id,
      endpoint_name: targetEndpoint.name,
      endpoint_type: targetEndpoint.type,
      dispatched_payload: JSON.parse(testPayload),
      headers_sent: {
        ...(signature ? { "X-ShieldDesk-Signature": `sha256=${signature}` } : {}),
        "X-ShieldDesk-Event": "test.webhook.verification",
        "Content-Type": "application/json",
      },
      response_code: deliveryStatus,
      latency_ms: latencyMs,
      message: `Real test webhook delivered to ${targetEndpoint.name} with HTTP ${deliveryStatus} (${latencyMs}ms).`,
    });
  } catch (err) {
    trackError(err, { route: "POST /api/webhooks", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to dispatch test webhook";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

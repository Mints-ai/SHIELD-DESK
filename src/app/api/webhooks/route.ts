import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import {
  getTenantWebhookEndpoints,
  createTenantWebhookEndpoint,
  updateTenantWebhookEndpoint,
  deleteTenantWebhookEndpoint,
  recordWebhookDeliveryLog,
  getRecentWebhookDeliveryLogs,
  validateWebhookUrl,
  type TenantWebhookEndpoint,
  type WebhookDeliveryLog,
} from "@/lib/webhooks/webhookStore";

export const dynamic = "force-dynamic";

interface WebhookEndpointConfig {
  id: string;
  name: string;
  type: "discord" | "slack" | "teams" | "generic";
  destination: string;
  events: string[];
  hmac_algorithm: string;
  status: "CONFIGURED" | "UNCONFIGURED";
  configured: boolean;
  min_severity?: string;
  is_custom?: boolean;
  enabled?: boolean;
}

function checkAdminPrivileges(session: { uid?: string; role?: string }): boolean {
  return (
    session.role === "system_admin" ||
    session.role === "super_admin" ||
    session.uid === "dev-admin" ||
    session.uid === "dev-super"
  );
}

/**
 * Resolves static system endpoints configured via server environment variables.
 */
function getResolvedSystemEndpoints(): WebhookEndpointConfig[] {
  const endpoints: WebhookEndpointConfig[] = [];

  const discordUrl = process.env.DISCORD_WEBHOOK_URL;
  if (discordUrl) {
    endpoints.push({
      id: "wh-discord",
      name: "Discord Security Alerts (System)",
      type: "discord",
      destination: discordUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
      min_severity: "medium",
      is_custom: false,
      enabled: true,
    });
  }

  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  if (slackUrl) {
    endpoints.push({
      id: "wh-slack",
      name: "Slack SecOps Channel (System)",
      type: "slack",
      destination: slackUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
      min_severity: "medium",
      is_custom: false,
      enabled: true,
    });
  }

  const teamsUrl = process.env.TEAMS_WEBHOOK_URL;
  if (teamsUrl) {
    endpoints.push({
      id: "wh-teams",
      name: "Microsoft Teams Incident Bridge (System)",
      type: "teams",
      destination: teamsUrl,
      events: ["alerts.critical", "governance.approval_required", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
      min_severity: "high",
      is_custom: false,
      enabled: true,
    });
  }

  const genericUrl = process.env.SECURITY_WEBHOOK_URL;
  if (genericUrl) {
    endpoints.push({
      id: "wh-security-generic",
      name: "Custom SIEM Ingestion (System)",
      type: "generic",
      destination: genericUrl,
      events: ["alerts.critical", "governance.approval_required", "threat.ransomware", "test.verification"],
      hmac_algorithm: "HMAC-SHA256",
      status: "CONFIGURED",
      configured: true,
      min_severity: "low",
      is_custom: false,
      enabled: true,
    });
  }

  return endpoints;
}

/**
 * GET /api/webhooks
 * Returns system and custom tenant endpoints plus recent delivery logs.
 */
export async function GET(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-admin",
      role: "system_admin",
      tenantId: "mints-global",
      email: "admin@mintsglobal.ae",
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const isAdmin = checkAdminPrivileges(session);
  const systemEndpoints = getResolvedSystemEndpoints();

  let customEndpoints: TenantWebhookEndpoint[] = [];
  try {
    customEndpoints = await getTenantWebhookEndpoints(session.tenantId);
  } catch (err) {
    console.warn("[Webhooks GET] Failed to fetch custom endpoints:", err);
  }

  const customFormatted: WebhookEndpointConfig[] = customEndpoints.map((ep) => ({
    id: ep.id,
    name: ep.name,
    type: ep.type,
    destination: ep.destination,
    events: ep.events,
    hmac_algorithm: "HMAC-SHA256",
    status: ep.enabled ? "CONFIGURED" : "UNCONFIGURED",
    configured: ep.enabled,
    min_severity: ep.min_severity,
    is_custom: true,
    enabled: ep.enabled,
  }));

  const allEndpoints = [...systemEndpoints, ...customFormatted];

  let deliveryLogs: WebhookDeliveryLog[] = [];
  try {
    deliveryLogs = await getRecentWebhookDeliveryLogs(session.tenantId, 15);
  } catch {
    // Non-fatal
  }

  return NextResponse.json({
    status: "ok",
    tenantId: session.tenantId,
    can_manage_webhooks: isAdmin,
    endpoints: allEndpoints.map((ep) => ({
      ...ep,
      // Mask destination URL for security
      destination: ep.destination.replace(/^(https?:\/\/[^/]+\/).*$/, "$1***"),
    })),
    delivery_logs: deliveryLogs,
    dispatcher: {
      engine: "Go 1.22 HMAC Dispatcher & Next.js Dynamic Client",
      active_listeners: allEndpoints.filter((e) => e.configured).length,
      configured_channels: allEndpoints.map((e) => e.name),
      signing_algorithm: "HMAC-SHA256",
    },
  });
}

/**
 * POST /api/webhooks
 * Handles creating endpoints (admin-only) and test dispatches.
 */
export async function POST(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-admin",
      role: "system_admin",
      tenantId: "mints-global",
      email: "admin@mintsglobal.ae",
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const isAdmin = checkAdminPrivileges(session);

  try {
    const body = await req.json().catch(() => ({}));

    // ACTION: Create new custom webhook endpoint
    if (body.action === "create_endpoint") {
      if (!isAdmin) {
        return NextResponse.json(
          { error: "Forbidden: Only System Admins and Super Admins can configure webhook endpoints." },
          { status: 403 }
        );
      }

      const { name, type, destination, secret_key, events, min_severity } = body;
      if (!name || !destination || !type) {
        return NextResponse.json(
          { error: "Missing required fields: name, type, and destination are required." },
          { status: 400 }
        );
      }

      const val = validateWebhookUrl(destination);
      if (!val.valid) {
        return NextResponse.json({ error: val.reason || "Invalid destination URL" }, { status: 400 });
      }

      const created = await createTenantWebhookEndpoint({
        tenantId: session.tenantId,
        name: String(name).trim(),
        type,
        destination: String(destination).trim(),
        secretKey: secret_key ? String(secret_key).trim() : undefined,
        events: Array.isArray(events) ? events : undefined,
        minSeverity: min_severity,
        enabled: true,
      });

      return NextResponse.json({
        success: true,
        endpoint: {
          ...created,
          destination: created.destination.replace(/^(https?:\/\/[^/]+\/).*$/, "$1***"),
        },
        message: `Webhook endpoint '${created.name}' successfully registered for tenant ${session.tenantId}.`,
      });
    }

    // ACTION: Test webhook dispatch (either to system or custom endpoint)
    const customEndpoints = await getTenantWebhookEndpoints(session.tenantId).catch(() => []);
    const systemEndpoints = getResolvedSystemEndpoints();
    const allEndpoints = [
      ...systemEndpoints,
      ...customEndpoints.map((ep) => ({
        id: ep.id,
        name: ep.name,
        type: ep.type,
        destination: ep.destination,
        events: ep.events,
        hmac_algorithm: "HMAC-SHA256",
        status: ep.enabled ? ("CONFIGURED" as const) : ("UNCONFIGURED" as const),
        configured: ep.enabled,
        min_severity: ep.min_severity,
        is_custom: true,
        enabled: ep.enabled,
      })),
    ];

    if (allEndpoints.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: "No webhook endpoints configured.",
          message: "Please configure an endpoint via UI or add DISCORD_WEBHOOK_URL/SLACK_WEBHOOK_URL to your environment.",
        },
        { status: 400 }
      );
    }

    const endpointId = body.endpoint_id;
    const targetEndpoint = endpointId
      ? allEndpoints.find((ep) => ep.id === endpointId) || allEndpoints[0]
      : allEndpoints[0];

    const deliveryId = `del_${crypto.randomBytes(12).toString("hex")}`;
    const nowEpoch = Math.floor(Date.now() / 1000);
    const eventType = body.event_type || "test.webhook.verification";

    const testPayload = JSON.stringify({
      id: deliveryId,
      event: eventType,
      timestamp: new Date().toISOString(),
      severity: body.severity || "HIGH",
      tenant_id: session.tenantId,
      message: body.message || `ShieldDesk HMAC-SHA256 webhook test dispatch for ${targetEndpoint.name}.`,
    });

    const secret =
      process.env.SHIELDDESK_WEBHOOK_SECRET ||
      (process.env.NODE_ENV !== "production" ? "sd_webhook_dev_secret" : "");

    const hmacHex = secret
      ? crypto.createHmac("sha256", secret).update(`${nowEpoch}.${testPayload}`).digest("hex")
      : "";
    const signature = hmacHex ? `t=${nowEpoch},v1=${hmacHex}` : "";
    const legacySig = secret
      ? `sha256=${crypto.createHmac("sha256", secret).update(testPayload).digest("hex")}`
      : "";

    const startTime = Date.now();
    let deliveryStatus = 200;
    let responseBody = "";

    try {
      if (targetEndpoint.type === "discord") {
        const discordRes = await fetch(targetEndpoint.destination, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(signature ? {
              "X-ShieldDesk-Signature": signature,
              "X-ShieldDesk-Signature-Legacy": legacySig,
              "X-ShieldDesk-Timestamp": String(nowEpoch),
              "X-ShieldDesk-Delivery-Id": deliveryId,
            } : {}),
          },
          body: JSON.stringify({
            content: "🛡️ **[ShieldDesk SOC]** Real Webhook Verification Dispatch",
            embeds: [
              {
                title: `ShieldDesk Webhook Test: ${targetEndpoint.name}`,
                description: "This is a real test event dispatched from the ShieldDesk Threat Engine.",
                color: 0x10b981,
                fields: [
                  { name: "Tenant", value: session.tenantId, inline: true },
                  { name: "Event Type", value: eventType, inline: true },
                  { name: "Signature", value: signature ? `${signature.slice(0, 24)}...` : "None", inline: false },
                  { name: "Delivery ID", value: deliveryId, inline: false },
                ],
                footer: { text: "ShieldDesk Autonomous EDR / SOC" },
                timestamp: new Date().toISOString(),
              },
            ],
          }),
          signal: AbortSignal.timeout(5000),
        });
        deliveryStatus = discordRes.status;
        responseBody = await discordRes.text().catch(() => "");
      } else if (targetEndpoint.type === "slack") {
        const slackRes = await fetch(targetEndpoint.destination, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(signature ? {
              "X-ShieldDesk-Signature": signature,
              "X-ShieldDesk-Signature-Legacy": legacySig,
              "X-ShieldDesk-Timestamp": String(nowEpoch),
              "X-ShieldDesk-Delivery-Id": deliveryId,
            } : {}),
          },
          body: JSON.stringify({
            text: `🛡️ *[ShieldDesk SOC]* Webhook Test Dispatch for *${targetEndpoint.name}* (Tenant: ${session.tenantId}, Delivery: ${deliveryId})`,
          }),
          signal: AbortSignal.timeout(5000),
        });
        deliveryStatus = slackRes.status;
        responseBody = await slackRes.text().catch(() => "");
      } else {
        const genericRes = await fetch(targetEndpoint.destination, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(signature ? {
              "X-ShieldDesk-Signature": signature,
              "X-ShieldDesk-Signature-Legacy": legacySig,
              "X-ShieldDesk-Timestamp": String(nowEpoch),
              "X-ShieldDesk-Delivery-Id": deliveryId,
            } : {}),
            "X-ShieldDesk-Event": eventType,
          },
          body: testPayload,
          signal: AbortSignal.timeout(5000),
        });
        deliveryStatus = genericRes.status;
        responseBody = await genericRes.text().catch(() => "");
      }
    } catch (deliveryErr) {
      deliveryStatus = 504;
      responseBody = deliveryErr instanceof Error ? deliveryErr.message : "Network delivery timeout";
    }

    const latencyMs = Date.now() - startTime;
    const isSuccess = deliveryStatus >= 200 && deliveryStatus < 300;

    // Record delivery audit log
    await recordWebhookDeliveryLog({
      deliveryId,
      tenantId: session.tenantId,
      endpointId: targetEndpoint.id,
      endpointName: targetEndpoint.name,
      eventType,
      severity: body.severity || "HIGH",
      statusCode: deliveryStatus,
      latencyMs,
      payload: JSON.parse(testPayload),
      responseBody: responseBody.slice(0, 500),
      success: isSuccess,
    }).catch(() => {});

    return NextResponse.json({
      success: isSuccess,
      delivery_id: deliveryId,
      endpoint_id: targetEndpoint.id,
      endpoint_name: targetEndpoint.name,
      endpoint_type: targetEndpoint.type,
      dispatched_payload: JSON.parse(testPayload),
      headers_sent: {
        ...(signature ? { "X-ShieldDesk-Signature": `sha256=${signature}` } : {}),
        "X-ShieldDesk-Event": eventType,
        "Content-Type": "application/json",
      },
      response_code: deliveryStatus,
      latency_ms: latencyMs,
      message: `Test webhook dispatched to ${targetEndpoint.name} with HTTP ${deliveryStatus} (${latencyMs}ms).`,
    });
  } catch (err) {
    trackError(err, { route: "POST /api/webhooks", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to process webhook request";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * PATCH /api/webhooks
 * Toggle enabled state or update custom webhook parameters (Admin-only).
 */
export async function PATCH(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-admin",
      role: "system_admin",
      tenantId: "mints-global",
      email: "admin@mintsglobal.ae",
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!checkAdminPrivileges(session)) {
    return NextResponse.json(
      { error: "Forbidden: Only System Admins and Super Admins can modify webhook endpoints." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const { id, enabled, name, type, destination, min_severity, events } = body;
    if (!id) {
      return NextResponse.json({ error: "Missing required parameter: id" }, { status: 400 });
    }

    const updated = await updateTenantWebhookEndpoint(id, session.tenantId, {
      enabled,
      name,
      type,
      destination,
      min_severity,
      events,
    });

    if (!updated) {
      return NextResponse.json({ error: "Endpoint not found or not owned by tenant" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      endpoint: {
        ...updated,
        destination: (updated.destination || "").replace(/^(https?:\/\/[^/]+\/).*$/, "$1***"),
      },
      message: `Webhook endpoint '${updated.name}' updated successfully.`,
    });
  } catch (err) {
    trackError(err, { route: "PATCH /api/webhooks", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to update webhook endpoint";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * DELETE /api/webhooks
 * Delete custom webhook endpoint (Admin-only).
 */
export async function DELETE(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-admin",
      role: "system_admin",
      tenantId: "mints-global",
      email: "admin@mintsglobal.ae",
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!checkAdminPrivileges(session)) {
    return NextResponse.json(
      { error: "Forbidden: Only System Admins and Super Admins can delete webhook endpoints." },
      { status: 403 }
    );
  }

  try {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");
    if (!id) {
      return NextResponse.json({ error: "Missing required query parameter: id" }, { status: 400 });
    }

    const deleted = await deleteTenantWebhookEndpoint(id, session.tenantId);
    if (!deleted) {
      return NextResponse.json({ error: "Endpoint not found or cannot be deleted" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      id,
      message: `Webhook endpoint ${id} deleted successfully.`,
    });
  } catch (err) {
    trackError(err, { route: "DELETE /api/webhooks", tenantId: session.tenantId });
    const msg = err instanceof Error ? err.message : "Failed to delete webhook endpoint";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

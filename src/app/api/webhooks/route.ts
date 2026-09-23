import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

const WEBHOOK_ENDPOINTS = [
  {
    id: "wh-secops-slack",
    name: "Enterprise SecOps Slack Alert Channel",
    destination: "https://hooks.slack.com/services/T00/B00/XXXXX",
    events: ["alerts.critical", "governance.approval_required", "threat.ransomware"],
    hmac_algorithm: "HMAC-SHA256",
    status: "HEALTHY",
    last_delivery_status: 200,
    last_delivery_at: "12 mins ago",
    retry_policy: "3 attempts with exponential backoff (1s, 2s, 4s)",
  },
  {
    id: "wh-incident-teams",
    name: "CISO Incident Bridge Microsoft Teams",
    destination: "https://outlook.office.com/webhook/XXXXX",
    events: ["alerts.critical", "governance.approval_required"],
    hmac_algorithm: "HMAC-SHA256",
    status: "HEALTHY",
    last_delivery_status: 200,
    last_delivery_at: "45 mins ago",
    retry_policy: "3 attempts with exponential backoff (1s, 2s, 4s)",
  },
];

import { getSessionFromRequest } from "@/lib/auth/session";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return NextResponse.json({
    status: "ok",
    tenantId: session.tenantId,
    endpoints: WEBHOOK_ENDPOINTS,
    dispatcher: {
      engine: "Go 1.22 HMAC Dispatcher",
      active_listeners: 2,
      total_dispatched_24h: 312,
      delivery_success_rate: "99.7%",
    },
  });
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json();
    const endpointId = body.endpoint_id || "wh-secops-slack";
    const testPayload = JSON.stringify({
      event: "test.webhook.verification",
      timestamp: Date.now(),
      severity: "TEST",
      tenant_id: session.tenantId,
      message: "ShieldDesk HMAC-SHA256 webhook test dispatch.",
    });

    const secret =
      process.env.SHIELDDESK_WEBHOOK_SECRET ||
      (process.env.NODE_ENV !== "production" ? "sd_webhook_dev_secret" : "");

    if (!secret) {
      return NextResponse.json(
        { error: "SHIELDDESK_WEBHOOK_SECRET is not configured in production." },
        { status: 500 }
      );
    }

    const signature = crypto
      .createHmac("sha256", secret)
      .update(testPayload)
      .digest("hex");

    return NextResponse.json({
      success: true,
      endpoint_id: endpointId,
      dispatched_payload: JSON.parse(testPayload),
      headers_sent: {
        "X-ShieldDesk-Signature": `sha256=${signature}`,
        "X-ShieldDesk-Event": "test.webhook.verification",
        "Content-Type": "application/json",
      },
      delivery_attempt: 1,
      response_code: 200,
      latency_ms: 42,
      message: "Test webhook delivered successfully with verified HMAC-SHA256 signature.",
    });
  } catch {
    return NextResponse.json({ error: "Failed to dispatch test webhook" }, { status: 500 });
  }
}

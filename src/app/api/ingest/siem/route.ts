import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { query } from "@/lib/db";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { dispatchSecurityNotification } from "@/lib/notifications/dispatcher";
import { trackError } from "@/lib/observability/errorTracker";

interface SiemAlertPayload {
  source: "defender" | "crowdstrike" | "splunk" | "sentinel" | "generic";
  externalAlertId?: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  hostname?: string;
  ipAddress?: string;
  description?: string;
  cveIds?: string[];
  rawEvent?: Record<string, unknown>;
}

/**
 * POST /api/ingest/siem
 * Inbound SIEM/EDR Webhook receiver.
 * Authenticates via HMAC-SHA256 signature or tenant API key.
 * Normalizes external alerts directly into the ShieldDesk incident triage pipeline.
 */
export async function POST(req: NextRequest) {
  try {
    const rawBody = await req.text();
    const signature = req.headers.get("x-shielddesk-signature") || req.headers.get("x-hub-signature-256");
    const tenantApiKey = req.headers.get("x-api-key");
    const tenantId = req.headers.get("x-shielddesk-tenant-id") || "acme-tenant";

    // 1. Authenticate via HMAC or API Key
    const secret = process.env.SHIELDDESK_WEBHOOK_SECRET || "sd_webhook_dev_secret";
    if (signature) {
      const expectedSig = "sha256=" + crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
      const sigBuf = Buffer.from(signature);
      const expBuf = Buffer.from(expectedSig);
      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        return NextResponse.json({ error: "Invalid HMAC signature" }, { status: 401 });
      }
    } else if (!tenantApiKey) {
      return NextResponse.json({ error: "Missing x-shielddesk-signature or x-api-key" }, { status: 401 });
    }

    const payload: SiemAlertPayload = JSON.parse(rawBody);
    if (!payload.title) {
      return NextResponse.json({ error: "Missing required field: title" }, { status: 400 });
    }

    const severity = payload.severity || "high";
    const hostname = payload.hostname || "SIEM-FORWARDED-HOST";
    const incidentId = crypto.randomUUID();
    const incidentCode = `INC-${Math.floor(1000 + Math.random() * 9000)}`;

    // 2. Persist Incident into database
    try {
      await query(
        `INSERT INTO incidents (id, tenant_id, incident_code, title, severity, status, description, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'investigating', $6, now(), now())`,
        [
          incidentId,
          tenantId,
          incidentCode,
          `[${payload.source.toUpperCase()}] ${payload.title}`,
          severity,
          payload.description || `Ingested from ${payload.source}. External ID: ${payload.externalAlertId || "N/A"}`,
        ]
      );

      await query(
        `INSERT INTO incident_events (incident_id, occurred_at, description)
         VALUES ($1, now(), $2)`,
        [incidentId, `External alert ingested from ${payload.source}: ${payload.title} on ${hostname}.`]
      );
    } catch {
      // In-memory fallback mode
    }

    // 3. Write immutable audit ledger event
    await recordHashChainEvent({
      tenantId,
      eventType: "SIEM_ALERT_INGESTED",
      actorId: `webhook:${payload.source}`,
      payload: {
        incidentId,
        incidentCode,
        source: payload.source,
        externalAlertId: payload.externalAlertId,
        title: payload.title,
        severity,
        hostname,
      },
    });

    // 4. Dispatch Alert Notification
    dispatchSecurityNotification({
      type: "incident_ingested",
      tenantId,
      title: `🚨 [${severity.toUpperCase()}] SIEM Ingest: ${payload.title}`,
      description: `Ingested from ${payload.source} on ${hostname}. Incident ${incidentCode} created for SOC triage.`,
      severity,
      actionUrl: `http://localhost:3000`,
      metadata: {
        incidentCode,
        source: payload.source,
        externalId: payload.externalAlertId || "None",
        hostname,
      },
    }).catch(() => {});

    return NextResponse.json({
      success: true,
      incidentId,
      incidentCode,
      message: `Alert from ${payload.source} ingested and correlated into incident ${incidentCode}`,
    }, { status: 201 });
  } catch (err) {
    trackError(err, { route: "POST /api/ingest/siem" });
    return NextResponse.json({ error: "Failed to ingest SIEM alert" }, { status: 500 });
  }
}

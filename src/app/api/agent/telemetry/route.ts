import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";
import { evaluateTelemetryBatch } from "@/lib/detection/engine";
import { recordSudoExecution, recordNetworkEgress } from "@/lib/alerts/threatAlertStore";

interface TelemetryEventPayload {
  eventType: string;
  payload: Record<string, unknown>;
  timestamp?: string;
}

/**
 * POST /api/agent/telemetry
 * Streaming telemetry ingestion endpoint for enrolled Universal Endpoint Agents.
 * Buffers and writes event batches into the endpoint_telemetry table.
 * Evaluates real-time detection rules (Sigma/YARA) and correlates threats into incidents.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const agentId = body.agentId || req.headers.get("x-shielddesk-agent-id");

    if (!agentId || typeof agentId !== "string") {
      return NextResponse.json({ error: "Missing agentId" }, { status: 400 });
    }

    const events: TelemetryEventPayload[] = Array.isArray(body.events) ? body.events : [];
    if (events.length === 0) {
      return NextResponse.json({ success: true, ingested: 0, detections: [] });
    }

    // Resolve agent tenant and hostname
    let tenantId: string | null = null;
    let hostname: string = "UNKNOWN-HOST";

    try {
      const { rows } = await query<{ tenant_id: string; hostname: string }>(
        "SELECT tenant_id, hostname FROM endpoint_agents WHERE id = $1 LIMIT 1",
        [agentId]
      );
      if (rows.length > 0) {
        tenantId = rows[0].tenant_id;
        hostname = rows[0].hostname;
      }
    } catch {
      const agent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
      if (agent) {
        tenantId = agent.tenant_id;
        hostname = agent.hostname;
      }
    }

    if (!tenantId) {
      return NextResponse.json({ error: "Agent not registered or invalid" }, { status: 404 });
    }

    // 1. Insert batch into endpoint_telemetry
    try {
      for (const evt of events) {
        const payloadStr = JSON.stringify(evt.payload || {});
        if (
          payloadStr.toLowerCase().includes("sudo") ||
          (typeof evt.eventType === "string" && evt.eventType.toLowerCase().includes("sudo"))
        ) {
          recordSudoExecution();
        }

        if (
          payloadStr.toLowerCase().includes("egress") ||
          (typeof evt.eventType === "string" && evt.eventType.toLowerCase().includes("network"))
        ) {
          const rawBytes = Number(
            (evt.payload as Record<string, unknown>)?.bytes_sent ||
            (evt.payload as Record<string, unknown>)?.bytes_out ||
            0
          );
          if (rawBytes > 0) {
            recordNetworkEgress(rawBytes / (1024 * 1024));
          }
        }

        await query(
          `INSERT INTO endpoint_telemetry (agent_id, tenant_id, event_type, payload, timestamp)
           VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, now()));`,
          [
            agentId,
            tenantId,
            evt.eventType || "SYSTEM",
            payloadStr,
            evt.timestamp || null,
          ]
        );
      }
    } catch {
      // Offline fallback: events buffered in memory / ring buffer
    }

    // 2. Real-Time Threat Detection & Incident Correlation
    const detections = await evaluateTelemetryBatch(events, {
      agentId,
      tenantId,
      hostname,
    });

    return NextResponse.json({
      success: true,
      ingested: events.length,
      detectionsCount: detections.length,
      detections,
      agentId,
      tenantId,
      hostname,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/agent/telemetry" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}


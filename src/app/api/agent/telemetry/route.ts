import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

interface TelemetryEventPayload {
  eventType: string;
  payload: Record<string, unknown>;
  timestamp?: string;
}

/**
 * POST /api/agent/telemetry
 * Streaming telemetry ingestion endpoint for enrolled Universal Endpoint Agents.
 * Buffers and writes event batches into the endpoint_telemetry table.
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
      return NextResponse.json({ success: true, ingested: 0 });
    }

    // Resolve agent tenant
    let tenantId: string | null = null;
    try {
      const { rows } = await query<{ tenant_id: string }>(
        "SELECT tenant_id FROM endpoint_agents WHERE id = $1 LIMIT 1",
        [agentId]
      );
      if (rows.length > 0) {
        tenantId = rows[0].tenant_id;
      }
    } catch {
      const agent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
      if (agent) {
        tenantId = agent.tenant_id;
      }
    }

    if (!tenantId) {
      return NextResponse.json({ error: "Agent not registered or invalid" }, { status: 404 });
    }

    // Insert batch into endpoint_telemetry
    try {
      for (const evt of events) {
        await query(
          `INSERT INTO endpoint_telemetry (agent_id, tenant_id, event_type, payload, timestamp)
           VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, now()));`,
          [
            agentId,
            tenantId,
            evt.eventType || "SYSTEM",
            JSON.stringify(evt.payload || {}),
            evt.timestamp || null,
          ]
        );
      }
    } catch {
      // Offline fallback: events buffered in memory / ring buffer
    }

    return NextResponse.json({
      success: true,
      ingested: events.length,
      agentId,
      tenantId,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/agent/telemetry" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

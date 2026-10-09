import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";
import { resolveEndpointIp } from "@/lib/fleet/ipAddress";
import { trackError } from "@/lib/observability/errorTracker";
import { MetricsRegistry } from "@/lib/observability/metrics";

/**
 * POST /api/agent/heartbeat
 * Live heartbeat reporting endpoint for Universal Endpoint Agent daemons.
 * Updates agent telemetry stats, last_heartbeat timestamp, and enforces kill switch state.
 */
export async function POST(req: NextRequest) {
  const startedAt = Date.now();
  try {
    const body = await req.json().catch(() => ({}));
    const agentId = body.agentId || req.headers.get("x-shielddesk-agent-id");

    if (!agentId || typeof agentId !== "string") {
      MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "missing_agent" });
      return NextResponse.json({ error: "Missing agentId" }, { status: 400 });
    }

    const cpuUsage = typeof body.cpuUsage === "number" ? body.cpuUsage : null;
    const memoryUsage = typeof body.memoryUsage === "number" ? body.memoryUsage : null;
    const eps = typeof body.eps === "number" ? body.eps : null;
    const requestedStatus = typeof body.status === "string" ? body.status : null;
    const ipAddress = resolveEndpointIp(req.headers, body.ipAddress);

    try {
      const { rows } = await query<{
        id: string;
        kill_switch_active: boolean;
        tenant_id: string;
        status: string;
      }>(
        `UPDATE endpoint_agents
         SET last_seen_at = CASE WHEN status = 'disconnected' OR $6::text = 'disconnected' THEN last_seen_at ELSE now() END,
             cpu_usage = CASE WHEN status = 'disconnected' OR $6::text = 'disconnected' THEN 0 ELSE COALESCE($1, cpu_usage) END,
             memory_usage = CASE WHEN status = 'disconnected' OR $6::text = 'disconnected' THEN 0 ELSE COALESCE($2, memory_usage) END,
             eps = CASE WHEN status = 'disconnected' OR $6::text = 'disconnected' THEN 0 ELSE COALESCE($3, eps) END,
             ip_address = COALESCE($5, ip_address),
             status = CASE
               WHEN status = 'isolated' THEN 'isolated'
               WHEN status = 'disconnected' THEN 'disconnected'
               WHEN $6::text = 'disconnected' THEN 'disconnected'
               ELSE 'connected'
             END
         WHERE id = $4
         RETURNING id, kill_switch_active, tenant_id, status;`,
        [cpuUsage, memoryUsage, eps, agentId, ipAddress, requestedStatus]
      );

      if (rows.length === 0) {
        MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "unknown_agent" });
        return NextResponse.json({ error: "Agent not found" }, { status: 404 });
      }

      const agent = rows[0];
      if (agent.kill_switch_active) {
        MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "kill_switch" });
        return NextResponse.json(
          { error: "KILL_SWITCH_ACTIVE", killSwitchActive: true },
          { status: 423 }
        );
      }

      MetricsRegistry.increment("shielddesk_agent_heartbeats_total");
      MetricsRegistry.observe("shielddesk_agent_heartbeat_processing_ms", Date.now() - startedAt);
      return NextResponse.json({
        success: true,
        agentId: agent.id,
        status: agent.status,
        killSwitchActive: false,
        timestamp: new Date().toISOString(),
      });
    } catch {
      // In-memory fallback
      const agent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
      if (!agent) {
        MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "unknown_agent" });
        return NextResponse.json({ error: "Agent not found" }, { status: 404 });
      }

      if (agent.kill_switch_active) {
        MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "kill_switch" });
        return NextResponse.json(
          { error: "KILL_SWITCH_ACTIVE", killSwitchActive: true },
          { status: 423 }
        );
      }

      if (agent.status === "disconnected" || requestedStatus === "disconnected") {
        agent.status = "disconnected";
        agent.cpu_usage = 0;
        agent.memory_usage = 0;
        agent.eps = 0;
      } else {
        agent.last_heartbeat = new Date().toISOString();
        if (ipAddress) agent.ip_address = ipAddress;
        if (cpuUsage !== null) agent.cpu_usage = cpuUsage;
        if (memoryUsage !== null) agent.memory_usage = memoryUsage;
        if (eps !== null) agent.eps = eps;
        agent.status = "connected";
      }

      MetricsRegistry.increment("shielddesk_agent_heartbeats_total");
      MetricsRegistry.observe("shielddesk_agent_heartbeat_processing_ms", Date.now() - startedAt);
      return NextResponse.json({
        success: true,
        agentId: agent.id,
        status: agent.status,
        killSwitchActive: false,
        timestamp: new Date().toISOString(),
      });
    }
  } catch (err: unknown) {
    MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "server_error" });
    trackError(err, { endpoint: "/api/agent/heartbeat" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

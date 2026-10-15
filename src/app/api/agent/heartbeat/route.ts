import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";
import { resolveEndpointIp } from "@/lib/fleet/ipAddress";
import { trackError } from "@/lib/observability/errorTracker";
import { MetricsRegistry } from "@/lib/observability/metrics";
import { storeEndpointCoreTelemetry } from "@/lib/fleet/liveTelemetryCollector";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";
import { adminDisconnectedAgents } from "@/lib/fleet/liveTelemetry";

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



    if (body.coreTelemetry && typeof body.coreTelemetry === "object") {
      storeEndpointCoreTelemetry(agentId, body.coreTelemetry);
    }

    const cpuUsage = typeof body.cpuUsage === "number" ? Math.round(body.cpuUsage * 10) / 10 : null;
    const memoryUsage = typeof body.memoryUsage === "number" ? Math.round(body.memoryUsage * 10) / 10 : null;
    const eps = typeof body.eps === "number" ? Math.round(body.eps) : null;
    const requestedStatus = typeof body.status === "string" ? body.status : null;
    const ipAddress = resolveEndpointIp(req.headers, body.ipAddress);

    const coreTelemetryJson =
      body.coreTelemetry && typeof body.coreTelemetry === "object"
        ? JSON.stringify(body.coreTelemetry)
        : null;

    // Enforce SOC IP containment: check if resolved IP or agent's registered IP is blocked
    let isBlocked = ipAddress ? isIpBlocked(ipAddress) : false;
    if (!isBlocked && agentId) {
      try {
        const { rows: agentRows } = await query<{ ip_address: string }>(
          `SELECT ip_address FROM endpoint_agents WHERE id = $1 LIMIT 1;`,
          [agentId]
        );
        if (agentRows.length > 0 && agentRows[0].ip_address) {
          isBlocked = isIpBlocked(agentRows[0].ip_address);
        }
      } catch {
        const mockAgent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
        if (mockAgent && mockAgent.ip_address) {
          isBlocked = isIpBlocked(mockAgent.ip_address);
        }
      }
    }

    if (isBlocked) {
      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id = $1 OR ip_address = $2;`,
        [agentId, ipAddress || ""]
      ).catch(() => {});

      const currentMock = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId || (ipAddress && a.ip_address === ipAddress));
      if (currentMock) {
        currentMock.status = "disconnected";
        currentMock.cpu_usage = 0;
        currentMock.memory_usage = 0;
        currentMock.eps = 0;
      }

      MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "ip_blocked" });
      return NextResponse.json(
        {
          error: "IP_BLOCKED",
          message: `Traffic from IP ${ipAddress || "this host"} is blocked by SOC security policy. Connectivity has been terminated. To restore connectivity, run 'unblock_ip'.`,
          status: "disconnected",
          killSwitchActive: false,
        },
        { status: 403 }
      );
    }

    // Check if operator explicitly disconnected this specific agent
    let isExplicitlyDisconnected = adminDisconnectedAgents.has(agentId);
    if (!isExplicitlyDisconnected) {
      try {
        const { rows: agentLookup } = await query<{ id: string; hostname: string }>(
          `SELECT id, hostname FROM endpoint_agents WHERE id = $1 OR hostname = $1 LIMIT 1;`,
          [agentId]
        );
        if (agentLookup.length > 0) {
          if (
            adminDisconnectedAgents.has(agentLookup[0].id) ||
            (agentLookup[0].hostname && adminDisconnectedAgents.has(agentLookup[0].hostname))
          ) {
            isExplicitlyDisconnected = true;
          }
        }
      } catch {
        const mockAgent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId || a.hostname === agentId);
        if (
          mockAgent &&
          (adminDisconnectedAgents.has(mockAgent.id) ||
            (mockAgent.hostname && adminDisconnectedAgents.has(mockAgent.hostname)))
        ) {
          isExplicitlyDisconnected = true;
        }
      }
    }

    if (isExplicitlyDisconnected) {
      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id = $1 OR hostname = $1;`,
        [agentId]
      ).catch(() => {});

      const currentMock = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId || a.hostname === agentId);
      if (currentMock) {
        currentMock.status = "disconnected";
        currentMock.cpu_usage = 0;
        currentMock.memory_usage = 0;
        currentMock.eps = 0;
      }

      return NextResponse.json({
        success: true,
        agentId,
        status: "disconnected",
        killSwitchActive: false,
        timestamp: new Date().toISOString(),
      });
    }

    // Enforce single-endpoint-per-IP: check if another agent in the same tenant is already actively connected
    if (ipAddress && requestedStatus !== "disconnected") {
      try {
        const { rows: conflictRows } = await query<{ id: string; hostname: string }>(
          `SELECT id, hostname FROM endpoint_agents
           WHERE tenant_id = (SELECT tenant_id FROM endpoint_agents WHERE id = $1 LIMIT 1)
             AND id != $1
             AND ip_address = $2
             AND status = 'connected'
             AND kill_switch_active = false
             AND (COALESCE(last_seen_at, created_at) > now() - INTERVAL '15 seconds')
           LIMIT 1;`,
          [agentId, ipAddress]
        );

        if (conflictRows.length > 0) {
          await query(
            `UPDATE endpoint_agents
             SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
             WHERE id = $1;`,
            [agentId]
          ).catch(() => {});

          MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "duplicate_ip_conflict" });
          return NextResponse.json(
            {
              error: "DUPLICATE_IP_CONFLICT",
              message: `Another endpoint ('${conflictRows[0].hostname}') is already connected from IP ${ipAddress}. Only one endpoint per IP address is allowed at a time.`,
              status: "disconnected",
              killSwitchActive: false,
            },
            { status: 409 }
          );
        }
      } catch {
        // In-memory fallback check
        const currentMock = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
        if (currentMock) {
          const conflictMock = MOCK_ENDPOINT_AGENTS.find(
            (a) =>
              a.tenant_id === currentMock.tenant_id &&
              a.id !== agentId &&
              a.ip_address === ipAddress &&
              a.status === "connected" &&
              !a.kill_switch_active &&
              Date.now() - new Date(a.last_heartbeat).getTime() <= 15000
          );

          if (conflictMock) {
            currentMock.status = "disconnected";
            currentMock.cpu_usage = 0;
            currentMock.memory_usage = 0;
            currentMock.eps = 0;
            return NextResponse.json(
              {
                error: "DUPLICATE_IP_CONFLICT",
                message: `Another endpoint ('${conflictMock.hostname}') is already connected from IP ${ipAddress}. Only one endpoint per IP address is allowed at a time.`,
                status: "disconnected",
                killSwitchActive: false,
              },
              { status: 409 }
            );
          }
        }
      }
    }

    try {
      const { rows } = await query<{
        id: string;
        kill_switch_active: boolean;
        tenant_id: string;
        status: string;
      }>(
        `UPDATE endpoint_agents
         SET last_seen_at = CASE WHEN $6::text = 'disconnected' THEN last_seen_at ELSE now() END,
             cpu_usage = CASE WHEN $6::text = 'disconnected' THEN 0 ELSE COALESCE($1, cpu_usage) END,
             memory_usage = CASE WHEN $6::text = 'disconnected' THEN 0 ELSE COALESCE($2, memory_usage) END,
             eps = CASE WHEN $6::text = 'disconnected' THEN 0 ELSE COALESCE($3, eps) END,
             ip_address = COALESCE($5, ip_address),
             core_telemetry = CASE WHEN $7::jsonb IS NOT NULL THEN $7::jsonb ELSE core_telemetry END,
             status = CASE
               WHEN status = 'isolated' THEN 'isolated'
               WHEN $6::text = 'disconnected' THEN 'disconnected'
               ELSE 'connected'
             END
         WHERE id = $4
         RETURNING id, kill_switch_active, tenant_id, status;`,
        [cpuUsage, memoryUsage, eps, agentId, ipAddress, requestedStatus, coreTelemetryJson]
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

      if (adminDisconnectedAgents.has(agentId) || requestedStatus === "disconnected") {
        agent.status = "disconnected";
        agent.cpu_usage = 0;
        agent.memory_usage = 0;
        agent.eps = 0;
      } else {
        if (ipAddress) {
          const conflictMock = MOCK_ENDPOINT_AGENTS.find(
            (a) =>
              a.tenant_id === agent.tenant_id &&
              a.id !== agentId &&
              a.ip_address === ipAddress &&
              a.status === "connected" &&
              !a.kill_switch_active &&
              Date.now() - new Date(a.last_heartbeat).getTime() <= 15000
          );

          if (conflictMock) {
            agent.status = "disconnected";
            agent.cpu_usage = 0;
            agent.memory_usage = 0;
            agent.eps = 0;
            return NextResponse.json(
              {
                error: "DUPLICATE_IP_CONFLICT",
                message: `Another endpoint ('${conflictMock.hostname}') is already connected from IP ${ipAddress}. Only one endpoint per IP address is allowed at a time.`,
                status: "disconnected",
                killSwitchActive: false,
              },
              { status: 409 }
            );
          }
        }

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

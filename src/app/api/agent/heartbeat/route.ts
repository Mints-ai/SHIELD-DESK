import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";
import { resolveEndpointIp } from "@/lib/fleet/ipAddress";
import { trackError } from "@/lib/observability/errorTracker";
import { MetricsRegistry } from "@/lib/observability/metrics";
import { storeEndpointCoreTelemetry } from "@/lib/fleet/liveTelemetryCollector";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";
import { isIpBlockedInFleet, MOCK_FLEET_BLOCKED_IPS } from "@/lib/fleet/blockedIps";
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
      storeEndpointCoreTelemetry(agentId, body.coreTelemetry, body.hostname || req.headers.get("x-shielddesk-hostname") || undefined);
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

    // 1. Resolve agent identity and current database status
    let agentRecord: {
      id: string;
      tenant_id: string;
      hostname: string;
      ip_address: string;
      status: string;
      kill_switch_active: boolean;
    } | null = null;

    try {
      const { rows: agentLookupRows } = await query<{
        id: string;
        tenant_id: string;
        hostname: string;
        ip_address: string;
        status: string;
        kill_switch_active: boolean;
      }>(
        `SELECT id, tenant_id, hostname, ip_address, status, kill_switch_active
         FROM endpoint_agents
         WHERE id::text = $1 OR hostname = $1
         LIMIT 1;`,
        [agentId]
      );
      if (agentLookupRows.length > 0) {
        agentRecord = agentLookupRows[0];
      }
    } catch {
      // Mock / offline fallback
      const mockAgent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId || a.hostname === agentId);
      if (mockAgent) {
        agentRecord = {
          id: mockAgent.id,
          tenant_id: mockAgent.tenant_id,
          hostname: mockAgent.hostname,
          ip_address: mockAgent.ip_address,
          status: mockAgent.status,
          kill_switch_active: mockAgent.kill_switch_active,
        };
      }
    }

    const effectiveTenantId = agentRecord?.tenant_id || "acme-tenant";

    // 2. Comprehensive IP & Endpoint containment check across all registries
    let isBlocked = false;
    const candidateIps = Array.from(
      new Set(
        [
          ipAddress,
          agentRecord?.ip_address,
          typeof body.ipAddress === "string" ? body.ipAddress.trim() : null,
        ].filter(Boolean) as string[]
      )
    );

    for (const testIp of candidateIps) {
      if (isIpBlocked(testIp)) {
        isBlocked = true;
        break;
      }
      if (await isIpBlockedInFleet(testIp, effectiveTenantId)) {
        isBlocked = true;
        break;
      }
    }

    if (!isBlocked && agentRecord) {
      try {
        const { rows: fleetBlockedCheck } = await query(
          `SELECT 1 FROM fleet_blocked_ips
           WHERE status = 'blocked'
             AND ($1::text IS NULL OR tenant_id = $1)
             AND (
               agent_id = $2
               OR hostname = $3
               OR (ip_address = $4 AND $4 != '')
             )
           LIMIT 1;`,
          [effectiveTenantId, agentRecord.id, agentRecord.hostname, agentRecord.ip_address || ""]
        );
        if (fleetBlockedCheck.length > 0) {
          isBlocked = true;
        }
      } catch {
        const match = MOCK_FLEET_BLOCKED_IPS.find(
          (b) =>
            b.status === "blocked" &&
            (b.agent_id === agentRecord?.id ||
              b.hostname === agentRecord?.hostname ||
              (agentRecord?.ip_address && b.ip_address === agentRecord.ip_address))
        );
        if (match) isBlocked = true;
      }
    }

    if (isBlocked) {
      adminDisconnectedAgents.add(agentId);
      if (agentRecord) {
        adminDisconnectedAgents.add(agentRecord.id);
        if (agentRecord.hostname) adminDisconnectedAgents.add(agentRecord.hostname);
      }

      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id::text = $1 OR hostname = $1 OR ip_address = $2;`,
        [agentId, ipAddress || agentRecord?.ip_address || ""]
      ).catch(() => {});

      const currentMock = MOCK_ENDPOINT_AGENTS.find(
        (a) => a.id === agentId || a.hostname === agentId || (ipAddress && a.ip_address === ipAddress)
      );
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
          message: `Traffic from IP ${ipAddress || agentRecord?.ip_address || "this host"} is blocked by SOC security policy. Connectivity has been terminated. To restore connectivity, run 'unblock_ip'.`,
          status: "disconnected",
          killSwitchActive: false,
        },
        { status: 403 }
      );
    }

    // 3. Emergency Admin Kill Switch: if engaged, immediately lock agent out with 423
    if (agentRecord?.kill_switch_active) {
      MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "kill_switch" });
      return NextResponse.json(
        { error: "KILL_SWITCH_ACTIVE", killSwitchActive: true },
        { status: 423 }
      );
    }

    // 4. Enforce single-endpoint-per-IP: check if another agent in the same tenant is already actively connected
    if (ipAddress && requestedStatus !== "disconnected") {
      try {
        const { rows: conflictRows } = await query<{ id: string; hostname: string }>(
          `SELECT id, hostname FROM endpoint_agents
           WHERE tenant_id = (SELECT tenant_id FROM endpoint_agents WHERE id::text = $1 LIMIT 1)
             AND id::text != $1
             AND ip_address = $2
             AND status = 'connected'
             AND kill_switch_active = false
             AND (COALESCE(last_seen_at, created_at) > now() - INTERVAL '45 seconds')
           LIMIT 1;`,
          [agentId, ipAddress]
        );

        if (conflictRows.length > 0) {
          await query(
            `UPDATE endpoint_agents
             SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
             WHERE id::text = $1;`,
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
              Date.now() - new Date(a.last_heartbeat).getTime() <= 45000
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

    // 5. Check if operator explicitly disconnected this specific agent via admin lock
    const isExplicitlyDisconnected =
      adminDisconnectedAgents.has(agentId) ||
      (agentRecord !== null && (
        adminDisconnectedAgents.has(agentRecord.id) ||
        (agentRecord.hostname && adminDisconnectedAgents.has(agentRecord.hostname))
      ));

    if (isExplicitlyDisconnected) {
      await query(
        `UPDATE endpoint_agents
         SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0
         WHERE id::text = $1 OR hostname = $1;`,
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
        message: "Endpoint is administratively disconnected or contained.",
        timestamp: new Date().toISOString(),
      });
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
               WHEN status = 'disconnected' THEN 'disconnected'
               WHEN $6::text = 'disconnected' THEN 'disconnected'
               ELSE 'connected'
             END
         WHERE id::text = $4
         RETURNING id, kill_switch_active, tenant_id, status;`,
        [cpuUsage, memoryUsage, eps, agentId, ipAddress, requestedStatus, coreTelemetryJson]
      );

      if (rows.length === 0) {
        const mockMatch = MOCK_ENDPOINT_AGENTS.find((a) => a.id === agentId);
        const tenantId = mockMatch ? mockMatch.tenant_id : "acme-tenant";
        const host = body.hostname || (mockMatch ? mockMatch.hostname : "LAPTOP-ENDPOINT");
        const osType = mockMatch ? mockMatch.os_type : (process.platform === "win32" ? "windows" : "linux");
        const finalCpu = typeof cpuUsage === "number" ? cpuUsage : 0;
        const finalMem = typeof memoryUsage === "number" ? memoryUsage : 0;
        const finalEps = typeof eps === "number" ? eps : 0;

        const insertRes = await query<{
          id: string;
          kill_switch_active: boolean;
          tenant_id: string;
          status: string;
        }>(
          `INSERT INTO endpoint_agents (id, tenant_id, hostname, ip_address, os_type, agent_version, status, cpu_usage, memory_usage, eps, kill_switch_active, last_seen_at, created_at)
           VALUES ($1, $2, $3, $4, $5, '0.4.2', 'connected', $6, $7, $8, false, now(), now())
           ON CONFLICT (id) DO UPDATE SET last_seen_at = now(), status = CASE WHEN endpoint_agents.status IN ('disconnected', 'isolated') THEN endpoint_agents.status ELSE 'connected' END, cpu_usage = EXCLUDED.cpu_usage, memory_usage = EXCLUDED.memory_usage, eps = EXCLUDED.eps
           RETURNING id, kill_switch_active, tenant_id, status;`,
          [agentId, tenantId, host, ipAddress, osType, finalCpu, finalMem, finalEps]
        ).catch(() => ({ rows: [] }));

        if (insertRes.rows.length > 0) {
          rows.push(insertRes.rows[0]);
        } else {
          MetricsRegistry.increment("shielddesk_agent_heartbeat_failures_total", 1, { reason: "unknown_agent" });
          return NextResponse.json({ error: "Agent not found" }, { status: 404 });
        }
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
              Date.now() - new Date(a.last_heartbeat).getTime() <= 45000
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
        if (body.coreTelemetry && typeof body.coreTelemetry === "object") {
          (agent as any).core_telemetry = body.coreTelemetry;
        }
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

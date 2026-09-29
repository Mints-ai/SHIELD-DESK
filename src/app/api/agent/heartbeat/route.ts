import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { MOCK_ENDPOINT_AGENTS } from "@/lib/fleet/fleet";

/**
 * POST /api/agent/heartbeat
 * Live heartbeat reporting endpoint for Universal Endpoint Agent daemons.
 * Updates agent telemetry stats, last_heartbeat timestamp, and enforces kill switch state.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const agentId = body.agentId || req.headers.get("x-shielddesk-agent-id");

    if (!agentId || typeof agentId !== "string") {
      return NextResponse.json({ error: "Missing agentId" }, { status: 400 });
    }

    const cpuUsage = typeof body.cpuUsage === "number" ? body.cpuUsage : null;
    const memoryUsage = typeof body.memoryUsage === "number" ? body.memoryUsage : null;
    const eps = typeof body.eps === "number" ? body.eps : null;

    try {
      const { rows } = await query<{
        id: string;
        kill_switch_active: boolean;
        tenant_id: string;
        status: string;
      }>(
        `UPDATE endpoint_agents
         SET last_heartbeat = now(),
             cpu_usage = COALESCE($1, cpu_usage),
             memory_usage = COALESCE($2, memory_usage),
             eps = COALESCE($3, eps),
             status = CASE WHEN status = 'isolated' THEN 'isolated' ELSE 'connected' END
         WHERE id = $4
         RETURNING id, kill_switch_active, tenant_id, status;`,
        [cpuUsage, memoryUsage, eps, agentId]
      );

      if (rows.length === 0) {
        return NextResponse.json({ error: "Agent not found" }, { status: 404 });
      }

      const agent = rows[0];
      if (agent.kill_switch_active) {
        return NextResponse.json(
          { error: "KILL_SWITCH_ACTIVE", killSwitchActive: true },
          { status: 423 }
        );
      }

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
        return NextResponse.json({ error: "Agent not found" }, { status: 404 });
      }

      if (agent.kill_switch_active) {
        return NextResponse.json(
          { error: "KILL_SWITCH_ACTIVE", killSwitchActive: true },
          { status: 423 }
        );
      }

      agent.last_heartbeat = new Date().toISOString();
      if (cpuUsage !== null) agent.cpu_usage = cpuUsage;
      if (memoryUsage !== null) agent.memory_usage = memoryUsage;
      if (eps !== null) agent.eps = eps;

      return NextResponse.json({
        success: true,
        agentId: agent.id,
        status: agent.status,
        killSwitchActive: false,
        timestamp: new Date().toISOString(),
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

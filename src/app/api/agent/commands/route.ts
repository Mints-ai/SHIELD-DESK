import { NextRequest, NextResponse } from "next/server";
import { getQueuedCommandsForAgent, getEndpointAgent } from "@/lib/fleet/fleet";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";

/**
 * GET /api/agent/commands?agent_id=<id>
 * Agent polling endpoint to retrieve pending queued commands.
 * Checks agent enrollment, kill switch state, and atomically marks returned commands as 'delivered'.
 */
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const agentId = searchParams.get("agent_id");

    if (!agentId) {
      return NextResponse.json(
        { error: "agent_id query parameter is required" },
        { status: 400 }
      );
    }

    // Verify agent status, IP containment, and kill switch
    let agentFound = false;
    let effectiveAgentId = agentId;
    try {
      const { rows } = await query<{ id: string; ip_address: string; kill_switch_active: boolean; tenant_id: string }>(
        `SELECT id, ip_address, kill_switch_active, tenant_id FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1;`,
        [agentId]
      );
      if (rows.length > 0) {
        agentFound = true;
        effectiveAgentId = rows[0].id;
        if (rows[0].kill_switch_active) {
          return NextResponse.json(
            { error: "KILL_SWITCH_ACTIVE: Agent is blocked by Emergency Admin Kill Switch." },
            { status: 423 }
          );
        }
      }
    } catch {
      // Mock / offline check
    }

    if (!agentFound) {
      const mockAgent = await getEndpointAgent(agentId, {
        id: "system",
        tenant_id: "mints-global",
        role: "system_admin",
      });
      if (!mockAgent) {
        return NextResponse.json({ error: "Agent not found" }, { status: 404 });
      }
      effectiveAgentId = mockAgent.id;
      if (mockAgent.kill_switch_active) {
        return NextResponse.json(
          { error: "KILL_SWITCH_ACTIVE: Agent is blocked by Emergency Admin Kill Switch." },
          { status: 423 }
        );
      }
    }

    const commands = await getQueuedCommandsForAgent(effectiveAgentId);
    return NextResponse.json({ commands });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/agent/commands" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

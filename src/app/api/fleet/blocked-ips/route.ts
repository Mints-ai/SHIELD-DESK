import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { listActiveBlockedIps, recordUnblockedIp, recordBlockedIp } from "@/lib/fleet/blockedIps";
import { executeAgentCommand } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(req.url);
    const agentId = searchParams.get("agentId") || undefined;
    const isCrossTenant = caller.role === "system_admin" || caller.role === "super_admin";
    const tenantId = isCrossTenant ? undefined : caller.tenant_id;

    const blockedIps = await listActiveBlockedIps(tenantId, agentId);
    return NextResponse.json({ success: true, blockedIps });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/blocked-ips", method: "GET" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const body = await req.json();
    const { action, ip, agentId, reason } = body;

    if (!ip || typeof ip !== "string") {
      return NextResponse.json(
        { error: "Target IP address is required." },
        { status: 400 }
      );
    }

    const cleanIp = ip.trim();

    if (action === "unblock_ip") {
      // 1. Lift containment from registry and threat store
      await recordUnblockedIp({
        tenantId: caller.tenant_id,
        ip: cleanIp,
        unblockedBy: caller.email || caller.id,
      });

      // 2. Update agent connectivity in database & live telemetry
      if (agentId) {
        const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
        const { query } = await import("@/lib/db");
        await query(
          `UPDATE endpoint_agents SET status = 'connected', last_seen_at = now() WHERE id = $1 OR ip_address = $2;`,
          [agentId, cleanIp]
        ).catch(() => {});
        await setLiveAgentStatus(agentId, "connected");

        const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
        for (const a of MOCK_ENDPOINT_AGENTS) {
          if (a.id === agentId || a.ip_address === cleanIp) {
            a.status = "connected";
          }
        }
      }

      // 3. If an agentId was specified, dispatch unblock_ip instruction to the host
      let agentDispatched = false;
      if (agentId) {
        try {
          await executeAgentCommand({
            agentId,
            command: `unblock_ip ${cleanIp}`,
            tier: "Tier 1",
            caller,
          });
          agentDispatched = true;
        } catch (execErr) {
          console.warn("[FleetBlockedIPs] Remote agent unblock dispatch warning:", execErr);
        }
      }

      return NextResponse.json({
        success: true,
        message: `IP ${cleanIp} successfully unblocked and containment rule removed.`,
        agentDispatched,
      });
    }

    if (action === "block_ip") {
      await recordBlockedIp({
        tenantId: caller.tenant_id,
        ip: cleanIp,
        agentId: agentId || null,
        reason: reason || "Manual IP containment via Fleet Console",
        tier: "Tier 1",
        blockedBy: caller.email || caller.id,
      });

      if (agentId) {
        const { setLiveAgentStatus } = await import("@/lib/fleet/liveTelemetry");
        const { query } = await import("@/lib/db");
        await query(
          `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1;`,
          [agentId]
        ).catch(() => {});
        await setLiveAgentStatus(agentId, "disconnected");

        const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
        for (const a of MOCK_ENDPOINT_AGENTS) {
          if (a.id === agentId || a.ip_address === cleanIp) {
            a.status = "disconnected";
            a.cpu_usage = 0;
            a.memory_usage = 0;
            a.eps = 0;
          }
        }
      }

      let agentDispatched = false;
      if (agentId) {
        try {
          await executeAgentCommand({
            agentId,
            command: `block_ip ${cleanIp}`,
            tier: "Tier 1",
            caller,
          });
          agentDispatched = true;
        } catch (execErr) {
          console.warn("[FleetBlockedIPs] Remote agent block dispatch warning:", execErr);
        }
      }

      return NextResponse.json({
        success: true,
        message: `IP ${cleanIp} successfully blocked.`,
        agentDispatched,
      });
    }

    return NextResponse.json(
      { error: `Unsupported action: '${action}'. Supported: 'unblock_ip', 'block_ip'.` },
      { status: 400 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/blocked-ips", method: "POST" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getLiveCommandLogs } from "@/lib/fleet/liveTelemetry";
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

    const logs = await getLiveCommandLogs(caller, agentId);
    return NextResponse.json({ logs });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/logs" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const isCrossTenant = caller.role === "system_admin" || caller.role === "super_admin";
    const canDelete = isCrossTenant || caller.role === "responder";
    if (!canDelete) {
      return NextResponse.json(
        { error: "Forbidden: Administrative privileges required to purge command logs" },
        { status: 403 }
      );
    }

    const { searchParams } = new URL(req.url);
    const agentId = searchParams.get("agentId") || undefined;

    const { query } = await import("@/lib/db");
    if (agentId) {
      if (isCrossTenant) {
        await query(`DELETE FROM agent_command_logs WHERE agent_id = $1`, [agentId]);
      } else {
        await query(`DELETE FROM agent_command_logs WHERE agent_id = $1 AND tenant_id = $2`, [agentId, caller.tenant_id]);
      }
    } else {
      if (isCrossTenant) {
        await query(`DELETE FROM agent_command_logs`);
      } else {
        await query(`DELETE FROM agent_command_logs WHERE tenant_id = $1`, [caller.tenant_id]);
      }
    }
    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/logs" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

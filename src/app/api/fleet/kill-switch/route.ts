import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { triggerKillSwitch } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

export async function POST(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const agentId = body.agentId;
    const active = body.active !== undefined ? Boolean(body.active) : Boolean(body.enable);

    const { setLiveKillSwitch } = await import("@/lib/fleet/liveTelemetry");
    setLiveKillSwitch(active, caller.tenant_id);

    const result = await triggerKillSwitch({
      agentId,
      active,
      caller,
    });

    return NextResponse.json({
      ...result,
      killSwitchActive: active,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    if (msg.includes("UNAUTHORIZED_KILL_SWITCH")) {
      return NextResponse.json({ error: msg }, { status: 403 });
    }
    trackError(err, { endpoint: "/api/fleet/kill-switch" });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

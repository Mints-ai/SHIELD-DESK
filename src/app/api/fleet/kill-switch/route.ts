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
    const { agentId, active = true } = body;

    const result = await triggerKillSwitch({
      agentId,
      active: Boolean(active),
      caller,
    });

    return NextResponse.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    if (msg.includes("UNAUTHORIZED_KILL_SWITCH")) {
      return NextResponse.json({ error: msg }, { status: 403 });
    }
    trackError(err, { endpoint: "/api/fleet/kill-switch" });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

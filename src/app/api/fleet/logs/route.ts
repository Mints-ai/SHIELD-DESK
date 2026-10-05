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

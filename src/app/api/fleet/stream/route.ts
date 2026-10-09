import { NextRequest } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getLiveFleetAgents } from "@/lib/fleet/liveTelemetry";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const caller = await getSessionUser(req);
  if (!caller) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      let isClosed = false;

      const sendTick = async () => {
        if (isClosed) return;
        try {
          const agents = await getLiveFleetAgents(caller);
          const totalEps = agents.reduce((acc, a) => acc + (a.eps || 0), 0);
          const activeCount = agents.filter((a) => a.status === "connected").length;
          const anyKilled = agents.some((a) => a.kill_switch_active);

          const payload = {
            type: "telemetry_tick",
            agents,
            stats: {
              activeCount,
              totalCount: agents.length,
              totalEps,
              killSwitchActive: anyKilled,
            },
            timestamp: new Date().toISOString(),
          };

          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify(payload)}\n\n`)
          );
        } catch (err) {
          // DB unavailable — send empty fleet so the UI shows "no agents"
          const emptyPayload = {
            type: "telemetry_tick",
            agents: [],
            stats: {
              activeCount: 0,
              totalCount: 0,
              totalEps: 0,
              killSwitchActive: false,
            },
            timestamp: new Date().toISOString(),
            dbError: err instanceof Error ? err.message : "Database unavailable",
          };
          try {
            controller.enqueue(
              encoder.encode(`data: ${JSON.stringify(emptyPayload)}\n\n`)
            );
          } catch {
            isClosed = true;
          }
        }
      };

      // Send initial tick immediately
      await sendTick();

      // Interval ticker every 3000ms
      const intervalId = setInterval(async () => {
        if (req.signal.aborted || isClosed) {
          clearInterval(intervalId);
          return;
        }
        await sendTick();
      }, 3000);

      req.signal.addEventListener("abort", () => {
        isClosed = true;
        clearInterval(intervalId);
        try {
          controller.close();
        } catch {
          // Already closed
        }
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

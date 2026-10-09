import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";
import { MetricsRegistry } from "@/lib/observability/metrics";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const expected = process.env.METRICS_BEARER_TOKEN;
  if (!expected) return NextResponse.json({ error: "Metrics endpoint is not configured." }, { status: 503 });
  const presented = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return new NextResponse(MetricsRegistry.toPrometheus(), { status: 200, headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store" } });
}

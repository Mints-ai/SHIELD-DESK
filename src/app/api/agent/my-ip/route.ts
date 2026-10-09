import { NextRequest, NextResponse } from "next/server";
import { getObservedEndpointIp } from "@/lib/fleet/ipAddress";

export async function GET(req: NextRequest) {
  const ip = getObservedEndpointIp(req.headers);
  return NextResponse.json(
    { ip, source: ip ? "proxy" : "unavailable" },
    { headers: { "Cache-Control": "no-store" } }
  );
}

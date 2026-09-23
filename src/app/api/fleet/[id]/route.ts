import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent } from "@/lib/fleet/fleet";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    const { id } = await params;
    const agent = await getEndpointAgent(id, caller);

    // Anti-enumeration: returns 404 whether agent doesn't exist or is cross-tenant
    if (!agent) {
      return NextResponse.json(
        { error: "Endpoint agent not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({ agent });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

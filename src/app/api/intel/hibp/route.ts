import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getHibpApiKey, getHibpStatus } from "@/lib/hibp";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Active session required" }, { status: 401 });
  }

  const status = getHibpStatus();
  return NextResponse.json(status);
}

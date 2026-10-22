import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { getHibpApiKey, getHibpStatus } from "@/lib/hibp";

export async function GET(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  const userHdr = req.headers.get("x-shielddesk-user");
  if (!session && isDevPersonaAllowed() && userHdr) {
    session = {
      uid: userHdr,
      role: "analyst",
      tenantId: "mints-global",
      email: `${userHdr}@mintsglobal.ae`,
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized: Active session required" }, { status: 401 });
  }

  const status = getHibpStatus();
  return NextResponse.json(status);
}

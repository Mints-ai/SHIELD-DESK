import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { operatorFromSession } from "@/lib/auth/operatorIdentity";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { DEV_USERS, type DevUserId } from "@/lib/constants/devUsers";

export async function GET(req: NextRequest) {
  // Resolve the authenticated cookie/bearer identity, never a stale UI persona.
  const headers = new Headers(req.headers);
  headers.delete("x-shielddesk-user");
  const session = await getSessionFromRequest(new Request(req.url, { headers }));
  const devPersonasAllowed = isDevPersonaAllowed();
  const devUser = session && Object.hasOwn(DEV_USERS, session.uid) ? DEV_USERS[session.uid as DevUserId] : null;
  const isDevSession = Boolean(session && devPersonasAllowed && devUser && devUser.role === session.role && devUser.tenantId === session.tenantId);
  const user = session ? (isDevSession ? DEV_USERS[session.uid as DevUserId] : operatorFromSession(session)) : null;
  return NextResponse.json({ user, devPersonasAllowed: devPersonasAllowed && (!session || isDevSession) }, {
    status: session ? 200 : 401,
    headers: { "Cache-Control": "private, no-store", Vary: "Cookie, Authorization" },
  });
}

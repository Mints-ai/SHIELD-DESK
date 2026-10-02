import { NextRequest, NextResponse } from "next/server";
import { enrollEndpointAgent } from "@/lib/fleet/enrollment";
import type { OsType } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/agent/enroll
 * Endpoint for a newly installed agent daemon to register using a valid enrollment token.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { token, hostname, ipAddress, osType, agentVersion, publicKey, installationId, licenseKey } = body;

    if (!token || typeof token !== "string") {
      return NextResponse.json({ error: "Missing or invalid enrollment token" }, { status: 400 });
    }
    if (!hostname || typeof hostname !== "string") {
      return NextResponse.json({ error: "Missing hostname" }, { status: 400 });
    }

    const validOsTypes: OsType[] = ["linux", "windows", "darwin"];
    const resolvedOsType: OsType = validOsTypes.includes(osType) ? osType : "linux";

    const clientIp =
      (typeof ipAddress === "string" && ipAddress) ||
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      "127.0.0.1";

    const result = await enrollEndpointAgent({
      rawToken: token.trim(),
      hostname: hostname.trim(),
      ipAddress: clientIp,
      osType: resolvedOsType,
      agentVersion: typeof agentVersion === "string" ? agentVersion : "0.4.2",
      clientPublicKeyPem: typeof publicKey === "string" ? publicKey.trim() : undefined,
      installationId: typeof installationId === "string" ? installationId.trim() : undefined,
      licenseKey: typeof licenseKey === "string" ? licenseKey.trim() : undefined,
    });

    if (!result.success) {
      return NextResponse.json({ error: result.error }, { status: 401 });
    }

    return NextResponse.json({
      success: true,
      agentId: result.agentId,
      tenantId: result.tenantId,
      certificate: result.certificate,
      message: "Agent enrolled successfully and bound to tenant",
    });
  } catch (err: unknown) {
    trackError(err, { route: "POST /api/agent/enroll" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

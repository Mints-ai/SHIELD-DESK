import { NextResponse } from "next/server";
import { getControlPlanePublicKey } from "@/lib/fleet/commandSigning";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/agent/public-key
 * Alias endpoint for enrolled agents to retrieve the control plane RSA-2048 public key.
 */
export async function GET() {
  try {
    const publicKey = getControlPlanePublicKey();
    return NextResponse.json({
      publicKey,
      algorithm: "RSA-SHA256",
      keySize: 2048,
    });
  } catch (err) {
    trackError(err, { route: "GET /api/agent/public-key" });
    return NextResponse.json({ error: "Failed to retrieve public key" }, { status: 500 });
  }
}

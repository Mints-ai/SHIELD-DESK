import { NextResponse } from "next/server";
import { getControlPlanePublicKey } from "@/lib/fleet/commandSigning";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/fleet/public-key
 * Returns the control plane's RSA-2048 public key in PEM format
 * for remote endpoint agents to verify command signatures.
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
    trackError(err, { route: "GET /api/fleet/public-key" });
    return NextResponse.json({ error: "Failed to retrieve public key" }, { status: 500 });
  }
}

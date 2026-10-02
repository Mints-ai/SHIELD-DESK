import { NextRequest, NextResponse } from "next/server";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { verifyCommercialLicense } from "@/lib/billing/licenses";
import { getSessionFromRequest } from "@/lib/auth/session";

type Params = { params: Promise<{ operation: string }> };

export async function POST(req: NextRequest, context: Params) {
  const { operation } = await context.params;
  try {
    const body = await req.json();
    if (operation === "validate") return NextResponse.json(await LicenseActivationService.validate(body));
    if (operation === "activate") return NextResponse.json({ success: true, activation: await LicenseActivationService.activate(body) });
    if (operation === "deactivate") return NextResponse.json({ success: true, activation: await LicenseActivationService.deactivate(body) });
    if (operation === "heartbeat") return NextResponse.json({ success: true, activation: await LicenseActivationService.heartbeat(body) });
    return NextResponse.json({ error: "Unknown license operation." }, { status: 404 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "License operation failed.";
    return NextResponse.json({ error: message }, { status: 403 });
  }
}

export async function GET(req: NextRequest, context: Params) {
  const { operation } = await context.params;
  if (operation !== "status" && operation !== "entitlements") return NextResponse.json({ error: "Unknown license view." }, { status: 404 });
  const session = await getSessionFromRequest(req);
  const tenantId = session?.tenantId;
  if (!tenantId) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const installationId = req.nextUrl.searchParams.get("installationId");
  if (!installationId) return NextResponse.json({ error: "installationId is required." }, { status: 400 });
  const activation = await LicenseActivationService.get(tenantId, installationId);
  if (!activation) return NextResponse.json({ error: "Activation not found." }, { status: 404 });
  if (operation === "status") return NextResponse.json({ activation });
  const licenseKey = req.nextUrl.searchParams.get("licenseKey");
  const verified = licenseKey ? verifyCommercialLicense(licenseKey) : null;
  if (!verified?.valid || verified.payload?.tenantId !== tenantId) return NextResponse.json({ error: "A valid tenant license is required." }, { status: 403 });
  return NextResponse.json({ tenantId, licenseId: verified.payload.licenseId, state: activation.state, features: verified.payload.features, maxEndpoints: verified.payload.maxEndpoints, maxUsers: verified.payload.maxUsers });
}

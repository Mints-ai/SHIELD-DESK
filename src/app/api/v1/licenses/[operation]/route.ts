import { NextRequest, NextResponse } from "next/server";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { verifyCommercialLicense } from "@/lib/billing/licenses";
import { EntitlementService } from "@/lib/billing/entitlements";
import { getSessionFromRequest } from "@/lib/auth/session";

type Params = { params: Promise<{ operation: string }> };

export async function POST(req: NextRequest, context: Params) {
  const { operation } = await context.params;
  try {
    const body = await req.json().catch(() => ({}));
    if (operation === "validate") {
      return NextResponse.json(await LicenseActivationService.validate(body));
    }
    if (operation === "activate") {
      return NextResponse.json({ success: true, activation: await LicenseActivationService.activate(body) });
    }
    if (operation === "refresh") {
      return NextResponse.json({ success: true, ...(await LicenseActivationService.refresh(body)) });
    }
    if (operation === "deactivate") {
      return NextResponse.json({ success: true, activation: await LicenseActivationService.deactivate(body) });
    }
    if (operation === "heartbeat") {
      return NextResponse.json({ success: true, activation: await LicenseActivationService.heartbeat(body) });
    }
    if (operation === "entitlements") {
      const { licenseKey } = body;
      if (!licenseKey) {
        return NextResponse.json({ error: "licenseKey is required in POST body." }, { status: 400 });
      }
      const verified = verifyCommercialLicense(licenseKey);
      if (!verified.valid || !verified.payload) {
        return NextResponse.json({ error: `Invalid license: ${verified.reason}` }, { status: 403 });
      }
      return NextResponse.json({
        success: true,
        licenseId: verified.payload.licenseId,
        tenantId: verified.payload.tenantId,
        tier: verified.payload.tier,
        features: verified.payload.features,
        maxEndpoints: verified.payload.maxEndpoints,
        maxUsers: verified.payload.maxUsers,
        expiresAt: verified.payload.expiresAt,
      });
    }
    return NextResponse.json({ error: "Unknown license operation." }, { status: 404 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "License operation failed.";
    return NextResponse.json({ error: message }, { status: 403 });
  }
}

export async function GET(req: NextRequest, context: Params) {
  const { operation } = await context.params;
  const session = await getSessionFromRequest(req);
  const tenantId = session?.tenantId;
  if (!tenantId) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  // Security Policy: Reject raw license key in GET query parameters to prevent leakage in proxies and access logs
  if (req.nextUrl.searchParams.has("licenseKey")) {
    return NextResponse.json(
      { error: "Security Policy: Transmitting raw license keys in GET query parameters is prohibited. Use POST /api/v1/licenses/entitlements or query status." },
      { status: 400 }
    );
  }

  if (operation === "activations") {
    const activations = await LicenseActivationService.listActivations(tenantId);
    return NextResponse.json({ success: true, tenantId, activations });
  }

  if (operation !== "status" && operation !== "entitlements") {
    return NextResponse.json({ error: "Unknown license view." }, { status: 404 });
  }

  const installationId = req.nextUrl.searchParams.get("installationId");
  if (!installationId) {
    return NextResponse.json({ error: "installationId is required." }, { status: 400 });
  }

  const activation = await LicenseActivationService.get(tenantId, installationId);
  if (!activation) {
    return NextResponse.json({ error: "Activation not found." }, { status: 404 });
  }

  if (operation === "status") {
    return NextResponse.json({ activation });
  }

  const licenseState = await EntitlementService.getLicenseState(tenantId);

  return NextResponse.json({
    tenantId,
    licenseId: activation.licenseId,
    state: activation.state,
    features: licenseState.license?.features || [],
    maxEndpoints: licenseState.license?.maxEndpoints || 5,
    maxUsers: licenseState.license?.maxUsers || 3,
  });
}

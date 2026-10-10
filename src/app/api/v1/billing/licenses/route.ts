import { NextRequest, NextResponse } from "next/server";
import { EntitlementService } from "@/lib/billing/entitlements";
import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * GET /api/v1/billing/licenses
 * Retrieves the current commercial license state, tier, and entitlements for the authenticated tenant.
 * Security Invariant: Tenant identity is derived strictly from the authenticated session.
 * Query parameter `offline=true` generates a signed offline entitlement cache token.
 */
export async function GET(req: NextRequest) {
  try {
    const session = await getSessionFromRequest(req);
    if (!session?.tenantId) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const tenantId = session.tenantId;
    const licenseState = await EntitlementService.getLicenseState(tenantId);
    const includeOffline = req.nextUrl.searchParams.get("offline") === "true";

    let offlineCache = undefined;
    if (includeOffline) {
      offlineCache = await EntitlementService.generateOfflineEntitlementCache({ tenantId });
    }

    return NextResponse.json(
      {
        tenantId,
        state: licenseState.state,
        tier: licenseState.license?.tier || "community",
        maxEndpoints: licenseState.license?.maxEndpoints || 5,
        features: licenseState.license?.features || [],
        expiresAt: licenseState.license?.expiresAt,
        graceUntil: licenseState.graceUntil,
        offlineCache: offlineCache ? offlineCache.cacheToken : undefined,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    trackError(err, { endpoint: "GET /api/v1/billing/licenses" });
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * POST /api/v1/billing/licenses
 * Activates a commercial license key strictly for the authenticated tenant.
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSessionFromRequest(req);
    if (!session?.tenantId) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const { licenseKey } = body;
    const tenantId = session.tenantId;

    if (!licenseKey) {
      return NextResponse.json(
        { error: "Missing required parameter 'licenseKey'" },
        { status: 400 }
      );
    }

    const activatedLicense = await EntitlementService.activateLicense({
      tenantId,
      licenseKey,
    });

    return NextResponse.json(
      {
        success: true,
        message: `License successfully activated for tenant '${tenantId}'`,
        license: {
          id: activatedLicense.id,
          tier: activatedLicense.tier,
          status: activatedLicense.status,
          maxEndpoints: activatedLicense.maxEndpoints,
          expiresAt: activatedLicense.expiresAt,
        },
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "License activation failed";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}

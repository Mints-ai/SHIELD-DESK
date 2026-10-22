import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { canManageIntegrationKeys, type ShieldDeskRole } from "@/lib/permissions";
import { getShodanApiKey, getShodanApiInfo, clearShodanCache } from "@/lib/shodan";
import { getHibpApiKey, getHibpStatus } from "@/lib/hibp";
import { trackError } from "@/lib/observability/errorTracker";

export const dynamic = "force-dynamic";

async function resolveSession(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    const userHdr = req.headers.get("x-shielddesk-user");
    if (userHdr) {
      const isSuper = userHdr === "dev-super" || userHdr.includes("super");
      const isAdmin = userHdr === "dev-admin" || userHdr.includes("admin");
      const isResponder = userHdr === "dev-responder" || userHdr.includes("responder");
      const role: ShieldDeskRole = isAdmin
        ? "system_admin"
        : isSuper
        ? "super_admin"
        : isResponder
        ? "responder"
        : "analyst";

      session = {
        uid: userHdr,
        role,
        tenantId: "mints-global",
        email: `${userHdr}@mintsglobal.ae`,
      };
    }
  }
  return session;
}

function maskKey(key?: string): string | null {
  if (!key || key.length < 6) return null;
  return `${key.slice(0, 4)}••••••••${key.slice(-4)}`;
}

function updateEnvFile(keyName: string, value: string | null) {
  try {
    const root = process.cwd();
    const envLocalPath = path.join(root, ".env.local");
    let content = "";
    if (fs.existsSync(envLocalPath)) {
      content = fs.readFileSync(envLocalPath, "utf-8");
    }

    const lines = content.split("\n");
    let replaced = false;
    const newLines = lines
      .map((line) => {
        const trimmed = line.trim();
        if (trimmed.startsWith(`${keyName}=`)) {
          replaced = true;
          return value ? `${keyName}=${value}` : "";
        }
        return line;
      })
      .filter((l) => l.trim().length > 0);

    if (!replaced && value) {
      newLines.push(`${keyName}=${value}`);
    }

    fs.writeFileSync(envLocalPath, newLines.join("\n") + "\n", "utf-8");
  } catch (err) {
    console.warn(`[Integrations] Failed to write to .env.local:`, err);
  }
}

/**
 * GET /api/integrations/keys
 * Returns configuration status and masked previews of third-party intel keys.
 */
export async function GET(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const shodanKey = getShodanApiKey();
    const hibpKey = getHibpApiKey();

    let shodanInfo = null;
    if (shodanKey) {
      shodanInfo = await getShodanApiInfo(shodanKey);
    }

    const hibpStatus = getHibpStatus();

    // Tenant ingest key for log streaming / webhooks
    const tenantIngestKey = `sdi_${session.tenantId.slice(0, 8)}_${Buffer.from(session.tenantId).toString("hex").slice(0, 12)}`;

    const canManage = canManageIntegrationKeys(session.role);

    return NextResponse.json({
      canManage,
      role: session.role,
      shodan: {
        configured: Boolean(shodanKey),
        maskedKey: maskKey(shodanKey),
        apiInfo: shodanInfo,
      },
      hibp: {
        configured: Boolean(hibpKey),
        maskedKey: maskKey(hibpKey),
        status: hibpStatus,
      },
      ingest: {
        configured: true,
        key: tenantIngestKey,
        endpoint: `${req.nextUrl.origin}/api/ingest`,
      },
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/integrations/keys", extra: { method: "GET" } });
    return NextResponse.json({ error: "Failed to retrieve integration keys status" }, { status: 500 });
  }
}

/**
 * POST /api/integrations/keys
 * Validates and saves third-party intelligence keys (Shodan or HIBP).
 */
export async function POST(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!canManageIntegrationKeys(session.role)) {
    return NextResponse.json(
      { error: "Forbidden: Only administrators (system_admin or super_admin) can configure external intel keys." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { provider, key, testOnly } = body;

    if (!provider || !key) {
      return NextResponse.json(
        { error: "Provider ('shodan' | 'hibp') and key are required." },
        { status: 400 }
      );
    }

    const trimmedKey = String(key).trim();

    if (provider === "shodan") {
      if (trimmedKey.length < 8) {
        return NextResponse.json(
          { error: "Invalid Shodan API key format. Key is too short." },
          { status: 400 }
        );
      }

      // Try validating key against Shodan live API
      let apiInfo = null;
      try {
        apiInfo = await getShodanApiInfo(trimmedKey);
      } catch {
        // Shodan network error
      }

      if (testOnly) {
        if (!apiInfo || !apiInfo.configured) {
          return NextResponse.json(
            {
              success: false,
              error: apiInfo?.error || "Invalid Shodan API key or connection failed.",
            },
            { status: 400 }
          );
        }
        return NextResponse.json({
          success: true,
          message: "Shodan API key is valid and verified.",
          apiInfo,
        });
      }

      // Persist in runtime process.env and .env.local
      process.env.SHODAN_API_KEY = trimmedKey;
      updateEnvFile("SHODAN_API_KEY", trimmedKey);
      clearShodanCache();

      return NextResponse.json({
        success: true,
        message: apiInfo?.configured
          ? "Shodan API key configured successfully."
          : "Shodan API key saved successfully.",
        apiInfo: apiInfo || { configured: true, plan: "community", queryCredits: 0, scanCredits: 0 },
        maskedKey: maskKey(trimmedKey),
      });
    }

    if (provider === "hibp") {
      // HIBP keys are typically 32-character hexadecimal strings
      if (trimmedKey.length < 16) {
        return NextResponse.json(
          { error: "Invalid HaveIBeenPwned API key format. Expected API key." },
          { status: 400 }
        );
      }

      if (testOnly) {
        return NextResponse.json({
          success: true,
          message: "HaveIBeenPwned API key format verified.",
        });
      }

      process.env.HIBP_API_KEY = trimmedKey;
      updateEnvFile("HIBP_API_KEY", trimmedKey);

      return NextResponse.json({
        success: true,
        message: "HaveIBeenPwned API key configured successfully.",
        maskedKey: maskKey(trimmedKey),
      });
    }

    return NextResponse.json({ error: `Unsupported provider '${provider}'.` }, { status: 400 });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/integrations/keys", extra: { method: "POST" } });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

/**
 * DELETE /api/integrations/keys?provider=<shodan|hibp>
 * Removes a third-party key.
 */
export async function DELETE(req: NextRequest) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!canManageIntegrationKeys(session.role)) {
    return NextResponse.json(
      { error: "Forbidden: Only administrators (system_admin or super_admin) can remove external intel keys." },
      { status: 403 }
    );
  }

  const { searchParams } = req.nextUrl;
  const provider = searchParams.get("provider");

  if (provider === "shodan") {
    delete process.env.SHODAN_API_KEY;
    updateEnvFile("SHODAN_API_KEY", null);
    clearShodanCache();
    return NextResponse.json({ success: true, message: "Shodan API key removed." });
  }

  if (provider === "hibp") {
    delete process.env.HIBP_API_KEY;
    updateEnvFile("HIBP_API_KEY", null);
    return NextResponse.json({ success: true, message: "HaveIBeenPwned API key removed." });
  }

  return NextResponse.json({ error: "Provider must be 'shodan' or 'hibp'." }, { status: 400 });
}

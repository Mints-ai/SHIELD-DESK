import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getShodanApiKey, getShodanApiInfo } from "@/lib/shodan";
import { getHibpApiKey, getHibpStatus } from "@/lib/hibp";
import { trackError } from "@/lib/observability/errorTracker";

export const dynamic = "force-dynamic";

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
  const session = await getSessionFromRequest(req);
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

    return NextResponse.json({
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
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
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
      // 1. Validate key against Shodan live API
      const apiInfo = await getShodanApiInfo(trimmedKey);
      if (!apiInfo.configured) {
        return NextResponse.json(
          {
            success: false,
            error: apiInfo.error || "Invalid Shodan API key or connection failed.",
          },
          { status: 400 }
        );
      }

      if (testOnly) {
        return NextResponse.json({
          success: true,
          message: "Shodan API key is valid and verified.",
          apiInfo,
        });
      }

      // Persist in runtime process.env and .env.local
      process.env.SHODAN_API_KEY = trimmedKey;
      updateEnvFile("SHODAN_API_KEY", trimmedKey);

      return NextResponse.json({
        success: true,
        message: "Shodan API key configured successfully.",
        apiInfo,
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
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = req.nextUrl;
  const provider = searchParams.get("provider");

  if (provider === "shodan") {
    delete process.env.SHODAN_API_KEY;
    updateEnvFile("SHODAN_API_KEY", null);
    return NextResponse.json({ success: true, message: "Shodan API key removed." });
  }

  if (provider === "hibp") {
    delete process.env.HIBP_API_KEY;
    updateEnvFile("HIBP_API_KEY", null);
    return NextResponse.json({ success: true, message: "HaveIBeenPwned API key removed." });
  }

  return NextResponse.json({ error: "Provider must be 'shodan' or 'hibp'." }, { status: 400 });
}

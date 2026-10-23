import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import {
  getShodanApiKey,
  getShodanApiInfo,
  getMyPublicIp,
  inspectHost,
} from "@/lib/shodan";
import dns from "dns";

export async function GET(req: NextRequest) {
  try {
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

    const key = getShodanApiKey();
    if (!key) {
      return NextResponse.json({
        configured: false,
        message: "SHODAN_API_KEY is not set in environment or .env.local file.",
      });
    }

    let apiInfo = await getShodanApiInfo(key).catch(() => null);
    if (!apiInfo || !apiInfo.configured) {
      apiInfo = {
        configured: true,
        plan: apiInfo?.plan || "community",
        queryCredits: apiInfo?.queryCredits ?? 0,
        scanCredits: apiInfo?.scanCredits ?? 0,
        error: apiInfo?.error,
      };
    }

    const searchParams = req.nextUrl.searchParams;
    const requestedIp = searchParams.get("ip");

    let myIp: string | null = null;
    let hostData = null;

    if (requestedIp) {
      hostData = await inspectHost(requestedIp, key);
    } else {
      myIp = await getMyPublicIp(key);
    }

    return NextResponse.json({
      configured: true,
      apiInfo,
      myIp,
      hostData,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || "Failed to process Shodan request" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
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

    const key = getShodanApiKey();
    if (!key) {
      return NextResponse.json(
        {
          configured: false,
          error: "SHODAN_API_KEY is not configured in your environment.",
        },
        { status: 400 }
      );
    }

    const body = await req.json().catch(() => ({}));
    let target = (body.ip || body.target || "").trim();

    // If no target provided, try to detect public IP
    if (!target) {
      const detected = await getMyPublicIp(key);
      if (detected) {
        target = detected;
      } else {
        return NextResponse.json(
          { error: "No target IP or hostname provided." },
          { status: 400 }
        );
      }
    }

    // If target is a hostname / domain, resolve it
    let resolvedIp = target;
    const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
    const isIpv6 = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(target);

    if (!isIpv4 && !isIpv6) {
      try {
        const lookup = await dns.promises.lookup(target);
        resolvedIp = lookup.address;
      } catch (err: any) {
        return NextResponse.json(
          { error: `Unable to resolve host '${target}': ${err.message}` },
          { status: 400 }
        );
      }
    }

    const inspection = await inspectHost(resolvedIp, key);
    return NextResponse.json({
      configured: true,
      target,
      resolvedIp,
      inspection,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || "Failed to inspect target host on Shodan" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import {
  getShodanApiKey,
  getShodanApiInfo,
  getMyPublicIp,
  inspectHost,
} from "@/lib/shodan";
import dns from "dns";

export async function GET(req: NextRequest) {
  try {
    const key = getShodanApiKey();
    if (!key) {
      return NextResponse.json({
        configured: false,
        message: "SHODAN_API_KEY is not set in environment or .env.local file.",
      });
    }

    const apiInfo = await getShodanApiInfo(key);
    if (!apiInfo.configured) {
      return NextResponse.json({
        configured: false,
        apiInfo,
        error: apiInfo.error || "Failed to validate Shodan API key.",
      });
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

import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import { getInternalServiceKey, createAdminAssertionToken } from "@/lib/auth/internalKeys";

export const dynamic = "force-dynamic";

const CVE_AI_ENGINE_URL = process.env.CVE_AI_ENGINE_URL || process.env.PYTHON_AI_SERVICE_URL || "http://localhost:8000";

/**
 * POST /api/intel/sync
 * Triggers live CVE threat intelligence feed synchronization.
 * Strictly gated by RBAC: only 'system_admin' and 'super_admin' roles have the 'intel.sync' permission.
 * Analysts and Responders receive a 403 Forbidden response.
 */
export async function POST(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    const headerUser = req.headers.get("x-shielddesk-user") || req.headers.get("X-ShieldDesk-User");
    if (headerUser) {
      if (headerUser === "dev-system-admin" || headerUser === "dev-admin") {
        session = {
          uid: headerUser,
          role: "system_admin",
          tenantId: "mints-global",
          email: "system-admin@mintsglobal.ae",
        };
      } else if (headerUser === "dev-super-admin" || headerUser === "dev-super") {
        session = {
          uid: headerUser,
          role: "super_admin",
          tenantId: "mints-global",
          email: "super-admin@mintsglobal.ae",
        };
      } else if (headerUser === "dev-responder") {
        session = {
          uid: "dev-responder",
          role: "responder",
          tenantId: "mints-global",
          email: "responder@mintsglobal.ae",
        };
      } else if (headerUser === "dev-analyst") {
        session = {
          uid: "dev-analyst",
          role: "analyst",
          tenantId: "mints-global",
          email: "analyst@mintsglobal.ae",
        };
      }
    }
  }

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Strict RBAC gate: Only roles with 'intel.sync' permission (system_admin and super_admin) are permitted.
  if (!hasPermission(session.role, "intel.sync")) {
    return NextResponse.json(
      {
        error: "Forbidden",
        message: `Role '${session.role}' is not authorized to trigger live threat intelligence synchronization. Required permission: intel.sync (system_admin or super_admin only).`,
      },
      { status: 403 }
    );
  }

  // Strict Internal Key & Administrator Assertion resolution: fail closed in production
  let internalKey: string;
  let adminAssertion: string;
  try {
    internalKey = getInternalServiceKey();
    adminAssertion = createAdminAssertionToken({
      operatorId: session.uid,
      role: session.role,
      operation: "intel_sync",
      ttlSeconds: 300,
    });
  } catch (configErr: any) {
    return NextResponse.json(
      { error: "Configuration Error", details: configErr.message },
      { status: 500 }
    );
  }

  try {
    const res = await fetch(`${CVE_AI_ENGINE_URL}/api/intel/sync`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": internalKey,
        "X-ShieldDesk-Admin-Assertion": adminAssertion,
        "X-ShieldDesk-Operator-Id": session.uid,
        "X-ShieldDesk-Operator-Role": session.role,
      },
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: "CVE AI Engine sync failed", details: errData },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json({
      success: true,
      message: "Live CVE threat intelligence synchronization completed successfully.",
      synced_by: {
        uid: session.uid,
        role: session.role,
      },
      data,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: "Failed to communicate with CVE AI Engine microservice", details: err.message },
      { status: 502 }
    );
  }
}

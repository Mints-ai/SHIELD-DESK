import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { RootCauseGroupingEngine } from "@/lib/verification-engine/rootCauseGrouping";
import { FindingInput } from "@/lib/verification-engine/types";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.read") && !canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const limit = searchParams.get("limit") ? parseInt(searchParams.get("limit")!, 10) : 50;

    const plans = await RootCauseGroupingEngine.getPlansByTenant(session.tenantId, limit);
    return NextResponse.json({ tenantId: session.tenantId, plansCount: plans.length, plans }, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.mitigate") && !canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const body = await request.json().catch(() => ({}));
    let findings: FindingInput[] = Array.isArray(body.findings) ? body.findings : [];

    // If findings are not directly provided, query asset_vulnerabilities for the tenant
    if (findings.length === 0) {
      try {
        const { query } = await import("@/lib/db");
        let sql = `SELECT id, asset_id, asset_hostname, cve_id, package_name, installed_version, fixed_version, cvss_score, epss_score, kev_listed, vendor_severity as severity
                   FROM asset_vulnerabilities
                   WHERE tenant_id = $1 AND status = 'open'`;
        const params: any[] = [session.tenantId];

        if (body.assetId) {
          params.push(body.assetId);
          sql += ` AND asset_id = $${params.length}`;
        }

        sql += ` LIMIT 200`;
        const dbRes = await query<any>(sql, params);
        findings = dbRes.rows.map((r: any) => ({
          id: r.id,
          assetId: r.asset_id || r.asset_hostname,
          assetHostname: r.asset_hostname,
          cveId: r.cve_id,
          packageName: r.package_name,
          installedVersion: r.installed_version,
          fixedVersion: r.fixed_version,
          cvssScore: r.cvss_score ? Number(r.cvss_score) : undefined,
          epssScore: r.epss_score ? Number(r.epss_score) : undefined,
          kevListed: Boolean(r.kev_listed),
          severity: r.severity,
        }));
      } catch {
        // Mock fallback if DB is empty or unreachable
      }
    }

    if (findings.length === 0) {
      return NextResponse.json(
        { message: "No active findings found to simulate remediation for.", plans: [] },
        { status: 200 }
      );
    }

    // Run root cause grouping and simulation
    const plans = RootCauseGroupingEngine.groupFindingsAndSimulate(findings, session.tenantId);

    // Persist plans if requested or by default
    if (body.persist !== false) {
      await RootCauseGroupingEngine.persistPlans(plans);
    }

    return NextResponse.json(
      {
        tenantId: session.tenantId,
        totalFindingsInput: findings.length,
        plansCount: plans.length,
        plans,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { query } from "@/lib/db";
import { trackError } from "@/lib/observability/errorTracker";
import { isDemoModeActive } from "@/lib/config/environment";
import crypto from "crypto";

export interface MitigationTaskRecord {
  id: string;
  plan_id: string;
  tenant_id: string;
  horizon: "immediate" | "short_term" | "long_term";
  title: string;
  description: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  status: "pending" | "approved" | "rejected" | "in_progress" | "completed";
  blast_radius?: string | null;
  cve_id?: string | null;
  incident_code?: string;
  created_at: string;
}

// In-memory demo store for when database is offline or in test mode
const DEMO_STORED_TASKS: Record<string, MitigationTaskRecord[]> = {
  "acme-tenant": [
    {
      id: "t1111111-1111-1111-1111-111111111111",
      plan_id: "p1111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      horizon: "immediate",
      title: "Isolate affected host FIN-WS-042",
      description: "Quarantine endpoint network interface to halt lateral movement toward database server",
      tier: "Tier 2",
      status: "pending",
      blast_radius: "Workstation FIN-WS-042 (Finance Subnet)",
      incident_code: "INC-1042",
      created_at: new Date(Date.now() - 3600000).toISOString(),
    },
    {
      id: "t2222222-2222-2222-2222-222222222222",
      plan_id: "p1111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      horizon: "immediate",
      title: "Revoke exposed user and administrative credentials",
      description: "Terminate active session tokens for compromised user accounts",
      tier: "Tier 1",
      status: "completed",
      blast_radius: "User Sessions",
      incident_code: "INC-1042",
      created_at: new Date(Date.now() - 7200000).toISOString(),
    },
    {
      id: "t3333333-3333-3333-3333-333333333333",
      plan_id: "p1111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      horizon: "short_term",
      title: "Deploy vendor patch for CVE-2020-6240",
      description: "Apply SAP Security Notes to resolve NetWeaver DoS vulnerability",
      tier: "Tier 2",
      status: "approved",
      blast_radius: "Finance Subnet Application Servers",
      cve_id: "CVE-2020-6240",
      incident_code: "INC-1042",
      created_at: new Date(Date.now() - 10800000).toISOString(),
    },
    {
      id: "t4444444-4444-4444-4444-444444444444",
      plan_id: "p1111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      horizon: "long_term",
      title: "Implement zero-trust microsegmentation",
      description: "Enforce strict firewall ACLs between general workstations and financial database tier",
      tier: "Tier 2",
      status: "pending",
      blast_radius: "Entire Finance Zone",
      incident_code: "INC-1042",
      created_at: new Date(Date.now() - 14400000).toISOString(),
    },
    {
      id: "t5555555-5555-5555-5555-555555555555",
      plan_id: "p1111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      horizon: "immediate",
      title: "Block outbound egress to suspicious domain",
      description: "Add DNS filter entry for newly registered domain detected in INC-1031",
      tier: "Tier 1",
      status: "completed",
      blast_radius: "Perimeter Gateway",
      incident_code: "INC-1031",
      created_at: new Date(Date.now() - 18000000).toISOString(),
    },
  ],
  "globex-tenant": [],
};

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const planId = searchParams.get("planId");
  const horizon = searchParams.get("horizon");
  const status = searchParams.get("status");

  try {
    const isCrossTenant = canAccess(session.role, "VIEW_CROSS_TENANT");
    let querySql = `
      SELECT t.id, t.plan_id, t.tenant_id, t.horizon, t.title, t.description,
             t.tier, t.status, t.blast_radius, t.cve_id, t.created_at,
             i.incident_code
      FROM mitigation_tasks t
      LEFT JOIN mitigation_plans p ON p.id = t.plan_id
      LEFT JOIN incidents i ON i.id = p.incident_id
      WHERE 1=1
    `;
    const params: unknown[] = [];

    if (!isCrossTenant) {
      params.push(session.tenantId);
      querySql += ` AND t.tenant_id = $${params.length}`;
    }

    if (planId) {
      params.push(planId);
      querySql += ` AND t.plan_id = $${params.length}`;
    }

    if (horizon && horizon !== "all") {
      params.push(horizon);
      querySql += ` AND t.horizon = $${params.length}`;
    }

    if (status && status !== "all") {
      params.push(status);
      querySql += ` AND t.status = $${params.length}`;
    }

    querySql += " ORDER BY t.created_at DESC";

    const res = await query<MitigationTaskRecord>(querySql, params);
    return NextResponse.json({
      tasks: res.rows,
      count: res.rows.length,
      tenantId: session.tenantId,
      _source: "database",
    });
  } catch (err) {
    // If DB is offline, fall back safely if demo mode is permitted
    if (isDemoModeActive()) {
      let tenantTasks = DEMO_STORED_TASKS[session.tenantId] || [];
      if (planId) {
        tenantTasks = tenantTasks.filter((t) => t.plan_id === planId);
      }
      if (horizon && horizon !== "all") {
        tenantTasks = tenantTasks.filter((t) => t.horizon === horizon);
      }
      if (status && status !== "all") {
        tenantTasks = tenantTasks.filter((t) => t.status === status);
      }
      return NextResponse.json({
        tasks: tenantTasks,
        count: tenantTasks.length,
        tenantId: session.tenantId,
        _source: "demo_fallback",
      });
    }

    trackError(err, {
      endpoint: "/api/tasks",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json(
      { error: "Failed to retrieve mitigation tasks from database" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Validate permission: Viewer cannot draft remediation tasks
  if (session.role === "viewer") {
    return NextResponse.json(
      { error: "Insufficient permissions to draft mitigation tasks" },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const description = typeof body.description === "string" ? body.description.trim() : "Custom task";
    const horizon = ["immediate", "short_term", "long_term"].includes(body.horizon)
      ? body.horizon
      : "immediate";
    const tier = ["Tier 0", "Tier 1", "Tier 2", "Tier 3"].includes(body.tier)
      ? body.tier
      : "Tier 2";
    const blastRadius = typeof body.blastRadius === "string" ? body.blastRadius : "Host Scope";
    const cveId = typeof body.cveId === "string" ? body.cveId : null;

    if (!title) {
      return NextResponse.json({ error: "Task title is required" }, { status: 400 });
    }

    const taskId = crypto.randomUUID();
    let planId = body.planId;

    // If no planId specified, attempt to associate with the tenant's active plan
    if (!planId) {
      try {
        const planRes = await query<{ id: string }>(
          "SELECT id FROM mitigation_plans WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
          [session.tenantId]
        );
        if (planRes.rows.length > 0) {
          planId = planRes.rows[0].id;
        } else {
          // Create default plan if none exists for this tenant
          const newPlanId = crypto.randomUUID();
          await query(
            `INSERT INTO mitigation_plans (id, incident_id, tenant_id, version, status, summary)
             VALUES ($1, '11111111-1111-1111-1111-111111111111', $2, 1, 'active', 'Tenant Remediation Plan')`,
            [newPlanId, session.tenantId]
          );
          planId = newPlanId;
        }
      } catch {
        planId = "p1111111-1111-1111-1111-111111111111";
      }
    }

    try {
      const insertSql = `
        INSERT INTO mitigation_tasks (
          id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, cve_id, created_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, NOW()
        )
        RETURNING id, plan_id, tenant_id, horizon, title, description, tier, status, blast_radius, cve_id, created_at
      `;
      const res = await query<MitigationTaskRecord>(insertSql, [
        taskId,
        planId,
        session.tenantId,
        horizon,
        title,
        description,
        tier,
        blastRadius,
        cveId,
      ]);

      return NextResponse.json({
        success: true,
        task: res.rows[0],
        _source: "database",
      });
    } catch (dbErr) {
      if (isDemoModeActive()) {
        const newTask: MitigationTaskRecord = {
          id: taskId,
          plan_id: planId || "p1111111-1111-1111-1111-111111111111",
          tenant_id: session.tenantId,
          horizon: horizon as MitigationTaskRecord["horizon"],
          title,
          description,
          tier: tier as MitigationTaskRecord["tier"],
          status: "pending",
          blast_radius: blastRadius,
          cve_id: cveId,
          incident_code: "INC-1042",
          created_at: new Date().toISOString(),
        };

        if (!DEMO_STORED_TASKS[session.tenantId]) {
          DEMO_STORED_TASKS[session.tenantId] = [];
        }
        DEMO_STORED_TASKS[session.tenantId].unshift(newTask);

        return NextResponse.json({
          success: true,
          task: newTask,
          _source: "demo_fallback",
        });
      }

      trackError(dbErr, {
        endpoint: "/api/tasks (POST)",
        userId: session.uid,
        tenantId: session.tenantId,
      });
      return NextResponse.json(
        { error: "Failed to persist mitigation task" },
        { status: 500 }
      );
    }
  } catch (err) {
    trackError(err, {
      endpoint: "/api/tasks (POST payload)",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    return NextResponse.json({ error: "Malformed task request payload" }, { status: 400 });
  }
}

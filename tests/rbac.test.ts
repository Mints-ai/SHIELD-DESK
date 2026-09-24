import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  getIncidents,
  investigateIncident,
  generateMitigationPlan,
  simulateBlastRadius,
  getMitigationPlan,
} from "@/lib/tools";
import { canAccess, canExecuteTool } from "@/lib/permissions";
import type { ChatSession } from "@/lib/auth/session";

describe("ShieldDesk Multi-Tenant RBAC & Isolation Suite", () => {
  const acmeAnalyst: ChatSession = {
    uid: "dev-analyst",
    role: "user",
    tenantId: "acme-tenant",
  };

  const globexAnalyst: ChatSession = {
    uid: "dev-other",
    role: "user",
    tenantId: "globex-tenant",
  };

  const systemAdmin: ChatSession = {
    uid: "dev-admin",
    role: "system_admin",
    tenantId: "acme-tenant",
  };

  it("FR-1: dev-analyst can retrieve Acme incidents", async () => {
    const res = await getIncidents(acmeAnalyst, { severity: "critical" });
    assert.ok(res.incidents, "Incidents array should be returned");
    assert.ok(res.incidents.length > 0, "Should return at least one critical incident for Acme");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const codes = res.incidents.map((i: any) => i.incident_code);
    assert.ok(codes.includes("INC-1042"), "INC-1042 should be visible to Acme analyst");
  });

  it("FR-1: dev-other (Globex) cannot see Acme incidents (Tenant Isolation)", async () => {
    const res = await getIncidents(globexAnalyst, { severity: "critical" });
    assert.ok(res.incidents, "Incidents array should be returned");
    assert.strictEqual(
      res.incidents.length,
      0,
      "Globex analyst must not see any Acme Corp incidents"
    );
  });

  it("FR-2: Anti-enumeration 404 — dev-other investigating INC-1042 receives 'not_found', never 403", async () => {
    const res = await investigateIncident(globexAnalyst, { incidentId: "INC-1042" });
    assert.ok("error" in res, "Should return error");
    assert.strictEqual(
      res.error,
      "not_found",
      "Must return 'not_found' (404 anti-enumeration) rather than 'forbidden' (403)"
    );
  });

  it("FR-1: dev-analyst can investigate Acme's INC-1042 with full timeline & assets", async () => {
    const res = await investigateIncident(acmeAnalyst, { incidentId: "INC-1042" });
    assert.ok(!("error" in res), "Investigation should succeed for authorized tenant");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = res as any;
    assert.strictEqual(data.incident.incidentCode, "INC-1042");
    assert.strictEqual(data.incident.severity, "critical");
    assert.ok(Array.isArray(data.events), "Events array should be present");
    assert.ok(Array.isArray(data.affectedAssets), "Affected assets array should be present");
  });

  it("FR-1: system_admin with VIEW_CROSS_TENANT can view cross-tenant incidents", async () => {
    assert.ok(
      canAccess(systemAdmin.role, "VIEW_CROSS_TENANT"),
      "system_admin should possess VIEW_CROSS_TENANT permission"
    );
    const res = await investigateIncident(systemAdmin, { incidentId: "INC-1042" });
    assert.ok(!("error" in res), "system_admin should access incident across tenant boundary");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.strictEqual((res as any).incident.incidentCode, "INC-1042");
  });

  it("RBAC Tool Gating: canExecuteTool enforces principle of least privilege", () => {
    // Analyst / standard user
    assert.strictEqual(canExecuteTool("user", "getIncidents"), true);
    assert.strictEqual(canExecuteTool("user", "investigateIncident"), true);
    assert.strictEqual(canExecuteTool("user", "analyzeCve"), true);
    assert.strictEqual(canExecuteTool("user", "generateMitigationPlan"), true);

    // Viewer role
    assert.strictEqual(canExecuteTool("viewer", "getIncidents"), true);
    assert.strictEqual(canExecuteTool("viewer", "analyzeCve"), true);
    assert.strictEqual(canExecuteTool("viewer", "simulateBlastRadius"), true);
    assert.strictEqual(canExecuteTool("viewer", "investigateIncident"), false);
    assert.strictEqual(canExecuteTool("viewer", "generateMitigationPlan"), false);

    // Unknown tool
    assert.strictEqual(canExecuteTool("system_admin", "unknownDestructiveTool"), false);
  });

  it("Priority 1: simulateBlastRadius computes downstream dependencies, posture delta, and isolation (Globex Analyst only)", async () => {
    // 1. Authorization Gate: Non-Globex analyst (Acme) must be rejected
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const blockedAcme: any = await simulateBlastRadius(acmeAnalyst, { cveId: "CVE-2024-6387" });
    assert.ok("error" in blockedAcme, "Acme analyst must be denied blast radius simulation");
    assert.strictEqual(blockedAcme.error, "not_authorized", "Must return not_authorized error for Acme analyst");

    // 2. Blast radius simulation succeeds for authorized Globex Analyst
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cveRes: any = await simulateBlastRadius(globexAnalyst, { cveId: "CVE-2024-6387" });
    assert.ok(cveRes.simulation, "Simulation object must be returned for Globex analyst");
    assert.strictEqual(cveRes.simulation.target_cve, "CVE-2024-6387");
    assert.ok(cveRes.simulation.downstream_dependencies.length >= 2, "Must identify downstream dependencies");
    assert.ok(cveRes.simulation.posture_downgrade, "Must calculate posture downgrade");
    assert.ok(cveRes.simulation.compliance_impact.length > 0, "Must calculate compliance impact");
    assert.strictEqual(cveRes.simulation.layers.length, 4, "Must return 4 architectural layers");
    assert.strictEqual(cveRes.simulation.layers[0].layer, "Initial Vector");
    assert.strictEqual(cveRes.simulation.layers[1].layer, "Process Layer");
    assert.strictEqual(cveRes.simulation.layers[2].layer, "Host System");
    assert.strictEqual(cveRes.simulation.layers[3].layer, "Network Layer");

    // 2b. Validate specialized CVE-2007-4475 matches exact expected visual table
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sapRes: any = await simulateBlastRadius(globexAnalyst, { cveId: "CVE-2007-4475" });
    assert.ok(sapRes.simulation, "Must simulate CVE-2007-4475");
    assert.strictEqual(sapRes.simulation.layers[0].damage_level, "Critical");
    assert.strictEqual(sapRes.simulation.layers[1].damage_level, "High");
    assert.strictEqual(sapRes.simulation.layers[2].damage_level, "Medium");
    assert.strictEqual(sapRes.simulation.layers[3].damage_level, "Low-to-Medium");
    assert.ok(sapRes.simulation.layers[0].scope.includes("SaveViewToSessionFile"));

    // 2c. Validate dynamic synthesis on arbitrary CVE
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dynRes: any = await simulateBlastRadius(globexAnalyst, { cveId: "CVE-2023-9999" });
    assert.ok(dynRes.simulation, "Must simulate dynamic arbitrary CVE");
    assert.strictEqual(dynRes.simulation.layers.length, 4);

    // 3. Tenant Isolation: Globex user cannot simulate blast radius on Acme's INC-1042
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const blockedRes: any = await simulateBlastRadius(globexAnalyst, { incidentId: "INC-1042" });
    assert.ok("error" in blockedRes, "Globex analyst must be denied access to Acme incident");
    assert.strictEqual(blockedRes.error, "not_found", "Must return 404 anti-enumeration");
  });

  it("Priority 1: generateMitigationPlan persists plan and returns tracked planId & planUrl", async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res: any = await generateMitigationPlan(acmeAnalyst, { incidentId: "INC-1042" });
    assert.ok(!("error" in res), "Should successfully generate plan");
    assert.ok(res.planId, "Must return tracked planId");
    assert.ok(res.planUrl, "Must return direct URL to plan viewer");
    assert.ok(res.tasks.length >= 3, "Must contain tasks across multiple horizons");
    assert.ok(res.governanceNote.includes("analyst approval"), "Must include human governance notice");
  });

  it("Priority 1: getMitigationPlan enforces tenant isolation with anti-enumeration 404", async () => {
    // Acme analyst queries seeded Acme plan
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const acmeRes: any = await getMitigationPlan(acmeAnalyst, {
      planId: "p1111111-1111-1111-1111-111111111111",
    });
    assert.ok(!("error" in acmeRes), "Acme analyst should access Acme plan");
    assert.strictEqual(acmeRes.plan.tenant_id, "acme-tenant");
    assert.ok(acmeRes.tasks.length > 0, "Tasks should be present in plan");

    // Globex analyst queries the same Acme plan -> MUST return 'not_found' (404)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const globexRes: any = await getMitigationPlan(globexAnalyst, {
      planId: "p1111111-1111-1111-1111-111111111111",
    });
    assert.ok("error" in globexRes, "Globex analyst must be denied");
    assert.strictEqual(
      globexRes.error,
      "not_found",
      "Must return anti-enumeration 404 ('not_found'), never 403"
    );

    // dev-admin (cross-tenant) can view
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const adminRes: any = await getMitigationPlan(systemAdmin, {
      planId: "p1111111-1111-1111-1111-111111111111",
    });
    assert.ok(!("error" in adminRes), "system_admin should access plan across tenants");
  });
});


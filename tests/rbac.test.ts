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
import type { ChatSession } from "@/lib/tools";
import { canAccess, canExecuteTool } from "@/lib/permissions";

describe("ShieldDesk Multi-Tenant RBAC & Isolation Suite", () => {
  const acmeAnalyst: ChatSession = {
    uid: "dev-analyst",
    role: "analyst",
    tenantId: "acme-tenant",
  };

  const globexAnalyst: ChatSession = {
    uid: "dev-other",
    role: "analyst",
    tenantId: "globex-tenant",
  };

  const systemAdmin: ChatSession = {
    uid: "dev-admin",
    role: "system_admin",
    tenantId: "acme-tenant",
  };

  it("does not return demo incidents when the database is unavailable", async () => {
    await assert.rejects(
      getIncidents(acmeAnalyst, { severity: "critical" }),
      /DATABASE_URL is not set/
    );
  });

  it("does not return demo incidents to another tenant when the database is unavailable", async () => {
    await assert.rejects(
      getIncidents(globexAnalyst, { severity: "critical" }),
      /DATABASE_URL is not set/
    );
  });

  it("does not investigate demo incidents when the database is unavailable", async () => {
    await assert.rejects(
      investigateIncident(globexAnalyst, { incidentId: "INC-1042" }),
      /DATABASE_URL is not set/
    );
  });

  it("does not bypass database availability for a cross-tenant administrator", async () => {
    assert.ok(canAccess(systemAdmin.role, "VIEW_CROSS_TENANT"));
    await assert.rejects(
      investigateIncident(systemAdmin, { incidentId: "INC-1042" }),
      /DATABASE_URL is not set/
    );
  });

  it("RBAC Tool Gating: canExecuteTool enforces principle of least privilege", () => {
    // Analyst: read-only investigation and CVE analysis, cannot generate mitigation plans
    assert.strictEqual(canExecuteTool("analyst", "getIncidents"), true);
    assert.strictEqual(canExecuteTool("analyst", "investigateIncident"), true);
    assert.strictEqual(canExecuteTool("analyst", "analyzeCve"), true);
    assert.strictEqual(canExecuteTool("analyst", "simulateBlastRadius"), true);
    assert.strictEqual(canExecuteTool("analyst", "generateMitigationPlan"), false);

    // Responder: active mitigation and incident response
    assert.strictEqual(canExecuteTool("responder", "getIncidents"), true);
    assert.strictEqual(canExecuteTool("responder", "investigateIncident"), true);
    assert.strictEqual(canExecuteTool("responder", "generateMitigationPlan"), true);

    // Unknown tool
    assert.strictEqual(canExecuteTool("system_admin", "unknownDestructiveTool"), false);
  });

  it("Priority 1: simulateBlastRadius computes downstream dependencies, posture delta, and isolation (all roles with cve.read)", async () => {
    // 1. Authorization Gate (updated policy): All roles with cve.read can now run blast radius.
    //    Acme analyst (role: "analyst") has cve.read — must be ALLOWED (not denied).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const acmeRes: any = await simulateBlastRadius(acmeAnalyst, { cveId: "CVE-2024-6387" });
    assert.ok(!("error" in acmeRes), "Acme analyst must be ALLOWED blast radius simulation under updated RBAC policy");
    assert.ok(acmeRes.simulation, "Simulation object must be returned for Acme analyst");
    assert.strictEqual(acmeRes.simulation.target_cve, "CVE-2024-6387");

    // 2. Blast radius simulation also succeeds for Globex Analyst
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

    await assert.rejects(
      simulateBlastRadius(globexAnalyst, { incidentId: "INC-1042" }),
      /DATABASE_URL is not set/
    );
  });

  it("does not generate a plan from a demo incident when the database is unavailable", async () => {
    await assert.rejects(
      generateMitigationPlan(acmeAnalyst, { incidentId: "INC-1042" }),
      /DATABASE_URL is not set/
    );
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

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as threatsGET, POST as threatsPOST } from "@/app/api/threats/route";
import {
  isUserAuthorizedForAlerts,
  getThreatAlertsForUser,
  recordThreatAlert,
  recordScrubbedPII,
  getLivePIIMetrics,
  blockIp,
  unblockIp,
  getBlockedIps,
  resetThreatAlerts,
} from "@/lib/alerts/threatAlertStore";

test("SD-044: Consistent Live PII Redaction Breakdown & Telemetry Across Operator Roles", async (t) => {
  // Reset store to known state
  resetThreatAlerts();

  // Populate sample PII scrubbed tokens in memory
  recordScrubbedPII({
    jwt_tokens: 14,
    passwords_and_secrets: 8,
    credit_cards: 5,
    emails: 22,
  });

  // Explicitly block test IP and record alert
  blockIp("198.51.100.44", "Automated containment: >5 consecutive failures");
  recordThreatAlert({
    targetUser: "victim@mintsglobal.ae",
    clientIp: "198.51.100.44",
    failureReason: "Invalid password attempt (>5 attempts)",
    tenantId: "mints-global",
  });

  const operatorPersonas = [
    { id: "dev-admin", role: "system_admin", name: "System Admin" },
    { id: "dev-super", role: "super_admin", name: "Super Admin" },
    { id: "dev-responder", role: "responder", name: "Incident Responder" },
    { id: "dev-analyst", role: "analyst", name: "SOC Analyst" },
  ];

  await t.test("ThreatAlertStore: isUserAuthorizedForAlerts recognizes all 4 operator roles and dev users", () => {
    // Direct role strings
    assert.strictEqual(isUserAuthorizedForAlerts("any-user", "system_admin"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("any-user", "super_admin"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("any-user", "responder"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("any-user", "analyst"), true);

    // Dev user IDs without explicit role param
    assert.strictEqual(isUserAuthorizedForAlerts("dev-admin"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("dev-super"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("dev-responder"), true);
    assert.strictEqual(isUserAuthorizedForAlerts("dev-analyst"), true);

    // Null or empty
    assert.strictEqual(isUserAuthorizedForAlerts(null), false);
    assert.strictEqual(isUserAuthorizedForAlerts(""), false);
  });

  await t.test("ThreatAlertStore: getThreatAlertsForUser returns alerts for all 4 operator roles", () => {
    for (const persona of operatorPersonas) {
      const alerts = getThreatAlertsForUser(persona.id, "mints-global", persona.role);
      assert.ok(alerts.length > 0, `Persona ${persona.name} should receive active threat alerts`);
      const targetAlert = alerts.find((a) => a.clientIp === "198.51.100.44");
      assert.ok(targetAlert, `Persona ${persona.name} should see the blocked IP alert`);
      assert.strictEqual(targetAlert?.isBlocked, true);
    }
  });

  await t.test("GET /api/threats: Telemetry and PII Breakdown are identical and consistent across all 4 roles", async () => {
    const results: Array<{
      persona: string;
      status: number;
      can_view_auth_alerts: boolean;
      pii_redacted_today: number;
      jwt_tokens: number;
      passwords_and_secrets: number;
      credit_cards: number;
      emails: number;
      active_agents: number;
      alerts_count: number;
      blocked_ips_count: number;
    }> = [];

    for (const persona of operatorPersonas) {
      const req = new NextRequest("http://localhost:3000/api/threats", {
        headers: {
          "X-ShieldDesk-User": persona.id,
        },
      });

      const res = await threatsGET(req);
      assert.strictEqual(res.status, 200, `GET /api/threats should succeed for ${persona.name}`);
      const data = await res.json();

      assert.strictEqual(data.can_view_auth_alerts, true, `${persona.name} can view auth alerts`);
      assert.ok(Array.isArray(data.security_alerts), `${persona.name} receives security_alerts array`);
      assert.ok(data.security_alerts.length > 0, `${persona.name} sees active security alerts`);
      assert.ok(Array.isArray(data.blocked_ips), `${persona.name} receives blocked_ips array`);
      assert.ok(data.blocked_ips.length > 0, `${persona.name} sees blocked IPs`);

      results.push({
        persona: persona.name,
        status: res.status,
        can_view_auth_alerts: data.can_view_auth_alerts,
        pii_redacted_today: data.ingest_telemetry?.pii_redacted_today ?? 0,
        jwt_tokens: data.ingest_telemetry?.pii_categories?.jwt_tokens ?? 0,
        passwords_and_secrets: data.ingest_telemetry?.pii_categories?.passwords_and_secrets ?? 0,
        credit_cards: data.ingest_telemetry?.pii_categories?.credit_cards ?? 0,
        emails: data.ingest_telemetry?.pii_categories?.emails ?? 0,
        active_agents: data.ingest_telemetry?.active_agents_connected ?? 0,
        alerts_count: data.security_alerts.length,
        blocked_ips_count: data.blocked_ips.length,
      });
    }

    // Verify all 4 roles match the baseline numbers exactly
    const baseline = results[0];
    for (let i = 1; i < results.length; i++) {
      const current = results[i];
      assert.strictEqual(
        current.pii_redacted_today,
        baseline.pii_redacted_today,
        `PII redacted today must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.jwt_tokens,
        baseline.jwt_tokens,
        `JWT tokens scrubbed must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.passwords_and_secrets,
        baseline.passwords_and_secrets,
        `Secrets/keys scrubbed must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.credit_cards,
        baseline.credit_cards,
        `Credit cards scrubbed must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.emails,
        baseline.emails,
        `Emails scrubbed must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.active_agents,
        baseline.active_agents,
        `Active agents must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.alerts_count,
        baseline.alerts_count,
        `Security alerts count must match between ${baseline.persona} and ${current.persona}`
      );
      assert.strictEqual(
        current.blocked_ips_count,
        baseline.blocked_ips_count,
        `Blocked IPs count must match between ${baseline.persona} and ${current.persona}`
      );
    }
  });

  await t.test("POST /api/threats (unblock_ip & block_ip): RBAC containment enforcement", async () => {
    const testIp = "192.0.2.111";

    // 1. Analyst attempting to block IP -> 403 Forbidden
    const analystReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ action: "block_ip", ip: testIp }),
    });
    const analystRes = await threatsPOST(analystReq);
    assert.strictEqual(analystRes.status, 403, "Analyst must be prohibited from blocking IP");

    // 2. Responder attempting to block IP -> 200 OK
    const responderBlockReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({ action: "block_ip", ip: testIp }),
    });
    const responderBlockRes = await threatsPOST(responderBlockReq);
    assert.strictEqual(responderBlockRes.status, 200, "Responder must be allowed to block IP");
    const responderBlockData = await responderBlockRes.json();
    assert.strictEqual(responderBlockData.success, true);
    assert.ok(responderBlockData.blocked_ips.some((b: any) => b.ip === testIp));

    // 3. Analyst attempting to unblock IP -> 403 Forbidden
    const analystUnblockReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ action: "unblock_ip", ip: testIp }),
    });
    const analystUnblockRes = await threatsPOST(analystUnblockReq);
    assert.strictEqual(analystUnblockRes.status, 403, "Analyst must be prohibited from unblocking IP");

    // 4. Responder attempting to unblock IP -> 200 OK
    const responderUnblockReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({ action: "unblock_ip", ip: testIp }),
    });
    const responderUnblockRes = await threatsPOST(responderUnblockReq);
    assert.strictEqual(responderUnblockRes.status, 200, "Responder must be allowed to unblock IP");
    const responderUnblockData = await responderUnblockRes.json();
    assert.strictEqual(responderUnblockData.success, true);
  });

  await t.test("POST /api/threats (simulate_burst & reset_baseline): Gated strictly to System Admin", async () => {
    // 1. Analyst attempting simulate_burst -> 403
    const analystBurstReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ action: "simulate_burst" }),
    });
    const analystBurstRes = await threatsPOST(analystBurstReq);
    assert.strictEqual(analystBurstRes.status, 403, "Analyst cannot simulate anomaly burst");

    // 2. Responder attempting simulate_burst -> 403
    const responderBurstReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({ action: "simulate_burst" }),
    });
    const responderBurstRes = await threatsPOST(responderBurstReq);
    assert.strictEqual(responderBurstRes.status, 403, "Responder cannot simulate anomaly burst");

    // 3. System Admin attempting simulate_burst -> 200
    const adminBurstReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({ action: "simulate_burst" }),
    });
    const adminBurstRes = await threatsPOST(adminBurstReq);
    assert.strictEqual(adminBurstRes.status, 200, "System Admin can simulate anomaly burst");

    // 4. Analyst attempting reset_baseline -> 403
    const analystResetReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ action: "reset_baseline" }),
    });
    const analystResetRes = await threatsPOST(analystResetReq);
    assert.strictEqual(analystResetRes.status, 403, "Analyst cannot reset baselines");

    // 5. Responder attempting reset_baseline -> 403
    const responderResetReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({ action: "reset_baseline" }),
    });
    const responderResetRes = await threatsPOST(responderResetReq);
    assert.strictEqual(responderResetRes.status, 403, "Responder cannot reset baselines");

    // 6. System Admin attempting reset_baseline -> 200
    const adminResetReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({ action: "reset_baseline" }),
    });
    const adminResetRes = await threatsPOST(adminResetReq);
    assert.strictEqual(adminResetRes.status, 200, "System Admin can reset baselines");
    const adminResetData = await adminResetRes.json();
    assert.strictEqual(adminResetData.success, true);
  });
});

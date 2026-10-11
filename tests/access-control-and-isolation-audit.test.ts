import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as shodanGetHandler, POST as shodanPostHandler } from "@/app/api/intel/shodan/route";
import { GET as hibpGetHandler } from "@/app/api/intel/hibp/route";
import { DELETE as fleetLogsDeleteHandler } from "@/app/api/fleet/logs/route";
import { getLiveCommandLogs } from "@/lib/fleet/liveTelemetry";
import { getLastScanResult, setLastScanResult, type ScanResult } from "@/lib/trivy";
import { getLastGitleaksScanResult, setLastGitleaksScanResult, type GitleaksScanResult } from "@/lib/gitleaks";
import { recordThreatAlert, getThreatAlertsForUser, resetThreatAlerts } from "@/lib/alerts/threatAlertStore";
import { createSessionToken } from "@/lib/auth/token";

describe("Access Control, Multi-Tenancy & Data Isolation Audit Suite", () => {
  describe("Perimeter Intel Endpoints Authentication Gate", () => {
    test("GET /api/intel/shodan rejects unauthenticated public requests with 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/intel/shodan");
      const res = await shodanGetHandler(req);
      assert.equal(res.status, 401);
      const json = await res.json();
      assert.equal(json.error.includes("Unauthorized"), true);
    });

    test("POST /api/intel/shodan rejects unauthenticated public requests with 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/intel/shodan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: "8.8.8.8" }),
      });
      const res = await shodanPostHandler(req);
      assert.equal(res.status, 401);
      const json = await res.json();
      assert.equal(json.error.includes("Unauthorized"), true);
    });

    test("GET /api/intel/hibp rejects unauthenticated public requests with 401", async () => {
      const req = new NextRequest("http://localhost:3000/api/intel/hibp");
      const res = await hibpGetHandler(req);
      assert.equal(res.status, 401);
      const json = await res.json();
      assert.equal(json.error.includes("Unauthorized"), true);
    });

    test("GET /api/intel/hibp allows authenticated session", async () => {
      const token = createSessionToken({
        uid: "test-analyst-1",
        tenantId: "tenant-intel-test",
        role: "analyst",
      });
      const req = new NextRequest("http://localhost:3000/api/intel/hibp", {
        headers: { Cookie: `shielddesk_session=${token}` },
      });
      const res = await hibpGetHandler(req);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok("configured" in json);
    });
  });

  describe("Fleet Command Logs Role & Multi-Tenant Isolation", () => {
    test("DELETE /api/fleet/logs forbids non-administrative callers", async () => {
      const viewerToken = createSessionToken({
        uid: "user-viewer-42",
        tenantId: "tenant-alpha",
        role: "analyst",
      });
      const req = new NextRequest("http://localhost:3000/api/fleet/logs?agentId=agent-123", {
        method: "DELETE",
        headers: { Cookie: `shielddesk_session=${viewerToken}` },
      });
      const res = await fleetLogsDeleteHandler(req);
      assert.equal(res.status, 403);
      const json = await res.json();
      assert.ok(json.error.includes("Administrative privileges required"));
    });

    test("getLiveCommandLogs scopes queries to caller tenant_id when agentId provided by non-cross-tenant role", async () => {
      const caller = {
        id: "analyst-1",
        tenant_id: "tenant-finance",
        role: "responder" as const,
      };

      const logs = await getLiveCommandLogs(caller, "agent-xyz-foreign");
      assert.ok(Array.isArray(logs));
      // Any retrieved logs must match caller tenant_id
      for (const log of logs) {
        assert.equal(log.tenantId, "tenant-finance");
      }
    });
  });

  describe("Trivy & Gitleaks Multi-Tenant Cache Partitioning", () => {
    test("Trivy scanner partitions cache results by tenantId", () => {
      const mockResultTenantA: ScanResult = {
        findings: [],
        summary: { critical: 1, high: 2, medium: 0, low: 0, unknown: 0 },
        scannedTarget: "/app/tenant-a",
        scanDurationMs: 120,
        binaryPath: "trivy.exe",
      };

      const mockResultTenantB: ScanResult = {
        findings: [],
        summary: { critical: 5, high: 0, medium: 0, low: 0, unknown: 0 },
        scannedTarget: "/app/tenant-b",
        scanDurationMs: 80,
        binaryPath: "trivy.exe",
      };

      setLastScanResult(mockResultTenantA, "tenant-org-a");
      setLastScanResult(mockResultTenantB, "tenant-org-b");

      const fetchedA = getLastScanResult("tenant-org-a");
      const fetchedB = getLastScanResult("tenant-org-b");

      assert.equal(fetchedA?.scannedTarget, "/app/tenant-a");
      assert.equal(fetchedA?.summary.critical, 1);
      assert.equal(fetchedB?.scannedTarget, "/app/tenant-b");
      assert.equal(fetchedB?.summary.critical, 5);
    });

    test("Gitleaks partitions secret findings cache by tenantId", () => {
      const gitleaksA: GitleaksScanResult = {
        findings: [],
        summary: { critical: 2, high: 0, medium: 0, total: 2 },
        scannedTarget: "/repos/tenant-a",
        scanDurationMs: 150,
        binaryPath: "gitleaks.exe",
        scanMode: "git_history",
        redacted: true,
      };

      const gitleaksB: GitleaksScanResult = {
        findings: [],
        summary: { critical: 0, high: 1, medium: 0, total: 1 },
        scannedTarget: "/repos/tenant-b",
        scanDurationMs: 90,
        binaryPath: "gitleaks.exe",
        scanMode: "git_history",
        redacted: true,
      };

      setLastGitleaksScanResult(gitleaksA, "tenant-secrets-a");
      setLastGitleaksScanResult(gitleaksB, "tenant-secrets-b");

      const fetchedSecretsA = getLastGitleaksScanResult("tenant-secrets-a");
      const fetchedSecretsB = getLastGitleaksScanResult("tenant-secrets-b");

      assert.equal(fetchedSecretsA?.scannedTarget, "/repos/tenant-a");
      assert.equal(fetchedSecretsA?.summary.critical, 2);
      assert.equal(fetchedSecretsB?.scannedTarget, "/repos/tenant-b");
      assert.equal(fetchedSecretsB?.summary.high, 1);
    });
  });

  describe("Threat Alerts Multi-Tenant Boundary Enforcement", () => {
    test("Alerts recorded for Tenant A are isolated from Tenant B queries", () => {
      resetThreatAlerts();

      recordThreatAlert({
        targetUser: "admin@tenant-alpha.com",
        clientIp: "198.51.100.12",
        failureReason: "Bad credentials",
        tenantId: "tenant-alpha",
      });

      recordThreatAlert({
        targetUser: "ceo@tenant-beta.com",
        clientIp: "198.51.100.34",
        failureReason: "Bad credentials",
        tenantId: "tenant-beta",
      });

      // Tenant Alpha admin
      const alphaAlerts = getThreatAlertsForUser("user-alpha-admin", "tenant-alpha", "responder");
      assert.equal(alphaAlerts.length, 1);
      assert.equal(alphaAlerts[0].targetUser, "admin@tenant-alpha.com");
      assert.equal(alphaAlerts[0].tenantId, "tenant-alpha");

      // Tenant Beta admin
      const betaAlerts = getThreatAlertsForUser("user-beta-admin", "tenant-beta", "responder");
      assert.equal(betaAlerts.length, 1);
      assert.equal(betaAlerts[0].targetUser, "ceo@tenant-beta.com");
      assert.equal(betaAlerts[0].tenantId, "tenant-beta");

      // Platform Super Admin (cross-tenant)
      const platformSuperAdminAlerts = getThreatAlertsForUser("super-admin-root", "tenant-alpha", "super_admin");
      assert.equal(platformSuperAdminAlerts.length >= 2, true);
    });
  });
});

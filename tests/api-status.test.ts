import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { getSystemStatusReport } from "@/lib/status/serviceStatus";
import { GET as statusGetHandler } from "@/app/api/status/route";

describe("Public API Status & Subsystem Health Monitoring Suite", () => {
  test("getSystemStatusReport returns comprehensive subsystem diagnostics", async () => {
    const report = await getSystemStatusReport();

    assert.ok(["operational", "degraded", "outage"].includes(report.status), "status must be valid health state");
    assert.equal(report.version, "2.4.0");
    assert.ok(typeof report.uptime_seconds === "number" && report.uptime_seconds >= 0);
    assert.ok(report.timestamp);

    // Summary validation
    assert.ok(report.summary.total_services >= 8);
    assert.ok(report.summary.operational >= 0);
    assert.equal(
      report.summary.total_services,
      report.summary.operational + report.summary.degraded + report.summary.outage
    );

    // Core services presence
    const expectedServices = [
      "database",
      "auth_gateway",
      "fleet_pki",
      "ai_engine",
      "scanner_engine",
      "threat_engine",
      "compliance_ledger",
      "billing_service",
    ];

    for (const svcKey of expectedServices) {
      assert.ok(report.services[svcKey], `Service ${svcKey} must exist in report`);
      const svc = report.services[svcKey];
      assert.ok(["operational", "degraded", "outage", "maintenance"].includes(svc.status));
      assert.ok(typeof svc.latency_ms === "number" && svc.latency_ms >= 0);
      assert.ok(svc.name.length > 0);
      assert.ok(svc.description.length > 0);
    }

    // Incidents structure
    assert.ok(Array.isArray(report.incidents));
    assert.ok(report.incidents.length > 0);
    assert.ok(report.incidents[0].id);
    assert.ok(report.incidents[0].title);
  });

  test("GET /api/status route handler returns valid HTTP response and headers", async () => {
    const res = await statusGetHandler(new NextRequest("http://localhost:3000/api/status"));

    // Either 200 (operational/degraded) or 503 (outage)
    assert.ok(res.status === 200 || res.status === 503);

    // Header validations
    const cacheControl = res.headers.get("Cache-Control");
    assert.ok(cacheControl?.includes("no-store"), "Must disable caching for real-time status");

    const statusHeader = res.headers.get("X-ShieldDesk-Status");
    assert.ok(["operational", "degraded", "outage"].includes(statusHeader || ""));

    const json = await res.json();
    assert.ok(json.version);
    assert.ok(json.services);
    assert.ok(json.summary);
  });

  test("browser requests redirect to the status page", async () => {
    const request = new NextRequest("http://localhost:3000/api/status", {
      headers: { accept: "text/html" },
    });
    const res = await statusGetHandler(request);

    assert.equal(res.status, 307);
    assert.equal(res.headers.get("location"), "http://localhost:3000/status");
  });

  test("format=json keeps browser requests on the telemetry API", async () => {
    const request = new NextRequest("http://localhost:3000/api/status?format=json", {
      headers: { accept: "text/html" },
    });
    const res = await statusGetHandler(request);

    assert.ok(res.status === 200 || res.status === 503);
    assert.equal(res.headers.get("location"), null);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    const json = await res.json();
    assert.ok(json.services);
    assert.ok(json.summary);
  });
});

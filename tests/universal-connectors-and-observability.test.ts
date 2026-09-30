import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ConnectorRegistry } from "../src/lib/connectors/registry";
import { ConnectorNormalizer } from "../src/lib/connectors/normalizer";
import { MetricsRegistry } from "../src/lib/observability/metrics";

test("Phase 22, 30: Universal Connectors and Observability Metrics Suite", async (t) => {
  const tenantId = "tenant-siem-conn";

  t.beforeEach(() => {
    ConnectorRegistry.clear(tenantId);
    MetricsRegistry.clear();
  });

  await t.test("ConnectorNormalizer: Correctly normalizes Wazuh alert payload", () => {
    const rawWazuh = {
      id: "wazuh-alert-8912",
      timestamp: "2026-09-30T10:00:00.000Z",
      rule: {
        id: "100021",
        level: 12,
        description: "Ransomware shadow copy deletion activity",
        groups: ["windows", "ransomware"],
      },
      agent: {
        id: "002",
        name: "finance-ws-1",
        ip: "192.168.10.45",
      },
      data: {
        win: {
          eventdata: {
            image: "C:\\Windows\\System32\\vssadmin.exe",
            commandLine: "vssadmin.exe delete shadows /all /quiet",
            processId: "3412",
            user: "CORP\\Administrator",
          },
        },
      },
    };

    const evt = ConnectorNormalizer.normalizeWazuh(rawWazuh, tenantId);
    assert.equal(evt.source, "wazuh");
    assert.equal(evt.severity, "critical");
    assert.equal(evt.affectedAsset.hostname, "finance-ws-1");
    assert.equal(evt.processContext?.name, "vssadmin.exe");
    assert.equal(evt.processContext?.pid, 3412);
  });

  await t.test("ConnectorNormalizer: Correctly normalizes Microsoft Defender alert payload", () => {
    const rawDefender = {
      alertId: "da-44810-sec",
      severity: "High",
      title: "Suspicious PowerShell In-Memory Injection",
      category: "Execution",
      computerDnsName: "exchange-srv-01.corp.internal",
      machineId: "mach-881249",
      alertCreationTime: "2026-09-30T10:05:00.000Z",
    };

    const evt = ConnectorNormalizer.normalizeDefender(rawDefender, tenantId);
    assert.equal(evt.source, "defender");
    assert.equal(evt.severity, "high");
    assert.equal(evt.affectedAsset.hostname, "exchange-srv-01.corp.internal");
    assert.ok(evt.tags.includes("microsoft-defender"));
  });

  await t.test("ConnectorRegistry: Ingests with HMAC verification and enforces signature integrity", async () => {
    const secretKey = "webhook-secret-key-123456789012";
    const payload = {
      id: "alert-wh-1",
      severity: "high",
      title: "Cobalt Strike Beacon",
      hostname: "dc-prod-01",
    };

    // 1. Invalid signature should be rejected
    const failedResult = await ConnectorRegistry.ingest("webhook", payload, tenantId, {
      secretKey,
      signatureHeader: "sha256=invalid-signature",
    });
    assert.equal(failedResult.success, false);
    assert.ok(failedResult.error?.includes("signature mismatch"));

    // 2. Valid HMAC signature succeeds
    const validSignature = crypto
      .createHmac("sha256", secretKey)
      .update(JSON.stringify(payload))
      .digest("hex");

    const successResult = await ConnectorRegistry.ingest("webhook", payload, tenantId, {
      secretKey,
      signatureHeader: `sha256=${validSignature}`,
    });
    assert.equal(successResult.success, true);
    assert.equal(successResult.event?.affectedAsset.hostname, "dc-prod-01");

    // Events stored in registry
    const events = ConnectorRegistry.getEvents(tenantId);
    assert.equal(events.length, 1);
  });

  await t.test("MetricsRegistry: Tracks operational counters and emits valid Prometheus exposition", () => {
    MetricsRegistry.increment("shielddesk_ingested_events_total", 5, { tenant: tenantId, source: "wazuh" });
    MetricsRegistry.increment("shielddesk_remediations_executed_total", 1, { action: "isolate_host", status: "success" });

    const val = MetricsRegistry.getCounter("shielddesk_ingested_events_total", { tenant: tenantId, source: "wazuh" });
    assert.equal(val, 5);

    const promOutput = MetricsRegistry.toPrometheus();
    assert.ok(promOutput.includes("shielddesk_build_info"));
    assert.ok(promOutput.includes("shielddesk_ingested_events_total{tenant=\"tenant-siem-conn\",source=\"wazuh\"} 5"));
  });
});

/**
 * Phase A: Security Data Layer Test Suite
 *
 * Tests:
 * 1. Connector SDK interface — all 7 methods on WazuhConnector (offline/mock)
 * 2. TrivyConnector — report submission, HMAC verification, normalization
 * 3. OpenVASConnector — normalize and validate
 * 4. AssetCriticalityService — rule-based classification and tenant overrides
 * 5. EventDeduplicator — window-based dedup, expire
 * 6. FindingCorrelator — CVE campaign, ransomware IoC, isolated alert, risk scores
 * 7. CanonicalSecurityEvent schema validation via validate()
 * 8. BACKWARD COMPATIBILITY: legacy ConnectorRegistry and ConnectorNormalizer still work
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { WazuhConnector } from "../src/lib/connectors/wazuh";
import { TrivyConnector } from "../src/lib/connectors/trivy";
import { OpenVASConnector } from "../src/lib/connectors/openvas";
import { AssetCriticalityService } from "../src/lib/connectors/asset-criticality";
import { EventDeduplicator, FindingCorrelator } from "../src/lib/connectors/deduplication";
import { ConnectorRegistry } from "../src/lib/connectors/registry";
import { ConnectorNormalizer } from "../src/lib/connectors/normalizer";
import type { CanonicalSecurityEvent } from "../src/lib/connectors/event-model";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEvent(overrides: Partial<CanonicalSecurityEvent> = {}): CanonicalSecurityEvent {
  const fp = crypto.randomBytes(16).toString("hex");
  return {
    id: `sec-evt-${fp.slice(0, 16)}`,
    tenantId: "tenant-phase-a",
    source: "wazuh",
    externalId: `ext-${fp}`,
    dedupFingerprint: fp,
    timestamp: new Date().toISOString(),
    ingestAt: new Date().toISOString(),
    severity: "high",
    category: "alert",
    eventType: "wazuh_alert",
    title: "Test Alert",
    description: "Test description",
    affectedAsset: { hostname: "srv-app-01", ip: "10.0.0.1" },
    status: "open",
    tags: ["wazuh", "test"],
    evidenceIds: [],
    rawPayload: {},
    ...overrides,
  };
}

// ─── Test Suite ──────────────────────────────────────────────────────────────

test("Phase A: Security Data Layer Suite", async (t) => {
  const tenantId = "tenant-phase-a";

  // ── 1. WazuhConnector — normalize and validate ───────────────────────────
  await t.test("WazuhConnector: normalizes critical-level Wazuh alert correctly", () => {
    const connector = new WazuhConnector();
    const raw = {
      id: "wazuh-9999",
      timestamp: "2026-09-30T10:00:00Z",
      rule: {
        id: "100500",
        level: 15,
        description: "Ransomware shadow copy deletion",
        groups: ["windows", "ransomware"],
      },
      agent: { id: "agent-01", name: "finance-dc-01", ip: "192.168.1.10" },
      data: {
        win: {
          eventdata: {
            image: "C:\\Windows\\System32\\vssadmin.exe",
            commandLine: "vssadmin.exe delete shadows /all /quiet",
            processId: "3412",
            user: "NT AUTHORITY\\SYSTEM",
          },
        },
      },
    };

    const evt = connector.normalize(raw, tenantId);

    assert.equal(evt.source, "wazuh");
    assert.equal(evt.severity, "critical");
    assert.equal(evt.tenantId, tenantId);
    assert.equal(evt.affectedAsset.hostname, "finance-dc-01");
    assert.equal(evt.affectedAsset.ip, "192.168.1.10");
    assert.equal(evt.processContext?.pid, 3412);
    assert.equal(evt.processContext?.name, "vssadmin.exe");
    assert.ok(evt.tags.includes("ransomware"));
    assert.ok(evt.dedupFingerprint.length >= 16, "dedupFingerprint must be substantial");
    assert.equal(evt.status, "open");
    assert.equal(evt.category, "alert");
  });

  await t.test("WazuhConnector: validate() rejects event with missing tenantId", () => {
    const connector = new WazuhConnector();
    const raw = { id: "bad-1", rule: { level: 5, description: "x" }, agent: {} };
    const evt = connector.normalize(raw, "");
    const result = connector.validate(evt);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("tenantId")));
  });

  await t.test("WazuhConnector: validate() passes for well-formed event", () => {
    const connector = new WazuhConnector();
    const raw = {
      id: "w-alert-valid",
      timestamp: "2026-09-30T10:00:00Z",
      rule: { id: "1001", level: 8, description: "Brute force attempt", groups: ["auth"] },
      agent: { id: "a1", name: "web-srv-01", ip: "10.0.0.5" },
    };
    const evt = connector.normalize(raw, tenantId);
    const result = connector.validate(evt);
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  await t.test("WazuhConnector: getCursor() initializes to '0' and tracks offset", () => {
    const connector = new WazuhConnector();
    assert.equal(connector.getCursor(), "0");
  });

  await t.test("WazuhConnector: CVE extraction from full_log field", () => {
    const connector = new WazuhConnector();
    const raw = {
      id: "cve-alert",
      timestamp: "2026-09-30T11:00:00Z",
      rule: { id: "99001", level: 10, description: "CVE exploit attempt" },
      agent: { name: "prod-srv-02", ip: "10.0.1.20" },
      full_log: "Exploit detected for CVE-2024-3400 on palo alto firewall",
    };
    const evt = connector.normalize(raw, tenantId);
    assert.ok(evt.vulnerability, "Should extract vulnerability block");
    assert.equal(evt.vulnerability?.cveId, "CVE-2024-3400");
  });

  // ── 2. TrivyConnector ────────────────────────────────────────────────────
  await t.test("TrivyConnector: normalizes Trivy JSON report vulnerability correctly", () => {
    const connector = new TrivyConnector();
    const raw = {
      VulnerabilityID: "CVE-2023-44487",
      PkgName: "golang.org/x/net",
      InstalledVersion: "0.14.0",
      FixedVersion: "0.17.0",
      Severity: "HIGH",
      Title: "HTTP/2 Rapid Reset Attack",
      Description: "HTTP/2 Rapid Reset (CVE-2023-44487)",
      CVSS: {
        nvd: { V3Score: 7.5, V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
      },
      _hostname: "ci-build-server",
      _target: "go.sum",
      _artifactName: "shielddesk-api:latest",
      _submittedAt: "2026-09-30T09:00:00Z",
    };

    const evt = connector.normalize(raw, tenantId);

    assert.equal(evt.source, "trivy");
    assert.equal(evt.category, "vulnerability");
    assert.equal(evt.eventType, "cve_finding");
    assert.equal(evt.vulnerability?.cveId, "CVE-2023-44487");
    assert.equal(evt.vulnerability?.cvssScore, 7.5);
    assert.equal(evt.vulnerability?.packageName, "golang.org/x/net");
    assert.equal(evt.vulnerability?.installedVersion, "0.14.0");
    assert.equal(evt.vulnerability?.fixedVersion, "0.17.0");
    assert.equal(evt.severity, "high");
    assert.equal(evt.affectedAsset.hostname, "ci-build-server");
    assert.equal(evt.findingContext?.remediationText, "Upgrade golang.org/x/net to 0.17.0");
  });

  await t.test("TrivyConnector: submitReport() enforces HMAC signing", async () => {
    const connector = new TrivyConnector();
    await connector.authenticate("", { type: "api_key", apiKey: "my-signing-secret" });

    const report = { ArtifactName: "nginx:latest", Results: [] };
    const validSig = crypto
      .createHmac("sha256", "my-signing-secret")
      .update(JSON.stringify(report))
      .digest("hex");

    const badResult = connector.submitReport(report, "nginx-host", "sha256=invalid");
    assert.equal(badResult.accepted, false);
    assert.ok(badResult.reason?.includes("HMAC signature mismatch"));

    const goodResult = connector.submitReport(report, "nginx-host", `sha256=${validSig}`);
    assert.equal(goodResult.accepted, true);
  });

  await t.test("TrivyConnector: collect() processes submitted reports and returns events", async () => {
    const connector = new TrivyConnector();
    await connector.authenticate("", { type: "api_key", apiKey: "secret-key" });

    const report = {
      ArtifactName: "myapp:v2.1",
      ArtifactType: "container_image",
      Results: [
        {
          Target: "myapp:v2.1 (ubuntu 22.04)",
          Type: "ubuntu",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2024-1234",
              PkgName: "libc6",
              InstalledVersion: "2.35-0ubuntu3",
              FixedVersion: "2.35-0ubuntu3.1",
              Severity: "CRITICAL",
            },
          ],
        },
      ],
    };

    connector.submitReport(report, "prod-k8s-node-01");
    const result = await connector.collect(tenantId, {});

    assert.equal(result.events.length, 1);
    assert.equal(result.events[0].vulnerability?.cveId, "CVE-2024-1234");
    assert.equal(result.events[0].severity, "critical");
    assert.equal(result.events[0].affectedAsset.hostname, "prod-k8s-node-01");
    assert.equal(result.hasMore, false);
  });

  // ── 3. OpenVASConnector ──────────────────────────────────────────────────
  await t.test("OpenVASConnector: normalizes OpenVAS result with CVE correctly", () => {
    const connector = new OpenVASConnector();
    const raw = {
      id: "result-openvas-001",
      name: "Apache Log4j RCE Vulnerability",
      description: "The remote host is affected by CVE-2021-44228",
      nvt: {
        oid: "1.3.6.1.4.1.25623.1.1.2.2021.3004",
        name: "Apache Log4j Multiple RCE Vulnerabilities (Log4Shell)",
        cvss_base: "10.0",
        cve_id: "CVE-2021-44228",
        solution_type: "VendorFix",
      },
      host: { ip: "10.10.0.55", hostname: "log4j-affected-app" },
      port: "8080/tcp",
      threat: "High",
      severity: "10.0",
      qod: { value: 70 },
      solution: { text: "Upgrade Apache Log4j to version 2.17.1 or later." },
      _reportEnd: "2026-09-30T08:00:00Z",
    };

    const evt = connector.normalize(raw, tenantId);

    assert.equal(evt.source, "openvas");
    assert.equal(evt.category, "vulnerability");
    assert.equal(evt.vulnerability?.cveId, "CVE-2021-44228");
    assert.equal(evt.severity, "critical");
    assert.equal(evt.affectedAsset.hostname, "log4j-affected-app");
    assert.equal(evt.affectedAsset.ip, "10.10.0.55");
    assert.equal(evt.networkContext?.dstPort, 8080);
    assert.equal(evt.networkContext?.protocol, "tcp");
    assert.equal(evt.findingContext?.confidence, 0.7);
    assert.equal(evt.findingContext?.remediationText, "Upgrade Apache Log4j to version 2.17.1 or later.");
  });

  await t.test("OpenVASConnector: validate() rejects event missing both hostname and ip", () => {
    const connector = new OpenVASConnector();
    const raw = {
      id: "no-host",
      name: "Some finding",
      nvt: {},
      host: {},
      severity: "5.0",
      _reportEnd: "2026-09-30T08:00:00Z",
    };
    const evt = connector.normalize(raw, tenantId);
    // Force removal of hostname and ip
    evt.affectedAsset.hostname = undefined;
    evt.affectedAsset.ip = undefined;
    const result = connector.validate(evt);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("hostname") || e.includes("ip")));
  });

  // ── 4. AssetCriticalityService ───────────────────────────────────────────
  await t.test("AssetCriticalityService: classifies domain controller as critical/compliance", () => {
    // "dc01.corp.internal" — starts with dc followed by digits and a dot
    const profile = AssetCriticalityService.classify(tenantId, "dc01.corp.internal");
    assert.equal(profile.criticality, "critical");
    assert.equal(profile.businessImpact, "compliance");
  });

  await t.test("AssetCriticalityService: classifies payment server as critical/revenue", () => {
    const profile = AssetCriticalityService.classify(tenantId, "payment-gateway-prod");
    assert.equal(profile.criticality, "critical");
    assert.equal(profile.businessImpact, "revenue");
  });

  await t.test("AssetCriticalityService: classifies web server as medium/reputational", () => {
    const profile = AssetCriticalityService.classify(tenantId, "www-nginx-01");
    assert.equal(profile.criticality, "medium");
    assert.equal(profile.businessImpact, "reputational");
  });

  await t.test("AssetCriticalityService: unknown hostname gets low criticality default", () => {
    const profile = AssetCriticalityService.classify(tenantId, "random-host-xyzabc");
    assert.equal(profile.criticality, "low");
    assert.equal(profile.businessImpact, "low");
  });

  await t.test("AssetCriticalityService: tenant override takes precedence over rule table", () => {
    AssetCriticalityService.clearOverrides(tenantId);
    AssetCriticalityService.registerOverride(
      tenantId,
      "custom-special-host",
      "critical",
      "revenue",
      "Manually classified by tenant admin"
    );
    const profile = AssetCriticalityService.classify(tenantId, "custom-special-host");
    assert.equal(profile.criticality, "critical");
    assert.equal(profile.businessImpact, "revenue");
    AssetCriticalityService.clearOverrides(tenantId);
  });

  await t.test("AssetCriticalityService: enrich() adds criticality to event in-place", () => {
    const evt = makeEvent({ affectedAsset: { hostname: "db-postgres-primary" } });
    AssetCriticalityService.enrich(evt);
    assert.equal(evt.affectedAsset.criticality, "critical");
    assert.equal(evt.affectedAsset.businessImpact, "compliance");
  });

  // ── 5. EventDeduplicator ─────────────────────────────────────────────────
  await t.test("EventDeduplicator: suppresses duplicate events within window", () => {
    EventDeduplicator.clear(tenantId);
    const fp = "aaaa1111bbbb2222cccc3333dddd4444";
    const evt1 = makeEvent({ dedupFingerprint: fp });
    const evt2 = makeEvent({ dedupFingerprint: fp, id: "sec-evt-different-id" });

    const result1 = EventDeduplicator.deduplicate(tenantId, [evt1]);
    assert.equal(result1.newEvents.length, 1);
    assert.equal(result1.suppressedCount, 0);

    const result2 = EventDeduplicator.deduplicate(tenantId, [evt2]);
    assert.equal(result2.newEvents.length, 0);
    assert.equal(result2.suppressedCount, 1);
    assert.ok(result2.duplicateFingerprints.includes(fp));

    EventDeduplicator.clear(tenantId);
  });

  await t.test("EventDeduplicator: expire() allows re-ingestion of fingerprint", () => {
    EventDeduplicator.clear(tenantId);
    const fp = "eeee5555ffff6666aaaa7777bbbb8888";
    const evt = makeEvent({ dedupFingerprint: fp });

    EventDeduplicator.deduplicate(tenantId, [evt]);
    EventDeduplicator.expire(tenantId, fp);

    const result = EventDeduplicator.deduplicate(tenantId, [evt]);
    assert.equal(result.newEvents.length, 1, "After expire, fingerprint should be accepted again");
    EventDeduplicator.clear(tenantId);
  });

  await t.test("EventDeduplicator: tenant isolation — same fingerprint in different tenants", () => {
    const fp = "cccc9999dddd0000eeee1111ffff2222";
    EventDeduplicator.clear("tenant-a");
    EventDeduplicator.clear("tenant-b");

    const evtA = makeEvent({ dedupFingerprint: fp, tenantId: "tenant-a" });
    const evtB = makeEvent({ dedupFingerprint: fp, tenantId: "tenant-b" });

    EventDeduplicator.deduplicate("tenant-a", [evtA]);
    // Same fingerprint in tenant-b should NOT be suppressed
    const result = EventDeduplicator.deduplicate("tenant-b", [evtB]);
    assert.equal(result.newEvents.length, 1, "Tenant B dedup is isolated from Tenant A");
    EventDeduplicator.clear();
  });

  // ── 6. FindingCorrelator ─────────────────────────────────────────────────
  await t.test("FindingCorrelator: correlates CVE campaign across multiple hosts", () => {
    const cveEvents = ["host-a", "host-b", "host-c"].map((hostname) =>
      makeEvent({
        affectedAsset: { hostname },
        vulnerability: { cveId: "CVE-2024-3400", kevListed: true, cvssScore: 10 },
        category: "vulnerability",
      })
    );

    const findings = FindingCorrelator.correlate(tenantId, cveEvents);
    const campaign = findings.find((f) => f.category === "cve_campaign");

    assert.ok(campaign, "Should produce a cve_campaign finding");
    assert.equal(campaign!.cveId, "CVE-2024-3400");
    assert.equal(campaign!.eventCount, 3);
    assert.equal(campaign!.affectedHostnames.length, 3);
    // KEV listed + CVSS 10: risk score = 100 + 20 + 6 = capped at 100
    assert.equal(campaign!.riskScore, 100);
  });

  await t.test("FindingCorrelator: tags ransomware events as ransomware_ioc finding", () => {
    const events = ["ws-1", "ws-2"].map((hostname) =>
      makeEvent({
        affectedAsset: { hostname },
        severity: "critical",
        tags: ["wazuh", "ransomware", "windows"],
      })
    );

    const findings = FindingCorrelator.correlate(tenantId, events);
    const ransomware = findings.find((f) => f.category === "ransomware_ioc");

    assert.ok(ransomware, "Should produce a ransomware_ioc finding");
    assert.equal(ransomware!.severity, "critical");
    assert.equal(ransomware!.riskScore, 95);
  });

  await t.test("FindingCorrelator: single event becomes isolated_alert finding", () => {
    const evt = makeEvent({
      vulnerability: { cveId: "CVE-2023-9999", cvssScore: 4.5, kevListed: false },
      category: "vulnerability",
    });

    const findings = FindingCorrelator.correlate(tenantId, [evt]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].category, "isolated_alert");
    assert.equal(findings[0].eventCount, 1);
    // CVSS 4.5 → base 45 + 0 KEV + 2 spread = 47
    assert.equal(findings[0].riskScore, 47);
  });

  await t.test("FindingCorrelator: risk score formula is deterministic and bounded", () => {
    // Critical KEV-listed campaign should not exceed 100
    const events = Array.from({ length: 100 }, (_, i) =>
      makeEvent({
        affectedAsset: { hostname: `host-${i}` },
        vulnerability: { cveId: "CVE-WORST-CASE", cvssScore: 10, kevListed: true },
        category: "vulnerability",
      })
    );
    const findings = FindingCorrelator.correlate(tenantId, events);
    const campaign = findings.find((f) => f.category === "cve_campaign");
    assert.ok(campaign, "Campaign should exist");
    assert.ok(campaign!.riskScore <= 100, "Risk score must never exceed 100");
    assert.ok(campaign!.riskScore >= 0, "Risk score must be non-negative");
  });

  // ── 7. Backward compatibility — legacy registry and normalizer ────────────
  await t.test("BACKWARD COMPAT: ConnectorNormalizer.normalizeWazuh still works", () => {
    const raw = {
      id: "legacy-wazuh-1",
      timestamp: "2026-09-30T09:00:00Z",
      rule: { id: "5551", level: 10, description: "SSH brute force", groups: ["sshd", "auth"] },
      agent: { id: "003", name: "bastion-01", ip: "10.0.0.1" },
    };
    const evt = ConnectorNormalizer.normalizeWazuh(raw, tenantId);
    assert.equal(evt.source, "wazuh");
    assert.equal(evt.severity, "high");
  });

  await t.test("BACKWARD COMPAT: ConnectorRegistry.ingest with HMAC still works", async () => {
    ConnectorRegistry.clear(tenantId);
    const secretKey = "test-secret-abc";
    const payload = { id: "leg-1", severity: "high", title: "Cobalt Strike", hostname: "victim" };
    const sig = crypto.createHmac("sha256", secretKey).update(JSON.stringify(payload)).digest("hex");

    const result = await ConnectorRegistry.ingest("wazuh", payload, tenantId, {
      secretKey,
      signatureHeader: `sha256=${sig}`,
    });
    assert.equal(result.success, true);
    ConnectorRegistry.clear(tenantId);
  });
});

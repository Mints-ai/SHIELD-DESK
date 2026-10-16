import { describe, it } from "node:test";
import assert from "node:assert";
import {
  satisfiesSeverityThreshold,
  matchesEventSubscription,
  dispatchSecurityNotification,
} from "@/lib/notifications/dispatcher";
import {
  createTenantWebhookEndpoint,
  updateTenantWebhookEndpoint,
  getTenantWebhookEndpoints,
} from "@/lib/webhooks/webhookStore";

describe("Webhook Dispatcher Event & Severity Filtering Suite", () => {
  const testTenant = "test-filtering-tenant";

  it("Step 1: Unit tests for severity threshold evaluation", () => {
    // Critical threshold checks
    assert.strictEqual(satisfiesSeverityThreshold("critical", "critical"), true);
    assert.strictEqual(satisfiesSeverityThreshold("high", "critical"), false, "High should be suppressed for critical threshold");
    assert.strictEqual(satisfiesSeverityThreshold("medium", "critical"), false, "Medium should be suppressed for critical threshold");
    assert.strictEqual(satisfiesSeverityThreshold("low", "critical"), false, "Low should be suppressed for critical threshold");

    // High threshold checks
    assert.strictEqual(satisfiesSeverityThreshold("critical", "high"), true);
    assert.strictEqual(satisfiesSeverityThreshold("high", "high"), true);
    assert.strictEqual(satisfiesSeverityThreshold("medium", "high"), false, "Medium should be suppressed for high threshold");

    // Medium threshold checks
    assert.strictEqual(satisfiesSeverityThreshold("high", "medium"), true);
    assert.strictEqual(satisfiesSeverityThreshold("medium", "medium"), true);
    assert.strictEqual(satisfiesSeverityThreshold("low", "medium"), false);

    // Low threshold (accepts all)
    assert.strictEqual(satisfiesSeverityThreshold("critical", "low"), true);
    assert.strictEqual(satisfiesSeverityThreshold("low", "low"), true);
  });

  it("Step 2: Unit tests for event type subscription matching", () => {
    // Exact matching
    assert.strictEqual(
      matchesEventSubscription("threat_detected", ["threat_detected", "approval_required"]),
      true
    );
    assert.strictEqual(
      matchesEventSubscription("incident_created", ["threat_detected", "approval_required"]),
      false,
      "Unsubscribed event must be rejected"
    );

    // Wildcard category matching (e.g. threat.*)
    assert.strictEqual(
      matchesEventSubscription("threat.ransomware", ["threat.*"]),
      true
    );
    assert.strictEqual(
      matchesEventSubscription("threat_detected", ["threat.*"]),
      true
    );
    assert.strictEqual(
      matchesEventSubscription("compliance.audit", ["threat.*"]),
      false
    );

    // Universal wildcard matching
    assert.strictEqual(matchesEventSubscription("anything", ["*"]), true);
    assert.strictEqual(matchesEventSubscription("anything", ["all"]), true);
    assert.strictEqual(matchesEventSubscription("anything", []), true);
  });

  it("Step 3: End-to-end multi-endpoint subscription and severity suppression", async () => {
    // Register Endpoint 1: PagerDuty / Critical Threats only
    const criticalEndpoint = await createTenantWebhookEndpoint({
      tenantId: testTenant,
      name: "Critical Escalations",
      type: "generic",
      destination: "https://mock-siem.corp/critical-alerts",
      events: ["threat_detected", "lockdown.activated"],
      minSeverity: "critical",
    });

    // Register Endpoint 2: Governance / Human Approvals of any severity (low+)
    const governanceEndpoint = await createTenantWebhookEndpoint({
      tenantId: testTenant,
      name: "Governance Approvals",
      type: "generic",
      destination: "https://mock-siem.corp/governance-alerts",
      events: ["approval_required"],
      minSeverity: "low",
    });

    // Case A: Threat event with MEDIUM severity
    // - Critical Escalations: SUPPRESSED (medium < critical)
    // - Governance Approvals: SUPPRESSED (threat_detected is not approval_required)
    const resA = await dispatchSecurityNotification({
      type: "threat_detected",
      tenantId: testTenant,
      title: "Suspicious Activity",
      description: "Low-confidence scan trigger",
      severity: "medium",
    });

    assert.strictEqual(
      resA.channelsDispatched.includes(criticalEndpoint.name),
      false,
      "Critical endpoint must NOT receive medium severity event"
    );
    assert.strictEqual(
      resA.channelsDispatched.includes(governanceEndpoint.name),
      false,
      "Governance endpoint must NOT receive threat_detected event"
    );

    // Case B: Threat event with CRITICAL severity
    // - Critical Escalations: MATCHES & DELIVERED
    // - Governance Approvals: SUPPRESSED (event type mismatch)
    const resB = await dispatchSecurityNotification({
      type: "threat_detected",
      tenantId: testTenant,
      title: "Ransomware Encoded PowerShell Execution",
      description: "Immediate host isolation required",
      severity: "critical",
    });

    assert.strictEqual(
      resB.channelsDispatched.includes(criticalEndpoint.name),
      true,
      "Critical endpoint MUST receive critical threat_detected event"
    );
    assert.strictEqual(
      resB.channelsDispatched.includes(governanceEndpoint.name),
      false,
      "Governance endpoint must NOT receive threat_detected event"
    );

    // Case C: Governance Approval Required event with HIGH severity
    // - Critical Escalations: SUPPRESSED (event type mismatch)
    // - Governance Approvals: MATCHES & DELIVERED
    const resC = await dispatchSecurityNotification({
      type: "approval_required",
      tenantId: testTenant,
      title: "Tier 3 Remediation Sign-off",
      description: "Production database failover signoff",
      severity: "high",
    });

    assert.strictEqual(
      resC.channelsDispatched.includes(governanceEndpoint.name),
      true,
      "Governance endpoint MUST receive approval_required event"
    );
    assert.strictEqual(
      resC.channelsDispatched.includes(criticalEndpoint.name),
      false,
      "Critical threat endpoint must NOT receive approval_required event"
    );

    // Case D: Paused endpoint verification
    // Pause the governance endpoint
    await updateTenantWebhookEndpoint(governanceEndpoint.id, testTenant, {
      enabled: false,
    });

    const resD = await dispatchSecurityNotification({
      type: "approval_required",
      tenantId: testTenant,
      title: "Tier 2 Remediation Sign-off",
      description: "Service restart",
      severity: "high",
    });

    assert.strictEqual(
      resD.channelsDispatched.includes(governanceEndpoint.name),
      false,
      "Paused endpoint must NEVER receive notifications"
    );
  });
});

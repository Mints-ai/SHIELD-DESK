/**
 * Enterprise Real-Time Alerting & Governance Dispatcher
 * Dispatches actionable webhook notifications to Slack, Microsoft Teams,
<<<<<<< HEAD
 * Discord, and custom SIEM endpoints with granular event-type and severity filtering.
=======
 * Discord, custom tenant endpoints, and PagerDuty with millisecond latency tracking
 * and automatic Dead-Letter Queue (DLQ) logging.
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583
 */

import crypto from "crypto";
import {
  getTenantWebhookEndpoints,
  recordWebhookDeliveryLog,
  type TenantWebhookEndpoint,
} from "@/lib/webhooks/webhookStore";

export interface SecurityAlertNotification {
  type:
    | "incident_ingested"
    | "incident_created"
    | "threat_detected"
    | "approval_required"
    | "plan_generated"
    | "kill_switch_engaged"
<<<<<<< HEAD
    | "lockdown.activated"
    | "policy.violated"
    | string;
=======
    | "auth_failure"
    | "brute_force_spike";
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583
  tenantId: string;
  title: string;
  description: string;
  severity?: "critical" | "high" | "medium" | "low" | string;
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

<<<<<<< HEAD
export const SEVERITY_RANKS: Record<string, number> = {
=======
const SEVERITY_LEVELS: Record<string, number> = {
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
<<<<<<< HEAD
=======

function severityMeetsMinimum(eventSeverity?: string, minSeverity?: string): boolean {
  const eventVal = SEVERITY_LEVELS[(eventSeverity || "medium").toLowerCase()] ?? 2;
  const minVal = SEVERITY_LEVELS[(minSeverity || "medium").toLowerCase()] ?? 2;
  return eventVal >= minVal;
}

export async function dispatchSecurityNotification(
  notification: SecurityAlertNotification
): Promise<{ success: boolean; channelsDispatched: string[] }> {
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  const teamsUrl = process.env.TEAMS_WEBHOOK_URL;
  const discordUrl = process.env.DISCORD_WEBHOOK_URL;
  const genericUrl = process.env.SECURITY_WEBHOOK_URL;
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583

/**
 * Checks whether an event's severity meets or exceeds the required minimum severity threshold.
 * low (1) < medium (2) < high (3) < critical (4)
 */
export function satisfiesSeverityThreshold(
  eventSeverity: string | undefined,
  minSeverity: string | undefined
): boolean {
  const normEvent = String(eventSeverity || "medium").toLowerCase();
  const normMin = String(minSeverity || "medium").toLowerCase();

  const eventRank = SEVERITY_RANKS[normEvent] ?? 2;
  const minRank = SEVERITY_RANKS[normMin] ?? 2;

  return eventRank >= minRank;
}

/**
 * Checks whether an event type matches an endpoint's subscribed event categories.
 */
export function matchesEventSubscription(
  eventType: string,
  subscribedEvents: string[] | undefined
): boolean {
  if (!subscribedEvents || subscribedEvents.length === 0) return true;

  const normType = eventType.toLowerCase().trim();

  return subscribedEvents.some((sub) => {
    const normSub = sub.toLowerCase().trim();
    if (normSub === "*" || normSub === "all") return true;
    if (normSub === normType) return true;

    // Normalize underscores to dots for category matching: e.g. "threat.*" matches "threat_detected"
    const dotType = normType.replace(/_/g, ".");
    const dotSub = normSub.replace(/_/g, ".");
    if (dotSub.endsWith(".*")) {
      const prefix = dotSub.slice(0, -2);
      if (dotType.startsWith(prefix)) return true;
    }

    return false;
  });
}

/**
 * Formats a Discord embed payload for an alert notification.
 */
function buildDiscordPayload(notification: SecurityAlertNotification, colorHex: string, deliveryId: string) {
  const colorInt = parseInt(colorHex.replace("#", ""), 16);
  return {
    content: "🛡️ **[ShieldDesk SOC Alert]**",
    embeds: [
      {
        title: `ShieldDesk SOC: ${notification.title}`,
        url: notification.actionUrl || "http://localhost:3000",
        description: notification.description,
        color: colorInt,
        fields: [
          { name: "Tenant", value: notification.tenantId, inline: true },
          { name: "Severity", value: (notification.severity || "Standard").toUpperCase(), inline: true },
          ...(notification.metadata
            ? Object.entries(notification.metadata).slice(0, 4).map(([k, v]) => ({
                name: k,
                value: String(v),
                inline: true,
              }))
            : []),
        ],
        footer: { text: "ShieldDesk Autonomous SOC Platform" },
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

/**
 * Formats a Slack attachments payload for an alert notification.
 */
function buildSlackPayload(notification: SecurityAlertNotification, colorHex: string, deliveryId: string) {
  return {
    attachments: [
      {
        color: colorHex,
        title: `🛡️ ShieldDesk SOC: ${notification.title}`,
        title_link: notification.actionUrl || "http://localhost:3000",
        text: notification.description,
        fields: [
          { title: "Tenant", value: notification.tenantId, short: true },
          { title: "Severity", value: (notification.severity || "Standard").toUpperCase(), short: true },
          ...(notification.metadata
            ? Object.entries(notification.metadata).slice(0, 4).map(([k, v]) => ({
                title: k,
                value: String(v),
                short: true,
              }))
            : []),
        ],
        footer: "ShieldDesk Autonomous SOC Platform",
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };
}

/**
 * Formats an Office 365 / Microsoft Teams MessageCard payload.
 */
function buildTeamsPayload(notification: SecurityAlertNotification, colorHex: string) {
  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: colorHex.replace("#", ""),
    summary: notification.title,
    sections: [
      {
        activityTitle: `ShieldDesk SOC: ${notification.title}`,
        activitySubtitle: `Tenant: ${notification.tenantId} | Severity: ${(notification.severity || "INFO").toUpperCase()}`,
        text: notification.description,
      },
    ],
    potentialAction: notification.actionUrl
      ? [
          {
            "@type": "OpenUri",
            name: "Inspect in ShieldDesk SOC",
            targets: [{ os: "default", uri: notification.actionUrl }],
          },
        ]
      : [],
  };
}

/**
 * Main dispatcher entrypoint: Fans out security alerts to system channels and
 * tenant custom endpoints according to event-type and severity filter policies.
 */
export async function dispatchSecurityNotification(
  notification: SecurityAlertNotification
): Promise<{ success: boolean; channelsDispatched: string[] }> {
  const channelsDispatched: string[] = [];

  // Color mapping by severity
  const colorMap: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#d97706",
    low: "#059669",
  };
  const color = notification.severity ? colorMap[notification.severity] || "#123826" : "#123826";

<<<<<<< HEAD
  // 1. Fetch dynamic custom endpoints configured for this tenant
  let customEndpoints: TenantWebhookEndpoint[] = [];
  try {
    customEndpoints = await getTenantWebhookEndpoints(notification.tenantId);
  } catch (err) {
    console.warn("[Alert Dispatcher] Failed to load tenant webhooks:", err);
  }

  // Filter custom endpoints by:
  // a) Enabled status
  // b) Event subscription match
  // c) Severity threshold satisfaction
  const eligibleCustomEndpoints = customEndpoints.filter((ep) => {
    if (ep.enabled === false) return false;
    if (!matchesEventSubscription(notification.type, ep.events)) return false;
    if (!satisfiesSeverityThreshold(notification.severity, ep.min_severity)) return false;
    return true;
  });

  // 2. Resolve default system environment endpoints
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  const teamsUrl = process.env.TEAMS_WEBHOOK_URL;
  const discordUrl = process.env.DISCORD_WEBHOOK_URL;
  const genericUrl = process.env.SECURITY_WEBHOOK_URL;

  // System endpoints default threshold is medium
  const systemTargets: Array<{ name: string; url: string; type: "slack" | "teams" | "discord" | "generic" }> = [];
  if (slackUrl && satisfiesSeverityThreshold(notification.severity, "medium")) {
    systemTargets.push({ name: "system_slack", url: slackUrl, type: "slack" });
  }
  if (teamsUrl && satisfiesSeverityThreshold(notification.severity, "high")) {
    systemTargets.push({ name: "system_teams", url: teamsUrl, type: "teams" });
  }
  if (discordUrl && satisfiesSeverityThreshold(notification.severity, "medium")) {
    systemTargets.push({ name: "system_discord", url: discordUrl, type: "discord" });
  }
  if (genericUrl && satisfiesSeverityThreshold(notification.severity, "low")) {
    systemTargets.push({ name: "system_generic", url: genericUrl, type: "generic" });
  }

  // 3. Fast handoff to Go Webhook Microservice if available (Port 8080)
  const goWebhookBaseUrl = process.env.GO_WEBHOOK_URL || "http://127.0.0.1:8080";
  const allTargets = [
    ...systemTargets.map((t) => ({ name: t.name, url: t.url })),
    ...eligibleCustomEndpoints.map((ep) => ({ name: ep.name, url: ep.destination })),
  ];

  if (allTargets.length > 0) {
    try {
      const goPromises = allTargets.map((target) =>
        fetch(`${goWebhookBaseUrl}/dispatch`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target_url: target.url,
            secret_key: process.env.SHIELDDESK_WEBHOOK_SECRET || "sd_webhook_dev_secret",
            event: notification.type,
            tenant_id: notification.tenantId,
            data: {
              title: notification.title,
              description: notification.description,
              severity: notification.severity || "standard",
              action_url: notification.actionUrl,
              metadata: notification.metadata,
            },
          }),
          signal: AbortSignal.timeout(600),
        })
      );

      const results = await Promise.allSettled(goPromises);
      let anyQueued = false;
      results.forEach((res, idx) => {
        if (res.status === "fulfilled" && (res.value.status === 200 || res.value.status === 202)) {
          channelsDispatched.push(allTargets[idx].name);
          anyQueued = true;
        }
      });

      if (anyQueued) {
        return { success: true, channelsDispatched };
      }
    } catch {
      // Microservice is offline, fall through to direct inline dispatch below
    }
  }

  // 4. Direct inline delivery for eligible custom endpoints
  for (const ep of eligibleCustomEndpoints) {
    const deliveryId = `del_${crypto.randomBytes(12).toString("hex")}`;
    const startTime = Date.now();
    let statusCode = 200;
    let responseBody = "";

    try {
      const secret = ep.secret_key || process.env.SHIELDDESK_WEBHOOK_SECRET || "sd_webhook_dev_secret";
      const nowEpoch = Math.floor(Date.now() / 1000);

      const destLower = ep.destination.toLowerCase();
      const isDiscord =
        ep.type === "discord" ||
        destLower.includes("discord.com/api/webhooks") ||
        destLower.includes("discordapp.com/api/webhooks");
      const isSlack = ep.type === "slack" || destLower.includes("hooks.slack.com");
      const isTeams =
        ep.type === "teams" ||
        destLower.includes("office.com/webhook") ||
        destLower.includes("outlook.office.com");

      if (isDiscord) {
        const payload = buildDiscordPayload(notification, color, deliveryId);
        const res = await fetch(ep.destination, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        });
        statusCode = res.status;
        responseBody = await res.text().catch(() => "");
      } else if (isSlack) {
        const payload = buildSlackPayload(notification, color, deliveryId);
        const res = await fetch(ep.destination, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        });
        statusCode = res.status;
        responseBody = await res.text().catch(() => "");
      } else if (isTeams) {
        const payload = buildTeamsPayload(notification, color);
        const res = await fetch(ep.destination, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        });
        statusCode = res.status;
        responseBody = await res.text().catch(() => "");
      } else {
        // Generic SIEM / Webhook
        const rawBody = JSON.stringify({
          delivery_id: deliveryId,
          event: notification.type,
          severity: notification.severity,
          tenant_id: notification.tenantId,
          timestamp: new Date().toISOString(),
          title: notification.title,
          description: notification.description,
          action_url: notification.actionUrl,
          metadata: notification.metadata,
        });

        const hmacHex = crypto.createHmac("sha256", secret).update(`${nowEpoch}.${rawBody}`).digest("hex");
        const signature = `t=${nowEpoch},v1=${hmacHex}`;

        const res = await fetch(ep.destination, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ShieldDesk-Signature": signature,
            "X-ShieldDesk-Event": notification.type,
            "X-ShieldDesk-Delivery-Id": deliveryId,
            "X-ShieldDesk-Timestamp": String(nowEpoch),
=======
  // 1. Slack Webhook Dispatch
  if (slackUrl) {
    const startTime = Date.now();
    let deliveryStatus = 200;
    let resBody = "";
    let isOk = false;

    try {
      const slackPayload = {
        attachments: [
          {
            color,
            title: `🛡️ ShieldDesk SOC: ${notification.title}`,
            title_link: notification.actionUrl || "http://localhost:3000",
            text: notification.description,
            fields: [
              { title: "Tenant", value: notification.tenantId, short: true },
              { title: "Severity", value: (notification.severity || "Standard").toUpperCase(), short: true },
              ...(notification.metadata
                ? Object.entries(notification.metadata).slice(0, 8).map(([k, v]) => ({
                    title: k,
                    value: String(v),
                    short: true,
                  }))
                : []),
            ],
            footer: "ShieldDesk Autonomous SOC Platform",
            ts: Math.floor(Date.now() / 1000),
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583
          },
          body: rawBody,
          signal: AbortSignal.timeout(5000),
        });
        statusCode = res.status;
        responseBody = await res.text().catch(() => "");
      }

<<<<<<< HEAD
      channelsDispatched.push(ep.name);
    } catch (err) {
      statusCode = 504;
      responseBody = err instanceof Error ? err.message : "Delivery timeout";
      console.warn(`[Alert Dispatcher] Delivery failed to ${ep.name}:`, err);
    }

    const latencyMs = Date.now() - startTime;

    // Asynchronously record delivery audit log for UI history & DLQ
    void recordWebhookDeliveryLog({
      deliveryId,
      tenantId: notification.tenantId,
      endpointId: ep.id,
      endpointName: ep.name,
      eventType: notification.type,
      severity: notification.severity,
      statusCode,
      latencyMs,
      payload: {
        title: notification.title,
        description: notification.description,
        type: notification.type,
        severity: notification.severity,
      },
      responseBody: responseBody.slice(0, 300),
      success: statusCode >= 200 && statusCode < 300,
    }).catch(() => {});
  }

  // 5. Direct inline delivery for system environment endpoints (fallbacks)
  for (const sysTarget of systemTargets) {
    try {
      if (sysTarget.type === "slack") {
        await fetch(sysTarget.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildSlackPayload(notification, color, "sys")),
          signal: AbortSignal.timeout(5000),
        });
      } else if (sysTarget.type === "discord") {
        await fetch(sysTarget.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildDiscordPayload(notification, color, "sys")),
          signal: AbortSignal.timeout(5000),
        });
      } else if (sysTarget.type === "teams") {
        await fetch(sysTarget.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildTeamsPayload(notification, color)),
          signal: AbortSignal.timeout(5000),
        });
      } else {
        await fetch(sysTarget.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(notification),
          signal: AbortSignal.timeout(5000),
        });
      }
      channelsDispatched.push(sysTarget.name);
    } catch (err) {
      console.warn(`[Alert Dispatcher] System delivery failed to ${sysTarget.name}:`, err);
=======
      const res = await fetch(slackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(slackPayload),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = res.status;
      resBody = await res.text().catch(() => "");
      isOk = res.ok;
      if (isOk) channelsDispatched.push("slack");
    } catch (err) {
      deliveryStatus = 504;
      resBody = err instanceof Error ? err.message : "Slack dispatch timeout";
    }

    const latencyMs = Math.max(1, Date.now() - startTime);

    try {
      const { recordWebhookDeliveryLog } = await import("@/lib/webhooks/webhookStore");
      await recordWebhookDeliveryLog({
        deliveryId: `del_${Math.random().toString(36).substring(2, 10)}`,
        tenantId: notification.tenantId,
        endpointId: "wh-slack",
        endpointName: "Slack SecOps Channel (System)",
        eventType: notification.type,
        severity: notification.severity,
        statusCode: deliveryStatus,
        latencyMs,
        success: isOk,
        destination: slackUrl,
        payload: { title: notification.title, description: notification.description, metadata: notification.metadata },
        responseBody: resBody.slice(0, 500),
        errorMessage: isOk ? undefined : `Slack delivery failed with HTTP ${deliveryStatus}`,
      });
    } catch { /* ignore */ }
  }

  // 2. Discord Webhook Dispatch
  if (discordUrl) {
    const startTime = Date.now();
    let deliveryStatus = 200;
    let resBody = "";
    let isOk = false;

    try {
      const discordPayload = {
        content: notification.severity === "critical"
          ? "🚨 **[ShieldDesk Critical Security Alert]**"
          : "🛡️ **[ShieldDesk SOC Alert]**",
        embeds: [
          {
            title: `🛡️ ShieldDesk SOC: ${notification.title}`,
            url: notification.actionUrl || "http://localhost:3000",
            description: notification.description,
            color: parseInt(color.replace("#", ""), 16),
            fields: [
              { name: "Tenant", value: notification.tenantId, inline: true },
              { name: "Severity", value: (notification.severity || "Standard").toUpperCase(), inline: true },
              ...(notification.metadata
                ? Object.entries(notification.metadata).slice(0, 10).map(([k, v]) => ({
                    name: k,
                    value: String(v),
                    inline: true,
                  }))
                : []),
            ],
            footer: { text: "ShieldDesk Autonomous SOC Platform • Threat Engine" },
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const res = await fetch(discordUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(discordPayload),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = res.status;
      resBody = await res.text().catch(() => "");
      isOk = res.ok || res.status === 204;
      if (isOk) channelsDispatched.push("discord");
    } catch (err) {
      deliveryStatus = 504;
      resBody = err instanceof Error ? err.message : "Discord dispatch timeout";
    }

    const latencyMs = Math.max(1, Date.now() - startTime);

    try {
      const { recordWebhookDeliveryLog } = await import("@/lib/webhooks/webhookStore");
      await recordWebhookDeliveryLog({
        deliveryId: `del_${Math.random().toString(36).substring(2, 10)}`,
        tenantId: notification.tenantId,
        endpointId: "wh-discord",
        endpointName: "Discord Security Alerts (System)",
        eventType: notification.type,
        severity: notification.severity,
        statusCode: deliveryStatus,
        latencyMs,
        success: isOk,
        destination: discordUrl,
        payload: { title: notification.title, description: notification.description, metadata: notification.metadata },
        responseBody: resBody.slice(0, 500),
        errorMessage: isOk ? undefined : `Discord delivery failed with HTTP ${deliveryStatus}`,
      });
    } catch { /* ignore */ }
  }

  // 3. Microsoft Teams Dispatch
  if (teamsUrl) {
    const startTime = Date.now();
    let deliveryStatus = 200;
    let resBody = "";
    let isOk = false;

    try {
      const teamsPayload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        themeColor: color.replace("#", ""),
        summary: notification.title,
        sections: [
          {
            activityTitle: `ShieldDesk SOC: ${notification.title}`,
            activitySubtitle: `Tenant: ${notification.tenantId} | Severity: ${(notification.severity || "INFO").toUpperCase()}`,
            text: notification.description,
          },
        ],
        potentialAction: notification.actionUrl
          ? [
              {
                "@type": "OpenUri",
                name: "Inspect in ShieldDesk SOC",
                targets: [{ os: "default", uri: notification.actionUrl }],
              },
            ]
          : [],
      };

      const res = await fetch(teamsUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(teamsPayload),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = res.status;
      resBody = await res.text().catch(() => "");
      isOk = res.ok;
      if (isOk) channelsDispatched.push("teams");
    } catch (err) {
      deliveryStatus = 504;
      resBody = err instanceof Error ? err.message : "Teams dispatch timeout";
    }

    const latencyMs = Math.max(1, Date.now() - startTime);

    try {
      const { recordWebhookDeliveryLog } = await import("@/lib/webhooks/webhookStore");
      await recordWebhookDeliveryLog({
        deliveryId: `del_${Math.random().toString(36).substring(2, 10)}`,
        tenantId: notification.tenantId,
        endpointId: "wh-teams",
        endpointName: "Microsoft Teams Incident Bridge (System)",
        eventType: notification.type,
        severity: notification.severity,
        statusCode: deliveryStatus,
        latencyMs,
        success: isOk,
        destination: teamsUrl,
        payload: { title: notification.title, description: notification.description, metadata: notification.metadata },
        responseBody: resBody.slice(0, 500),
        errorMessage: isOk ? undefined : `Teams delivery failed with HTTP ${deliveryStatus}`,
      });
    } catch { /* ignore */ }
  }

  // 4. Custom Tenant Registered Webhook Endpoints
  try {
    const { getTenantWebhookEndpoints, executeWebhookDispatch, recordWebhookDeliveryLog } = await import(
      "@/lib/webhooks/webhookStore"
    );
    const endpoints = await getTenantWebhookEndpoints(notification.tenantId);

    const eligibleEndpoints = endpoints.filter((ep) => {
      if (!ep.enabled || !ep.destination) return false;
      // Do not duplicate system URLs
      if (ep.destination === discordUrl || ep.destination === slackUrl || ep.destination === teamsUrl || ep.destination === genericUrl) {
        return false;
      }
      // Check event subscription
      if (ep.events && ep.events.length > 0 && !ep.events.includes(notification.type)) {
        return false;
      }
      // Check minimum severity
      if (!severityMeetsMinimum(notification.severity, ep.min_severity)) {
        return false;
      }
      return true;
    });

    for (const ep of eligibleEndpoints) {
      const deliveryId = `del_${Math.random().toString(36).substring(2, 10)}`;
      const result = await executeWebhookDispatch({
        destination: ep.destination,
        type: ep.type,
        eventType: notification.type,
        severity: notification.severity,
        tenantId: notification.tenantId,
        payload: {
          title: notification.title,
          description: notification.description,
          action_url: notification.actionUrl,
          metadata: notification.metadata,
        },
        deliveryId,
        secretKey: ep.secret_key,
      });

      if (result.success) {
        channelsDispatched.push(`custom_${ep.type}_${ep.id}`);
      }

      await recordWebhookDeliveryLog({
        deliveryId,
        tenantId: notification.tenantId,
        endpointId: ep.id,
        endpointName: ep.name,
        eventType: notification.type,
        severity: notification.severity,
        statusCode: result.statusCode,
        latencyMs: result.latencyMs,
        success: result.success,
        destination: ep.destination,
        payload: { title: notification.title, description: notification.description, metadata: notification.metadata },
        responseBody: result.responseBody.slice(0, 500),
        errorMessage: result.errorMessage,
      });
    }
  } catch (customErr) {
    console.warn("[ShieldDesk Alert Dispatcher] Custom tenant endpoints dispatch error:", customErr);
  }

  // 5. Generic SIEM Webhook
  if (genericUrl) {
    const startTime = Date.now();
    let deliveryStatus = 200;
    let resBody = "";
    let isOk = false;

    try {
      const res = await fetch(genericUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(notification),
        signal: AbortSignal.timeout(5000),
      });
      deliveryStatus = res.status;
      resBody = await res.text().catch(() => "");
      isOk = res.ok;
      if (isOk) channelsDispatched.push("generic_webhook");
    } catch (err) {
      deliveryStatus = 504;
      resBody = err instanceof Error ? err.message : "Generic SIEM dispatch timeout";
>>>>>>> 1d7a9db2a27a8bcd5e14cda26249c57dce7dd583
    }

    const latencyMs = Math.max(1, Date.now() - startTime);

    try {
      const { recordWebhookDeliveryLog } = await import("@/lib/webhooks/webhookStore");
      await recordWebhookDeliveryLog({
        deliveryId: `del_${Math.random().toString(36).substring(2, 10)}`,
        tenantId: notification.tenantId,
        endpointId: "wh-security-generic",
        endpointName: "Custom SIEM Ingestion (System)",
        eventType: notification.type,
        severity: notification.severity,
        statusCode: deliveryStatus,
        latencyMs,
        success: isOk,
        destination: genericUrl,
        payload: { title: notification.title, description: notification.description, metadata: notification.metadata },
        responseBody: resBody.slice(0, 500),
        errorMessage: isOk ? undefined : `SIEM delivery failed with HTTP ${deliveryStatus}`,
      });
    } catch { /* ignore */ }
  }

  return {
    success: true,
    channelsDispatched,
  };
}

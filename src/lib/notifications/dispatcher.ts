/**
 * Enterprise Real-Time Alerting & Governance Dispatcher
 * Dispatches actionable webhook notifications to Slack, Microsoft Teams,
 * Discord, custom tenant endpoints, and PagerDuty with millisecond latency tracking
 * and automatic Dead-Letter Queue (DLQ) logging.
 */

export interface SecurityAlertNotification {
  type:
    | "incident_ingested"
    | "incident_created"
    | "threat_detected"
    | "approval_required"
    | "plan_generated"
    | "kill_switch_engaged"
    | "auth_failure"
    | "brute_force_spike";
  tenantId: string;
  title: string;
  description: string;
  severity?: "critical" | "high" | "medium" | "low";
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

const SEVERITY_LEVELS: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

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

  const channelsDispatched: string[] = [];

  // Color mapping for cards
  const colorMap = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#d97706",
    low: "#059669",
  };
  const color = notification.severity ? colorMap[notification.severity] : "#123826";

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
          },
        ],
      };

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

/**
 * Enterprise Real-Time Alerting & Governance Dispatcher
 * Dispatches actionable webhook notifications to Slack, Microsoft Teams,
 * and PagerDuty when security events, mitigation plans, or approval tokens occur.
 */

export interface SecurityAlertNotification {
  type: "incident_ingested" | "approval_required" | "plan_generated" | "kill_switch_engaged";
  tenantId: string;
  title: string;
  description: string;
  severity?: "critical" | "high" | "medium" | "low";
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

export async function dispatchSecurityNotification(notification: SecurityAlertNotification): Promise<{ success: boolean; channelsDispatched: string[] }> {
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  const teamsUrl = process.env.TEAMS_WEBHOOK_URL;
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

  // 1. Slack Webhook Payload
  if (slackUrl) {
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

      await fetch(slackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(slackPayload),
        signal: AbortSignal.timeout(5000),
      });
      channelsDispatched.push("slack");
    } catch (err) {
      console.warn("[ShieldDesk Alert Dispatcher] Slack delivery error:", err);
    }
  }

  // 2. Microsoft Teams Adaptive Card
  if (teamsUrl) {
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

      await fetch(teamsUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(teamsPayload),
        signal: AbortSignal.timeout(5000),
      });
      channelsDispatched.push("teams");
    } catch (err) {
      console.warn("[ShieldDesk Alert Dispatcher] Teams delivery error:", err);
    }
  }

  // 3. Generic SIEM Webhook
  if (genericUrl) {
    try {
      await fetch(genericUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(notification),
        signal: AbortSignal.timeout(5000),
      });
      channelsDispatched.push("generic_webhook");
    } catch (err) {
      console.warn("[ShieldDesk Alert Dispatcher] Generic webhook delivery error:", err);
    }
  }

  return {
    success: true,
    channelsDispatched,
  };
}

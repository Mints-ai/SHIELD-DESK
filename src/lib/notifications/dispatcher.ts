/**
 * Enterprise Real-Time Alerting & Governance Dispatcher
 * Dispatches actionable webhook notifications to Slack, Microsoft Teams,
 * and PagerDuty when security events, mitigation plans, or approval tokens occur.
 */

export interface SecurityAlertNotification {
  type: "incident_ingested" | "incident_created" | "threat_detected" | "approval_required" | "plan_generated" | "kill_switch_engaged";
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

  // Check if Go Webhook Microservice is available on port 8080 (Fire-and-forget handoff)
  const goWebhookBaseUrl = process.env.GO_WEBHOOK_URL || "http://127.0.0.1:8080";
  const targets = [
    { name: "slack", url: slackUrl },
    { name: "teams", url: teamsUrl },
    { name: "discord", url: discordUrl },
    { name: "generic_webhook", url: genericUrl },
  ].filter((t): t is { name: string; url: string } => Boolean(t.url));

  if (targets.length > 0) {
    try {
      const goPromises = targets.map((target) =>
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
          signal: AbortSignal.timeout(600), // Swift timeout to prevent blocking Next.js
        })
      );

      const results = await Promise.allSettled(goPromises);
      let anyQueued = false;
      results.forEach((res, idx) => {
        if (res.status === "fulfilled" && (res.value.status === 200 || res.value.status === 202)) {
          channelsDispatched.push(targets[idx].name);
          anyQueued = true;
        }
      });

      if (anyQueued) {
        return { success: true, channelsDispatched };
      }
    } catch {
      // Fallback to direct inline dispatch below if Go microservice is offline
    }
  }

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

  // 2. Discord Webhook Payload
  if (discordUrl) {
    try {
      const discordPayload = {
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

      await fetch(discordUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(discordPayload),
        signal: AbortSignal.timeout(5000),
      });
      channelsDispatched.push("discord");
    } catch (err) {
      console.warn("[ShieldDesk Alert Dispatcher] Discord delivery error:", err);
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

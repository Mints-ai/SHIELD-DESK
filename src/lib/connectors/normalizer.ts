import crypto from "node:crypto";
import { EventSeverity, UniversalSecurityEvent } from "./types";

export class ConnectorNormalizer {
  /**
   * Normalizes Wazuh JSON alert payload into canonical UniversalSecurityEvent.
   */
  public static normalizeWazuh(
    payload: Record<string, unknown>,
    tenantId: string
  ): UniversalSecurityEvent {
    const rule = (payload.rule as Record<string, unknown>) || {};
    const agent = (payload.agent as Record<string, unknown>) || {};
    const data = (payload.data as Record<string, unknown>) || {};
    const win = (data.win as Record<string, unknown>) || {};
    const eventdata = (win.eventdata as Record<string, unknown>) || {};

    const level = Number(rule.level || 3);
    let severity: EventSeverity = "low";
    if (level >= 12) severity = "critical";
    else if (level >= 8) severity = "high";
    else if (level >= 5) severity = "medium";

    const externalId = String(payload.id || rule.id || `wazuh-${Date.now()}`);
    const eventId = `sec-evt-${crypto.createHash("sha256").update(tenantId + externalId).digest("hex").slice(0, 16)}`;

    return {
      id: eventId,
      tenantId,
      source: "wazuh",
      externalId,
      timestamp: String(payload.timestamp || new Date().toISOString()),
      severity,
      title: String(rule.description || "Wazuh Security Detection Alert"),
      description: `Wazuh Rule ${rule.id || "N/A"}: ${rule.description || "Detected security anomaly"}`,
      affectedAsset: {
        id: String(agent.id || ""),
        hostname: String(agent.name || "wazuh-agent"),
        ip: String(agent.ip || ""),
      },
      processContext: eventdata.image
        ? {
            name: String(eventdata.image).split(/[\\/]/).pop(),
            commandLine: String(eventdata.commandLine || ""),
            pid: Number(eventdata.processId) || undefined,
            sha256: String(eventdata.hashes || ""),
            user: String(eventdata.user || ""),
          }
        : undefined,
      tags: Array.isArray(rule.groups) ? (rule.groups as string[]) : ["wazuh", "siem"],
      rawPayload: payload,
    };
  }

  /**
   * Normalizes Microsoft Defender for Endpoint alert/incident payload.
   */
  public static normalizeDefender(
    payload: Record<string, unknown>,
    tenantId: string
  ): UniversalSecurityEvent {
    const alertId = String(payload.id || payload.alertId || `defender-${Date.now()}`);
    const rawSeverity = String(payload.severity || "Medium").toLowerCase();

    let severity: EventSeverity = "medium";
    if (rawSeverity.includes("crit")) severity = "critical";
    else if (rawSeverity.includes("high")) severity = "high";
    else if (rawSeverity.includes("low") || rawSeverity.includes("informational")) severity = "low";

    const machineId = String(payload.machineId || payload.computerDnsName || "defender-endpoint");
    const eventId = `sec-evt-${crypto.createHash("sha256").update(tenantId + alertId).digest("hex").slice(0, 16)}`;

    return {
      id: eventId,
      tenantId,
      source: "defender",
      externalId: alertId,
      timestamp: String(payload.alertCreationTime || new Date().toISOString()),
      severity,
      title: String(payload.title || "Microsoft Defender Endpoint Alert"),
      description: String(payload.description || "Endpoint detection alert from Microsoft Defender"),
      affectedAsset: {
        id: machineId,
        hostname: String(payload.computerDnsName || machineId),
      },
      tags: ["microsoft-defender", String(payload.category || "threat")],
      rawPayload: payload,
    };
  }

  /**
   * Normalizes CrowdStrike Falcon detection streaming payload.
   */
  public static normalizeCrowdStrike(
    payload: Record<string, unknown>,
    tenantId: string
  ): UniversalSecurityEvent {
    const detectId = String(payload.detection_id || payload.CompositeId || `falcon-${Date.now()}`);
    const rawSeverity = Number(payload.Severity || payload.severity || 2);

    let severity: EventSeverity = "medium";
    if (rawSeverity >= 4) severity = "critical";
    else if (rawSeverity === 3) severity = "high";
    else if (rawSeverity <= 1) severity = "low";

    const device = (payload.device as Record<string, unknown>) || {};
    const eventId = `sec-evt-${crypto.createHash("sha256").update(tenantId + detectId).digest("hex").slice(0, 16)}`;

    return {
      id: eventId,
      tenantId,
      source: "crowdstrike",
      externalId: detectId,
      timestamp: String(payload.ProcessStartTime || new Date().toISOString()),
      severity,
      title: String(payload.DetectName || payload.Tactic || "CrowdStrike Falcon Detection"),
      description: String(payload.DetectDescription || payload.Technique || "Suspicious behavior identified on sensor"),
      affectedAsset: {
        id: String(device.device_id || payload.aid || ""),
        hostname: String(device.hostname || payload.ComputerName || "falcon-sensor"),
        os: String(device.os_version || payload.OSVersion || ""),
      },
      processContext: {
        name: String(payload.FileName || ""),
        commandLine: String(payload.CommandLine || ""),
        sha256: String(payload.SHA256String || ""),
      },
      tags: ["crowdstrike", String(payload.Tactic || "execution"), String(payload.Technique || "behavior")],
      rawPayload: payload,
    };
  }

  /**
   * Normalizes generic webhook payload.
   */
  public static normalizeGenericWebhook(
    payload: Record<string, unknown>,
    tenantId: string
  ): UniversalSecurityEvent {
    const extId = String(payload.id || payload.eventId || `webhook-${Date.now()}`);
    const severityStr = String(payload.severity || "medium").toLowerCase();
    const severity: EventSeverity =
      severityStr === "critical"
        ? "critical"
        : severityStr === "high"
        ? "high"
        : severityStr === "low"
        ? "low"
        : "medium";

    const eventId = `sec-evt-${crypto.createHash("sha256").update(tenantId + extId).digest("hex").slice(0, 16)}`;

    return {
      id: eventId,
      tenantId,
      source: "webhook",
      externalId: extId,
      timestamp: String(payload.timestamp || new Date().toISOString()),
      severity,
      title: String(payload.title || "Generic Ingested Security Alert"),
      description: String(payload.description || "Alert ingested via Universal Webhook connector"),
      affectedAsset: {
        hostname: String(payload.hostname || payload.asset || "unknown-host"),
        ip: String(payload.ip || ""),
      },
      tags: ["webhook", "custom-siem"],
      rawPayload: payload,
    };
  }
}

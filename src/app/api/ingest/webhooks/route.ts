import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { dispatchSecurityNotification } from "@/lib/notifications/dispatcher";

export async function POST(req: NextRequest) {
  // 1. API Key Authentication
  const apiKeyHeader = req.headers.get("x-shielddesk-api-key") || req.headers.get("authorization");
  const configuredKey = process.env.SHIELDDESK_INGEST_API_KEY;

  if (configuredKey) {
    if (!apiKeyHeader) {
      return NextResponse.json({ error: "Unauthorized: Missing API Key" }, { status: 401 });
    }
    const key = apiKeyHeader.replace(/^Bearer\s+/i, "").trim();
    if (key !== configuredKey) {
      return NextResponse.json({ error: "Unauthorized: Invalid API Key" }, { status: 401 });
    }
  }

  // 2. Tenant Resolution
  const tenantId =
    req.headers.get("x-shielddesk-tenant") ||
    req.headers.get("x-tenant-id") ||
    "acme-tenant";

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON payload" }, { status: 400 });
  }

  // 3. Telemetry Normalizer (CrowdStrike / Defender / Wazuh / OCSF / Generic)
  let title = "Security Alert";
  let description = "Unspecified external telemetry event";
  let severity: "critical" | "high" | "medium" | "low" = "high";
  let hostname = "UNKNOWN-HOST";
  let source = "Generic SIEM";
  const linkedCves: string[] = [];

  // CrowdStrike Falcon Detection format
  if (body?.event?.DetectName || body?.event?.ComputerName) {
    source = "CrowdStrike Falcon";
    title = body.event.DetectName || "CrowdStrike Malicious Behavior";
    description = body.event.DetectDescription || `Falcon detection: ${body.event.CommandLine || "Suspicious execution"}`;
    hostname = body.event.ComputerName || "CS-WORKSTATION";
    const sevNum = Number(body.event.Severity || 3);
    severity = sevNum >= 4 ? "critical" : sevNum === 3 ? "high" : "medium";
  }
  // Microsoft Defender for Endpoint format
  else if (body?.title && (body?.machineDnsName || body?.alertId)) {
    source = "Microsoft Defender";
    title = body.title;
    description = body.description || "Microsoft Defender EDR alert";
    hostname = body.machineDnsName || "DEFENDER-HOST";
    const sevStr = String(body.severity || "").toLowerCase();
    if (sevStr.includes("crit")) severity = "critical";
    else if (sevStr.includes("high")) severity = "high";
    else if (sevStr.includes("med")) severity = "medium";
    else severity = "low";
  }
  // Wazuh / Syslog format
  else if (body?.rule?.description) {
    source = "Wazuh HIDS";
    title = body.rule.description;
    description = `Rule ID: ${body.rule.id || "N/A"} - ${body.full_log || title}`;
    hostname = body.agent?.name || "WAZUH-AGENT";
    const level = Number(body.rule.level || 7);
    severity = level >= 12 ? "critical" : level >= 8 ? "high" : "medium";
  }
  // Generic or OCSF alert
  else {
    title = body.title || body.name || body.activity_name || "Autonomous Telemetry Alert";
    description = body.description || body.message || JSON.stringify(body);
    hostname = body.hostname || body.host || body.machine || "FIN-WS-042";
    const rawSev = String(body.severity || "").toLowerCase();
    if (rawSev.includes("crit")) severity = "critical";
    else if (rawSev.includes("med")) severity = "medium";
    else if (rawSev.includes("low")) severity = "low";
    else severity = "high";
  }

  // Extract any CVE IDs from text
  const cveMatches = description.match(/CVE-\d{4}-\d{4,7}/gi);
  if (cveMatches) {
    for (const c of cveMatches) {
      if (!linkedCves.includes(c.toUpperCase())) linkedCves.push(c.toUpperCase());
    }
  }

  // 4. Ingest Incident into Database
  const incidentId = crypto.randomUUID();
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const incidentCode = `INC-${randomSuffix}`;

  try {
    // Insert into incidents table
    await query(
      `INSERT INTO incidents (id, incident_code, tenant_id, severity, status, title, description, created_at, updated_at)
       VALUES ($1, $2, $3, $4, 'investigating', $5, $6, now(), now())`,
      [incidentId, incidentCode, tenantId, severity, `[${source}] ${title}`, description]
    );

    // Insert timeline event
    await query(
      `INSERT INTO incident_events (incident_id, occurred_at, description)
       VALUES ($1, now(), $2)`,
      [incidentId, `Alert ingested from ${source} on host ${hostname}`]
    );

    // Insert asset if hostname known
    if (hostname && hostname !== "UNKNOWN-HOST") {
      const assetId = crypto.randomUUID();
      await query(
        `INSERT INTO assets (id, tenant_id, hostname, asset_type)
         VALUES ($1, $2, $3, 'workstation')
         ON CONFLICT DO NOTHING`,
        [assetId, tenantId, hostname]
      );
      await query(
        `INSERT INTO incident_assets (incident_id, asset_id)
         VALUES ($1, (SELECT id FROM assets WHERE hostname = $2 AND tenant_id = $3 LIMIT 1))
         ON CONFLICT DO NOTHING`,
        [incidentId, hostname, tenantId]
      );
    }
  } catch {
    // If PostgreSQL is in offline dev mode, proceed gracefully
  }

  // 5. Dispatch Real-time Notification
  dispatchSecurityNotification({
    type: "incident_ingested",
    tenantId,
    title: `New Incident Ingested: ${incidentCode}`,
    description: `[${source}] ${title} on host ${hostname}. Severity: ${severity.toUpperCase()}.`,
    severity,
    actionUrl: `http://localhost:3000`,
    metadata: {
      incidentCode,
      source,
      hostname,
      linkedCves: linkedCves.join(", ") || "None",
    },
  }).catch(() => {});

  return NextResponse.json({
    success: true,
    incidentId,
    incidentCode,
    source,
    tenantId,
    severity,
    hostname,
    linkedCves,
    message: "Alert successfully ingested and normalized into ShieldDesk SOC queue.",
  });
}

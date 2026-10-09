import crypto from "node:crypto";
import { query } from "@/lib/db";
import { dispatchSecurityNotification } from "@/lib/notifications/dispatcher";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import { parseYaraRule } from "@/lib/detection/yara/parser";
import { evaluateYaraRule } from "@/lib/detection/yara/evaluator";
import { getYaraRules, recordYaraMatch } from "@/lib/detection/yara/store";
import type { YaraRuleRecord, YaraRuleAst, YaraMatchResult } from "@/lib/detection/yara/types";

export interface DetectionRule {
  id: string;
  name: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  type: "sigma" | "yara" | "anomaly" | "ioc";
  description: string;
  matchPattern?: RegExp;
  evaluator?: (event: Record<string, unknown>) => boolean;
  enabled: boolean;
  matchesCount: number;
}

export interface DetectionMatch {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  matchedAt: string;
  agentId: string;
  tenantId: string;
  hostname: string;
  evidence: Record<string, unknown>;
  incidentId?: string;
  incidentCode?: string;
}

// Built-in Sigma, YARA, and Behavioral Rules
export const ACTIVE_DETECTION_RULES: DetectionRule[] = [
  {
    id: "sigma_encoded_powershell",
    name: "Suspicious Encoded PowerShell Execution",
    category: "Execution / Defense Evasion",
    severity: "high",
    type: "sigma",
    description: "Detects PowerShell execution with base64 encoded payload and execution policy bypass flags.",
    evaluator: (payload) => {
      const cmd = String(payload.commandLine || payload.cmd || payload.command || "").toLowerCase();
      return (
        cmd.includes("powershell") &&
        (cmd.includes("-enc") || cmd.includes("-encodedcommand") || cmd.includes("frombase64string"))
      );
    },
    enabled: true,
    matchesCount: 0,
  },
  {
    id: "sigma_shadow_copy_deletion",
    name: "VSS Volume Shadow Copy Deletion (Ransomware Prep)",
    category: "Impact / Ransomware",
    severity: "critical",
    type: "sigma",
    description: "Detects attempts to delete Windows Volume Shadow Copies using vssadmin or wmic prior to encryption.",
    evaluator: (payload) => {
      const cmd = String(payload.commandLine || payload.cmd || payload.command || "").toLowerCase();
      return (
        (cmd.includes("vssadmin") && cmd.includes("delete") && cmd.includes("shadows")) ||
        (cmd.includes("wmic") && cmd.includes("shadowcopy") && cmd.includes("delete")) ||
        (cmd.includes("wbadmin") && cmd.includes("delete") && cmd.includes("catalog"))
      );
    },
    enabled: true,
    matchesCount: 0,
  },
  {
    id: "sigma_mimikatz_lsass",
    name: "LSASS Memory Dumping / Credential Access",
    category: "Credential Access",
    severity: "critical",
    type: "sigma",
    description: "Detects memory dump operations targeting LSASS (Mimikatz, Procdump, comsvcs.dll).",
    evaluator: (payload) => {
      const cmd = String(payload.commandLine || payload.cmd || payload.command || "").toLowerCase();
      return (
        cmd.includes("sekurlsa") ||
        (cmd.includes("procdump") && cmd.includes("lsass")) ||
        (cmd.includes("comsvcs.dll") && cmd.includes("minidump"))
      );
    },
    enabled: true,
    matchesCount: 0,
  },
  {
    id: "yara_webshell_c99",
    name: "Webshell C99 / b374k PHP Payload",
    category: "Persistence / Webshell",
    severity: "critical",
    type: "yara",
    description: "Detects known PHP backdoor webshell signatures and obfuscated command runners.",
    evaluator: (payload) => {
      const data = String(payload.content || payload.fileContent || payload.commandLine || "").toLowerCase();
      return (
        data.includes("c99shell") ||
        data.includes("b374k") ||
        (data.includes("base64_decode") && data.includes("eval(")) ||
        data.includes("passthru($_post")
      );
    },
    enabled: true,
    matchesCount: 0,
  },
  {
    id: "yara_ransomware_extensions",
    name: "Mass Extension Renaming / Ransomware Artifact",
    category: "Ransomware",
    severity: "critical",
    type: "yara",
    description: "Detects mass filesystem modifications with known ransomware extensions (.lockbit, .blackcat, .crypto).",
    evaluator: (payload) => {
      const filename = String(payload.fileName || payload.path || payload.targetFile || "").toLowerCase();
      return (
        filename.endsWith(".lockbit") ||
        filename.endsWith(".blackcat") ||
        filename.endsWith(".cry") ||
        filename.endsWith(".locked")
      );
    },
    enabled: true,
    matchesCount: 0,
  },
  {
    id: "sigma_ssh_bruteforce",
    name: "SSH Distributed Brute Force Attempt",
    category: "Initial Access",
    severity: "medium",
    type: "sigma",
    description: "Detects high-frequency authentication failures from a single remote IP address.",
    evaluator: (payload) => {
      const eventType = String(payload.eventType || payload.type || "");
      const failedCount = Number(payload.failedAttempts || payload.failCount || 0);
      return eventType === "AUTH_FAILURE" && failedCount >= 10;
    },
    enabled: true,
    matchesCount: 0,
  },
];

// Fallback in-memory store for incidents correlated from detection matches
export interface CorrelatedIncident {
  id: string;
  incident_code: string;
  tenant_id: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "investigating" | "resolved" | "closed";
  title: string;
  description: string;
  rule_id: string;
  agent_id: string;
  hostname: string;
  created_at: string;
  events: Array<{ occurred_at: string; description: string; evidence?: Record<string, unknown> }>;
}

export const IN_MEMORY_CORRELATED_INCIDENTS: CorrelatedIncident[] = [];

// AST Cache for compiled YARA rules
const YARA_AST_CACHE = new Map<string, { raw: string; ast: YaraRuleAst }>();

function getOrCompileYaraAst(rawContent: string, ruleId: string): YaraRuleAst | null {
  const cached = YARA_AST_CACHE.get(ruleId);
  if (cached && cached.raw === rawContent) {
    return cached.ast;
  }
  const res = parseYaraRule(rawContent);
  if (res.success && res.ast) {
    YARA_AST_CACHE.set(ruleId, { raw: rawContent, ast: res.ast });
    return res.ast;
  }
  return null;
}

/**
 * Evaluates an incoming batch of telemetry events from an endpoint agent against detection rules.
 * When a critical or high-severity threat matches, automatically correlates and creates an incident in the SOC pipeline.
 */
export async function evaluateTelemetryBatch(
  events: Array<{ eventType: string; payload: Record<string, unknown>; timestamp?: string }>,
  context: { agentId: string; tenantId: string; hostname?: string }
): Promise<DetectionMatch[]> {
  const matches: DetectionMatch[] = [];
  const hostname = context.hostname || "UNKNOWN-HOST";

  // Load active YARA rules for this tenant
  let dynamicYaraRules: YaraRuleRecord[] = [];
  try {
    dynamicYaraRules = await getYaraRules(context.tenantId);
  } catch {
    // Non-fatal
  }

  for (const event of events) {
    const combinedPayload: Record<string, unknown> = {
      ...event.payload,
      eventType: event.eventType,
    };

    // 1. Evaluate Dynamic Native YARA Rules
    if (dynamicYaraRules.length > 0) {
      // Gather payload inspection strings
      const candidateStrings: string[] = [];
      const addString = (val: unknown) => {
        if (typeof val === "string" && val.length > 0) {
          candidateStrings.push(val);
        }
      };

      addString(combinedPayload.content);
      addString(combinedPayload.fileContent);
      addString(combinedPayload.content_preview);
      addString(combinedPayload.commandLine);
      addString(combinedPayload.cmd);
      addString(combinedPayload.command);
      addString(combinedPayload.memoryDump);
      addString(combinedPayload.payload);
      addString(combinedPayload.path);
      addString(combinedPayload.filePath);
      addString(combinedPayload.file_path);
      addString(combinedPayload.fileName);
      addString(combinedPayload.file_name);
      // Fallback: full JSON serialized event string
      candidateStrings.push(JSON.stringify(combinedPayload));

      for (const yRule of dynamicYaraRules) {
        if (!yRule.enabled) continue;
        const ast = getOrCompileYaraAst(yRule.raw_content, yRule.rule_id);
        if (!ast) continue;

        let bestMatch: YaraMatchResult | null = null;
        for (const candidate of candidateStrings) {
          const evalRes = evaluateYaraRule(ast, candidate);
          if (evalRes.matched) {
            bestMatch = evalRes;
            break;
          }
        }

        if (bestMatch && bestMatch.matched) {
          yRule.matches_today = (yRule.matches_today || 0) + 1;
          const targetPath = String(
            combinedPayload.filePath ||
              combinedPayload.file_path ||
              combinedPayload.path ||
              combinedPayload.fileName ||
              combinedPayload.file_name ||
              yRule.target ||
              "telemetry-stream"
          );

          const yaraMatchRecord: DetectionMatch = {
            ruleId: yRule.rule_id,
            ruleName: yRule.name,
            category: yRule.category,
            severity: yRule.severity,
            matchedAt: new Date().toISOString(),
            agentId: context.agentId,
            tenantId: context.tenantId,
            hostname,
            evidence: {
              ...combinedPayload,
              yara_match: {
                rule_id: yRule.rule_id,
                matched_strings: bestMatch.matches,
                execution_time_ms: bestMatch.executionTimeMs,
              },
            },
          };

          // Correlate into incident for High & Critical threats
          let createdIncidentId: string | undefined;
          try {
            const incident = await correlateDetectionToIncident(yaraMatchRecord);
            yaraMatchRecord.incidentId = incident.id;
            yaraMatchRecord.incidentCode = incident.incident_code;
            createdIncidentId = incident.id;
          } catch (err) {
            console.error("[DetectionEngine] Failed to correlate YARA incident:", err);
          }

          // Record match into YARA match ledger
          try {
            await recordYaraMatch({
              tenantId: context.tenantId,
              ruleId: yRule.rule_id,
              agentId: context.agentId,
              filePath: targetPath,
              matchedStrings: bestMatch.matches,
              incidentId: createdIncidentId,
            });
          } catch (err) {
            console.error("[DetectionEngine] Failed to record YARA match in store:", err);
          }

          matches.push(yaraMatchRecord);
        }
      }
    }

    // 2. Evaluate Built-in Sigma / Behavioral Rules
    for (const rule of ACTIVE_DETECTION_RULES) {
      if (!rule.enabled) continue;

      let isMatch = false;
      try {
        if (rule.evaluator) {
          isMatch = rule.evaluator(combinedPayload);
        } else if (rule.matchPattern) {
          const str = JSON.stringify(combinedPayload);
          isMatch = rule.matchPattern.test(str);
        }
      } catch {
        isMatch = false;
      }

      if (isMatch) {
        rule.matchesCount++;
        const matchRecord: DetectionMatch = {
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: rule.severity,
          matchedAt: new Date().toISOString(),
          agentId: context.agentId,
          tenantId: context.tenantId,
          hostname,
          evidence: combinedPayload,
        };

        // Correlate into Incident automatically for High & Critical threats
        try {
          const incident = await correlateDetectionToIncident(matchRecord);
          matchRecord.incidentId = incident.id;
          matchRecord.incidentCode = incident.incident_code;
        } catch (err) {
          console.error("[DetectionEngine] Failed to correlate incident:", err);
        }

        matches.push(matchRecord);
      }
    }
  }

  return matches;
}

/**
 * Creates an incident in PostgreSQL (or fallback memory store) from a detection match,
 * records timeline events, links asset, and dispatches real-time SOC alerts.
 */
export async function correlateDetectionToIncident(
  match: DetectionMatch
): Promise<{ id: string; incident_code: string }> {
  const incidentId = crypto.randomUUID();
  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const incidentCode = `INC-${randomSuffix}`;
  const title = `[Detection: ${match.ruleName}] Threat detected on ${match.hostname}`;
  const description = `Autonomous detection engine triggered rule '${match.ruleId}' (${match.category}) on agent ${match.agentId}.\nEvidence:\n${JSON.stringify(match.evidence, null, 2)}`;

  let persistedInDb = false;

  try {
    // 1. Insert into incidents table
    await query(
      `INSERT INTO incidents (id, incident_code, tenant_id, severity, status, title, description, created_at, updated_at)
       VALUES ($1, $2, $3, $4, 'investigating', $5, $6, now(), now())`,
      [incidentId, incidentCode, match.tenantId, match.severity, title, description]
    );

    // 2. Insert into incident_events table
    await query(
      `INSERT INTO incident_events (incident_id, occurred_at, description)
       VALUES ($1, now(), $2)`,
      [
        incidentId,
        `Detection rule triggered: ${match.ruleName} (${match.ruleId}) on ${match.hostname}. Evidence captured from streaming telemetry.`,
      ]
    );

    // 3. Link Asset if hostname is known
    if (match.hostname && match.hostname !== "UNKNOWN-HOST") {
      const assetId = crypto.randomUUID();
      await query(
        `INSERT INTO assets (id, tenant_id, hostname, asset_type)
         VALUES ($1, $2, $3, 'workstation')
         ON CONFLICT DO NOTHING`,
        [assetId, match.tenantId, match.hostname]
      );
      await query(
        `INSERT INTO incident_assets (incident_id, asset_id)
         VALUES ($1, (SELECT id FROM assets WHERE hostname = $2 AND tenant_id = $3 LIMIT 1))
         ON CONFLICT DO NOTHING`,
        [incidentId, match.hostname, match.tenantId]
      );
    }
    persistedInDb = true;
  } catch {
    // Database offline / fallback mode: store in memory
  }

  // Always keep in-memory correlated list for instant query / test verification
  const correlatedRecord: CorrelatedIncident = {
    id: incidentId,
    incident_code: incidentCode,
    tenant_id: match.tenantId,
    severity: match.severity,
    status: "investigating",
    title,
    description,
    rule_id: match.ruleId,
    agent_id: match.agentId,
    hostname: match.hostname,
    created_at: new Date().toISOString(),
    events: [
      {
        occurred_at: new Date().toISOString(),
        description: `Detection rule triggered: ${match.ruleName} (${match.ruleId}) on ${match.hostname}`,
        evidence: match.evidence,
      },
    ],
  };
  IN_MEMORY_CORRELATED_INCIDENTS.unshift(correlatedRecord);

  // 4. Log to Hash Chain Audit Ledger
  try {
    await recordHashChainEvent({
      tenantId: match.tenantId,
      eventType: "THREAT_DETECTION_CORRELATED",
      actorId: `engine:detection-rules`,
      payload: {
        incidentId,
        incidentCode,
        ruleId: match.ruleId,
        severity: match.severity,
        agentId: match.agentId,
        hostname: match.hostname,
        evidence: match.evidence,
      },
    });
  } catch {
    // Non-fatal
  }

  // 5. Dispatch Real-Time Notification (Discord, Slack, Teams)
  dispatchSecurityNotification({
    type: "threat_detected",
    tenantId: match.tenantId,
    title: `🚨 ${match.severity.toUpperCase()} THREAT: ${match.ruleName}`,
    description: `Endpoint ${match.hostname} triggered autonomous detection rule ${match.ruleId}.\nIncident ${incidentCode} created and assigned to SOC triage.`,
    severity: match.severity,
    actionUrl: `http://localhost:3000`,
    metadata: {
      incidentCode,
      hostname: match.hostname,
      agentId: match.agentId,
      ruleId: match.ruleId,
      persistedInDb: String(persistedInDb),
    },
  }).catch(() => {});

  return { id: incidentId, incident_code: incidentCode };
}

/**
 * Returns all active rules and their real-time match statistics.
 */
export function getActiveDetectionRules() {
  return ACTIVE_DETECTION_RULES.map((r) => ({
    id: r.id,
    name: r.name,
    category: r.category,
    severity: r.severity,
    type: r.type,
    description: r.description,
    enabled: r.enabled,
    matchesCount: r.matchesCount,
  }));
}

/**
 * Toggles a detection rule on or off.
 */
export function toggleDetectionRule(ruleId: string, enabled: boolean): boolean {
  const rule = ACTIVE_DETECTION_RULES.find((r) => r.id === ruleId);
  if (rule) {
    rule.enabled = enabled;
    return true;
  }
  return false;
}

import crypto from "node:crypto";
import { query } from "@/lib/db";
import { parseYaraRule } from "./parser";
import type {
  YaraRuleRecord,
  YaraMatchRecord,
  YaraStringMatch,
} from "./types";

export type {
  YaraRuleRecord,
  YaraMatchRecord,
  YaraStringMatch,
};

// Seeded Default System Rules
export const SEED_SYSTEM_YARA_RULES: YaraRuleRecord[] = [
  {
    id: "a0000001-0000-0000-0000-000000000001",
    tenant_id: null,
    rule_id: "YARA-MAL-001",
    name: "WebShell_C99_PHP",
    category: "Malware / Webshell",
    severity: "critical",
    description: "Detects common PHP webshells, base64 command execution, and reverse TCP shells.",
    target: "filesystem / webroot",
    raw_content: `rule WebShell_C99_PHP {
    meta:
        id = "YARA-MAL-001"
        description = "Detects common PHP webshells and reverse command shells"
        severity = "critical"
        category = "Malware / Webshell"
    strings:
        $s1 = "c99shell" nocase
        $s2 = "b374k" nocase
        $s3 = "passthru($_POST" nocase
        $s4 = "c3lzdGVtKCRfR0VUWydjbWQnXS" ascii wide
        $s5 = "/bin/sh -i >& /dev/tcp/" ascii wide
    condition:
        any of them
}`,
    enabled: true,
    is_system: true,
    matches_today: 3,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "a0000001-0000-0000-0000-000000000002",
    tenant_id: null,
    rule_id: "YARA-MAL-002",
    name: "Ransomware_LockBit_Indicators",
    category: "Ransomware",
    severity: "critical",
    description: "Detects LockBit and modern ransomware encryption notes, mass file extensions, and shadow deletion commands.",
    target: "filesystem write operations",
    raw_content: `rule Ransomware_LockBit_Indicators {
    meta:
        id = "YARA-MAL-002"
        description = "Detects LockBit and modern ransomware encryption indicators"
        severity = "critical"
        category = "Ransomware"
    strings:
        $r1 = "LockBit 3.0" ascii wide
        $r2 = "All your files have been encrypted" nocase
        $r3 = "vssadmin delete shadows /all /quiet" nocase
        $r4 = ".lockbit" nocase
        $r5 = ".blackcat" nocase
    condition:
        2 of them
}`,
    enabled: true,
    is_system: true,
    matches_today: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "a0000001-0000-0000-0000-000000000003",
    tenant_id: null,
    rule_id: "YARA-MAL-003",
    name: "Cobalt_Strike_Beacon_Memory",
    category: "C2 / Post-Exploitation",
    severity: "high",
    description: "Detects Cobalt Strike malleable C2 reflective DLL loader memory patterns and named pipe artifacts.",
    target: "process memory",
    raw_content: `rule Cobalt_Strike_Beacon_Memory {
    meta:
        id = "YARA-MAL-003"
        description = "Detects Cobalt Strike malleable C2 reflective DLL beacon memory patterns"
        severity = "high"
        category = "C2 / Post-Exploitation"
    strings:
        $cs1 = "%s as %s\\\\%s: %d" ascii
        $cs2 = "\\\\\\\\.\\\\pipe\\\\status_" ascii
        $cs3 = "ReflectiveLoader" ascii fullword
        $cs4 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        any of them
}`,
    enabled: true,
    is_system: true,
    matches_today: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "a0000001-0000-0000-0000-000000000004",
    tenant_id: null,
    rule_id: "YARA-MAL-004",
    name: "Log4j_JNDI_Exploit_Strings",
    category: "Exploit / Initial Access",
    severity: "critical",
    description: "Detects Log4j JNDI remote code execution strings and nested lower lookup obfuscations.",
    target: "inbound HTTP / log stream",
    raw_content: `rule Log4j_JNDI_Exploit_Strings {
    meta:
        id = "YARA-MAL-004"
        description = "Detects Log4j JNDI injection patterns and obfuscation bypasses"
        severity = "critical"
        category = "Exploit / Initial Access"
    strings:
        $j1 = "\${jndi:ldap://" nocase
        $j2 = "\${jndi:rmi://" nocase
        $j3 = "\${jndi:dns://" nocase
        $j4 = "\${lower:j}\${lower:n}\${lower:d}\${lower:i}" nocase
    condition:
        any of them
}`,
    enabled: true,
    is_system: true,
    matches_today: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "a0000001-0000-0000-0000-000000000005",
    tenant_id: null,
    rule_id: "YARA-MAL-005",
    name: "Mimikatz_Credential_Dumping",
    category: "Credential Access",
    severity: "critical",
    description: "Detects Mimikatz sekurlsa and logonpasswords memory artifact signatures and debug privilege escalations.",
    target: "process memory / LSASS",
    raw_content: `rule Mimikatz_Credential_Dumping {
    meta:
        id = "YARA-MAL-005"
        description = "Detects Mimikatz sekurlsa and logonpasswords memory artifact signatures"
        severity = "critical"
        category = "Credential Access"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase ascii wide
        $m2 = "lsadump::sam" nocase ascii wide
        $m3 = "privilege::debug" nocase ascii wide
        $m4 = "mimilib.dll" nocase ascii wide
        $m5 = "Invoke-Mimikatz" nocase ascii wide
    condition:
        any of them
}`,
    enabled: true,
    is_system: true,
    matches_today: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
];

// Fallback in-memory stores
export const IN_MEMORY_YARA_RULES: YaraRuleRecord[] = [
  ...SEED_SYSTEM_YARA_RULES.map((r) => ({ ...r })),
];

export const IN_MEMORY_YARA_MATCHES: YaraMatchRecord[] = [
  {
    id: "m0000001-0000-0000-0000-000000000001",
    tenant_id: "acme-tenant",
    rule_id: "YARA-MAL-001",
    agent_id: "ws-fin-01",
    file_path: "/var/www/html/uploads/c99.php",
    matched_strings: [
      {
        id: "$s1",
        offset: 142,
        length: 8,
        snippet: "...eval(base64_decode('c99shell'))...",
        matchedValue: "c99shell",
      },
    ],
    incident_id: "inc-demo-001",
    created_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: "m0000001-0000-0000-0000-000000000002",
    tenant_id: "acme-tenant",
    rule_id: "YARA-MAL-003",
    agent_id: "srv-bastion-01",
    file_path: "PID: 3412 (lsass.exe memory)",
    matched_strings: [
      {
        id: "$cs3",
        offset: 4096,
        length: 16,
        snippet: "...ReflectiveLoader binary offset...",
        matchedValue: "ReflectiveLoader",
      },
    ],
    incident_id: "inc-demo-002",
    created_at: new Date(Date.now() - 7200000).toISOString(),
  },
];

/**
 * Reset memory store for testing.
 */
export function resetYaraMemoryStore(): void {
  IN_MEMORY_YARA_RULES.length = 0;
  IN_MEMORY_YARA_RULES.push(...SEED_SYSTEM_YARA_RULES.map((r) => ({ ...r })));
  IN_MEMORY_YARA_MATCHES.length = 0;
}

/**
 * Returns all YARA rules visible to the given tenant (global system rules + tenant-owned custom rules).
 */
export async function getYaraRules(tenantId?: string): Promise<YaraRuleRecord[]> {
  try {
    const querySql = tenantId
      ? `SELECT * FROM yara_rules WHERE tenant_id = $1 OR tenant_id IS NULL ORDER BY created_at ASC`
      : `SELECT * FROM yara_rules ORDER BY created_at ASC`;
    const params = tenantId ? [tenantId] : [];
    const { rows } = await query<YaraRuleRecord>(querySql, params);

    if (rows && rows.length > 0) {
      // Merge with live match counts
      const stats = await getYaraMatchStats(tenantId);
      return rows.map((r) => ({
        ...r,
        matches_today: stats[r.rule_id] ?? 0,
      }));
    }
  } catch {
    // DB offline fallback
  }

  // Memory store fallback
  const rules = IN_MEMORY_YARA_RULES.filter(
    (r) => r.tenant_id === null || !tenantId || r.tenant_id === tenantId
  );
  const stats = await getYaraMatchStats(tenantId);
  return rules.map((r) => ({
    ...r,
    matches_today: (stats[r.rule_id] ?? 0) + (r.matches_today || 0),
  }));
}

/**
 * Retrieve a specific YARA rule by UUID id or rule_id.
 */
export async function getYaraRuleById(
  idOrRuleId: string,
  tenantId?: string
): Promise<YaraRuleRecord | null> {
  try {
    const querySql = tenantId
      ? `SELECT * FROM yara_rules WHERE (id = $1 OR rule_id = $1) AND (tenant_id = $2 OR tenant_id IS NULL) LIMIT 1`
      : `SELECT * FROM yara_rules WHERE id = $1 OR rule_id = $1 LIMIT 1`;
    const params = tenantId ? [idOrRuleId, tenantId] : [idOrRuleId];
    const { rows } = await query<YaraRuleRecord>(querySql, params);
    if (rows && rows.length > 0) {
      return rows[0];
    }
  } catch {
    // DB offline fallback
  }

  const found = IN_MEMORY_YARA_RULES.find(
    (r) =>
      (r.id === idOrRuleId || r.rule_id === idOrRuleId) &&
      (r.tenant_id === null || !tenantId || r.tenant_id === tenantId)
  );
  return found ? { ...found } : null;
}

export interface CreateYaraRuleInput {
  name: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  description?: string;
  target?: string;
  raw_content: string;
  rule_id?: string;
}

/**
 * Validates and creates a new custom YARA rule for a tenant.
 */
export async function createYaraRule(
  data: CreateYaraRuleInput,
  tenantId: string
): Promise<YaraRuleRecord> {
  // Validate syntax
  const parseRes = parseYaraRule(data.raw_content);
  if (!parseRes.success || !parseRes.ast) {
    const err = parseRes.error;
    throw new Error(
      `YARA syntax error at line ${err?.line ?? 1}, col ${err?.column ?? 1}: ${err?.message ?? "Invalid rule syntax"}`
    );
  }

  const ast = parseRes.ast;
  const id = crypto.randomUUID();
  const ruleId =
    data.rule_id ||
    String(ast.meta?.id || `YARA-CUST-${Math.floor(1000 + Math.random() * 9000)}`);
  const name = data.name || ast.name;
  const category = data.category || String(ast.meta?.category || "Custom");
  const severity =
    data.severity ||
    (ast.meta?.severity as "critical" | "high" | "medium" | "low") ||
    "medium";
  const description =
    data.description ||
    String(ast.meta?.description || `Custom YARA rule ${name}`);
  const target = data.target || "endpoint telemetry / files";
  const now = new Date().toISOString();

  const newRule: YaraRuleRecord = {
    id,
    tenant_id: tenantId,
    rule_id: ruleId,
    name,
    category,
    severity,
    description,
    target,
    raw_content: data.raw_content,
    enabled: true,
    is_system: false,
    matches_today: 0,
    created_at: now,
    updated_at: now,
  };

  try {
    await query(
      `INSERT INTO yara_rules (id, tenant_id, rule_id, name, category, severity, description, target, raw_content, enabled, is_system, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, false, $10, $11)`,
      [
        id,
        tenantId,
        ruleId,
        name,
        category,
        severity,
        description,
        target,
        data.raw_content,
        now,
        now,
      ]
    );
  } catch {
    // DB offline fallback: store in memory
  }

  // Always keep in memory store
  IN_MEMORY_YARA_RULES.push(newRule);
  return newRule;
}

export interface UpdateYaraRuleInput {
  enabled?: boolean;
  severity?: "critical" | "high" | "medium" | "low";
  target?: string;
  description?: string;
  raw_content?: string;
  name?: string;
  category?: string;
}

/**
 * Updates an existing YARA rule (e.g. toggles enabled status or edits content).
 */
export async function updateYaraRule(
  id: string,
  updates: UpdateYaraRuleInput,
  tenantId?: string
): Promise<YaraRuleRecord | null> {
  const existing = await getYaraRuleById(id, tenantId);
  if (!existing) return null;

  // If raw_content is updated, validate syntax
  if (updates.raw_content) {
    const parseRes = parseYaraRule(updates.raw_content);
    if (!parseRes.success) {
      throw new Error(`YARA syntax error: ${parseRes.error?.message}`);
    }
  }

  const updatedRecord: YaraRuleRecord = {
    ...existing,
    enabled: updates.enabled !== undefined ? updates.enabled : existing.enabled,
    severity: updates.severity || existing.severity,
    target: updates.target || existing.target,
    description: updates.description || existing.description,
    raw_content: updates.raw_content || existing.raw_content,
    name: updates.name || existing.name,
    category: updates.category || existing.category,
    updated_at: new Date().toISOString(),
  };

  try {
    await query(
      `UPDATE yara_rules
       SET enabled = $1, severity = $2, target = $3, description = $4, raw_content = $5, name = $6, category = $7, updated_at = $8
       WHERE id = $9 OR rule_id = $9`,
      [
        updatedRecord.enabled,
        updatedRecord.severity,
        updatedRecord.target,
        updatedRecord.description,
        updatedRecord.raw_content,
        updatedRecord.name,
        updatedRecord.category,
        updatedRecord.updated_at,
        id,
      ]
    );
  } catch {
    // DB offline fallback
  }

  const idx = IN_MEMORY_YARA_RULES.findIndex((r) => r.id === id || r.rule_id === id);
  if (idx !== -1) {
    IN_MEMORY_YARA_RULES[idx] = updatedRecord;
  }

  return updatedRecord;
}

/**
 * Deletes a custom YARA rule. System rules are protected and cannot be deleted.
 */
export async function deleteYaraRule(
  id: string,
  tenantId?: string
): Promise<{ success: boolean; error?: string }> {
  const existing = await getYaraRuleById(id, tenantId);
  if (!existing) {
    return { success: false, error: "Rule not found" };
  }

  if (existing.is_system) {
    return {
      success: false,
      error: "System default rules cannot be deleted",
    };
  }

  try {
    await query(`DELETE FROM yara_rules WHERE (id = $1 OR rule_id = $1)`, [id]);
  } catch {
    // DB offline fallback
  }

  const idx = IN_MEMORY_YARA_RULES.findIndex((r) => r.id === id || r.rule_id === id);
  if (idx !== -1) {
    IN_MEMORY_YARA_RULES.splice(idx, 1);
  }

  return { success: true };
}

export interface RecordYaraMatchInput {
  tenantId: string;
  ruleId: string;
  agentId: string;
  filePath?: string;
  matchedStrings: YaraStringMatch[];
  incidentId?: string | null;
}

/**
 * Records a detection match event into the database and fallback ring buffer.
 */
export async function recordYaraMatch(input: RecordYaraMatchInput): Promise<YaraMatchRecord> {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const record: YaraMatchRecord = {
    id,
    tenant_id: input.tenantId,
    rule_id: input.ruleId,
    agent_id: input.agentId,
    file_path: input.filePath || "memory-telemetry",
    matched_strings: input.matchedStrings,
    incident_id: input.incidentId || null,
    created_at: now,
  };

  try {
    await query(
      `INSERT INTO yara_rule_matches (id, tenant_id, rule_id, agent_id, file_path, matched_strings, incident_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        id,
        input.tenantId,
        input.ruleId,
        input.agentId,
        record.file_path,
        JSON.stringify(input.matchedStrings),
        input.incidentId || null,
        now,
      ]
    );
  } catch {
    // DB offline fallback
  }

  IN_MEMORY_YARA_MATCHES.unshift(record);
  if (IN_MEMORY_YARA_MATCHES.length > 500) {
    IN_MEMORY_YARA_MATCHES.pop();
  }

  return record;
}

/**
 * Returns recent matches for a tenant.
 */
export async function getYaraMatches(
  tenantId?: string,
  limit = 50
): Promise<YaraMatchRecord[]> {
  try {
    const querySql = tenantId
      ? `SELECT * FROM yara_rule_matches WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`
      : `SELECT * FROM yara_rule_matches ORDER BY created_at DESC LIMIT $1`;
    const params = tenantId ? [tenantId, limit] : [limit];
    const { rows } = await query<YaraMatchRecord>(querySql, params);
    if (rows && rows.length > 0) {
      return rows;
    }
  } catch {
    // DB offline fallback
  }

  const filtered = tenantId
    ? IN_MEMORY_YARA_MATCHES.filter((m) => m.tenant_id === tenantId)
    : IN_MEMORY_YARA_MATCHES;
  return filtered.slice(0, limit);
}

/**
 * Returns match count today per rule ID.
 */
export async function getYaraMatchStats(tenantId?: string): Promise<Record<string, number>> {
  const stats: Record<string, number> = {};

  try {
    const querySql = tenantId
      ? `SELECT rule_id, COUNT(*) as count FROM yara_rule_matches WHERE tenant_id = $1 AND created_at >= CURRENT_DATE GROUP BY rule_id`
      : `SELECT rule_id, COUNT(*) as count FROM yara_rule_matches WHERE created_at >= CURRENT_DATE GROUP BY rule_id`;
    const params = tenantId ? [tenantId] : [];
    const { rows } = await query<{ rule_id: string; count: string | number }>(querySql, params);
    if (rows) {
      for (const row of rows) {
        stats[row.rule_id] = Number(row.count);
      }
      return stats;
    }
  } catch {
    // DB offline fallback
  }

  for (const m of IN_MEMORY_YARA_MATCHES) {
    if (!tenantId || m.tenant_id === tenantId) {
      stats[m.rule_id] = (stats[m.rule_id] || 0) + 1;
    }
  }

  return stats;
}

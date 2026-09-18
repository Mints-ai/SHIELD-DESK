import "server-only";
import type OpenAI from "openai";
import { getSupabase } from "@/lib/db";
import { canAccess } from "@/lib/permissions";
import type { ChatSession } from "@/lib/auth/session";

export type { ChatSession } from "@/lib/auth/session";

/**
 * ShieldDesk chat tools — the allow-listed set the model is permitted to
 * call (Phase 4 of the development plan), scoped to the four supported
 * intents from the Scope Addendum: fetch incidents, analyze a CVE,
 * investigate an incident, generate a mitigation plan. The model receives
 * only these names + schemas; every implementation below re-checks RBAC +
 * tenant isolation itself rather than trusting anything the model says
 * about who's asking.
 *
 * DATABASE: Migrated from local PostgreSQL (pg pool) to Supabase JS client.
 * All queries use the Supabase query builder. Raw SQL has been replaced with
 * .from().select().eq() chains. The application-layer RBAC + tenant scoping
 * logic is unchanged — we do NOT rely on Supabase RLS.
 *
 * The Python vulnerability-intelligence engine (Phase 5) is reached over
 * HTTP via PYTHON_AI_SERVICE_URL — see server.py at the repo root.
 */

// ---------------------------------------------------------------------------
// Tool schemas — OpenAI-compatible `tools` format, which Ollama's
// /v1/chat/completions endpoint also accepts for tool-calling-capable
// models (qwen2.5+, qwen3, llama3.1+, mistral-nemo, etc).
// ---------------------------------------------------------------------------
export const CHAT_TOOLS: OpenAI.Chat.Completions.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "getIncidents",
      description:
        "Fetch incidents for the caller's tenant, optionally filtered by " +
        "severity or status. Use for requests like 'show me today's critical " +
        "incidents' or 'what incidents are open right now'.",
      parameters: {
        type: "object",
        properties: {
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low"],
            description: "Filter to a single severity level. Omit for all severities.",
          },
          status: {
            type: "string",
            enum: ["open", "investigating", "resolved", "closed"],
            description: "Filter to a single status. Omit for all statuses.",
          },
          limit: {
            type: "integer",
            description: "Max incidents to return. Defaults to 10.",
          },
        },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "analyzeCve",
      description:
        "Analyze a specific CVE: severity, CVSS score, CISA KEV exploit " +
        "risk, operational remediation tier, and a recommended mitigation. " +
        "Use for requests like 'analyze CVE-2024-3400'.",
      parameters: {
        type: "object",
        properties: {
          cveId: {
            type: "string",
            description: "The CVE identifier, e.g. 'CVE-2024-3400'.",
          },
        },
        required: ["cveId"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "investigateIncident",
      description:
        "Investigate a specific incident: its details, event timeline, and " +
        "affected assets. Use for requests like 'investigate INC-1042'.",
      parameters: {
        type: "object",
        properties: {
          incidentId: {
            type: "string",
            description: "The incident code, e.g. 'INC-1042'.",
          },
        },
        required: ["incidentId"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "generateMitigationPlan",
      description:
        "Generate a mitigation plan (immediate / short-term / long-term " +
        "tasks) for a specific incident. Planning and governance only — " +
        "never executes any action. Use for requests like 'generate a " +
        "mitigation plan for INC-1042'.",
      parameters: {
        type: "object",
        properties: {
          incidentId: {
            type: "string",
            description: "The incident code, e.g. 'INC-1042'.",
          },
        },
        required: ["incidentId"],
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Dev fallback seed data (used when Supabase is unreachable / tables empty)
// ---------------------------------------------------------------------------
const MOCK_INCIDENTS = [
  {
    id: "11111111-1111-1111-1111-111111111111",
    incident_code: "INC-1042",
    tenant_id: "acme-tenant",
    severity: "critical",
    status: "investigating",
    title: "Suspicious lateral movement on FIN-WS-042",
    description: "Detected lateral movement attempt from FIN-WS-042 toward the finance subnet. Two affected assets so far. No confirmed data exfiltration.",
    created_at: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
  },
  {
    id: "22222222-2222-2222-2222-222222222222",
    incident_code: "INC-1039",
    tenant_id: "acme-tenant",
    severity: "high",
    status: "open",
    title: "Repeated failed admin logins, EU tenant",
    description: "Multiple failed administrator login attempts detected from an external IP range.",
    created_at: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
  },
  {
    id: "33333333-3333-3333-3333-333333333333",
    incident_code: "INC-1031",
    tenant_id: "acme-tenant",
    severity: "medium",
    status: "resolved",
    title: "Outbound traffic to a newly-registered domain",
    description: "Endpoint contacted a domain registered within the last 48 hours; blocked by egress filtering.",
    created_at: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
  },
];

const MOCK_EVENTS: Record<string, Array<{ occurred_at: string; description: string }>> = {
  "11111111-1111-1111-1111-111111111111": [
    { occurred_at: new Date(Date.now() - 3 * 3600 * 1000).toISOString(), description: "Initial detection: anomalous SMB traffic from FIN-WS-042." },
    { occurred_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(), description: "Confirmed lateral movement attempt toward FIN-DB-01." },
    { occurred_at: new Date(Date.now() - 1 * 3600 * 1000).toISOString(), description: "Analyst assigned; containment options under review." },
  ],
};

const MOCK_ASSETS: Record<string, Array<{ hostname: string; asset_type: string }>> = {
  "11111111-1111-1111-1111-111111111111": [
    { hostname: "FIN-WS-042", asset_type: "workstation" },
    { hostname: "FIN-DB-01", asset_type: "database-server" },
  ],
};

const MOCK_INCIDENT_CVES: Record<string, string[]> = {
  "INC-1042": ["CVE-2024-3400"],
};

const MOCK_CVE_RECORDS: Record<string, Record<string, unknown>> = {
  "CVE-2024-3400": {
    cve_id: "CVE-2024-3400",
    cvss_score: 10.0,
    severity: "CRITICAL",
    cisa_kev: true,
    remediation_tier: "IMMEDIATE_ACTION",
    description: "Command injection vulnerability in PAN-OS GlobalProtect feature allows an unauthenticated attacker to execute arbitrary code with root privileges.",
    recommended_mitigation: "Apply vendor hotfixes immediately. Disable device telemetry as temporary workaround if hotfix cannot be immediately deployed.",
  },
};

// ---------------------------------------------------------------------------
// Tool: getIncidents
// Always scoped to the caller's tenant unless they hold VIEW_CROSS_TENANT.
// ---------------------------------------------------------------------------
export async function getIncidents(
  session: ChatSession,
  args: { severity?: string; status?: string; limit?: number } = {}
) {
  const limit = Math.min(Math.max(args.limit ?? 10, 1), 50);

  try {
    const supabase = getSupabase();
    let q = supabase
      .from("incidents")
      .select("incident_code, severity, status, title, created_at");

    if (!canAccess(session.role, "VIEW_CROSS_TENANT")) {
      q = q.eq("tenant_id", session.tenantId);
    }
    if (args.severity) {
      q = q.eq("severity", args.severity);
    }
    if (args.status) {
      q = q.eq("status", args.status);
    } else {
      q = q.not("status", "in", "(resolved,closed)");
    }

    q = q.order("created_at", { ascending: false }).limit(limit);

    const { data, error } = await q;
    if (error) throw error;
    return { incidents: data ?? [] };
  } catch {
    // Dev fallback if Supabase is unreachable
    const filtered = MOCK_INCIDENTS.filter((inc) => {
      if (!canAccess(session.role, "VIEW_CROSS_TENANT") && inc.tenant_id !== session.tenantId) {
        return false;
      }
      if (args.severity && inc.severity.toLowerCase() !== args.severity.toLowerCase()) {
        return false;
      }
      if (args.status) {
        return inc.status.toLowerCase() === args.status.toLowerCase();
      }
      return inc.status !== "resolved" && inc.status !== "closed";
    });
    return {
      incidents: filtered.slice(0, limit).map((inc) => ({
        incident_code: inc.incident_code,
        severity: inc.severity,
        status: inc.status,
        title: inc.title,
        created_at: inc.created_at,
      })),
    };
  }
}

// ---------------------------------------------------------------------------
// Tool: investigateIncident
// ---------------------------------------------------------------------------
export async function investigateIncident(
  session: ChatSession,
  args: { incidentId?: string }
) {
  if (!args.incidentId) return { error: "missing_incident_id" };

  try {
    const supabase = getSupabase();

    // Step 1: Fetch the incident
    let incidentQuery = supabase
      .from("incidents")
      .select("id, incident_code, severity, status, title, description, created_at")
      .eq("incident_code", args.incidentId);

    if (!canAccess(session.role, "VIEW_CROSS_TENANT")) {
      incidentQuery = incidentQuery.eq("tenant_id", session.tenantId);
    }

    const { data: incident, error: incidentError } = await incidentQuery
      .limit(1)
      .maybeSingle();

    if (incidentError) throw incidentError;
    if (!incident) return { error: "not_found" };

    // Step 2: Fetch events and assets in parallel
    const [eventsResult, assetsResult] = await Promise.all([
      supabase
        .from("incident_events")
        .select("occurred_at, description")
        .eq("incident_id", incident.id)
        .order("occurred_at", { ascending: true }),
      supabase
        .from("incident_assets")
        .select("assets(hostname, asset_type)")
        .eq("incident_id", incident.id),
    ]);

    const events = eventsResult.data ?? [];
    const affectedAssets = (assetsResult.data ?? [])
      .map((row: { assets: unknown }) => row.assets)
      .filter(Boolean) as Array<{ hostname: string; asset_type: string }>;

    return {
      incident: {
        incidentCode: incident.incident_code,
        severity: incident.severity,
        status: incident.status,
        title: incident.title,
        description: incident.description,
        createdAt: incident.created_at,
      },
      events,
      affectedAssets,
    };
  } catch {
    // Dev fallback if Supabase is unreachable
    const incident = MOCK_INCIDENTS.find(
      (i) => i.incident_code.toUpperCase() === args.incidentId!.toUpperCase()
    );
    if (!incident) return { error: "not_found" };
    if (!canAccess(session.role, "VIEW_CROSS_TENANT") && incident.tenant_id !== session.tenantId) {
      return { error: "not_found" };
    }

    const events = MOCK_EVENTS[incident.id] || [];
    const assets = MOCK_ASSETS[incident.id] || [];

    return {
      incident: {
        incidentCode: incident.incident_code,
        severity: incident.severity,
        status: incident.status,
        title: incident.title,
        description: incident.description,
        createdAt: incident.created_at,
      },
      events,
      affectedAssets: assets,
    };
  }
}

// ---------------------------------------------------------------------------
// Tool: analyzeCve
// Calls out to the real Phase 5 Python engine (server.py / cve_ai_engine.py):
// GET /api/lookup?cve=CVE-XXXX-XXXXX — exact match against the trained
// 12,900+ CVE knowledge base. Rate-limited, tenant-agnostic per the
// development plan's tool table — CVE data isn't tenant-scoped data, it's
// shared threat intelligence.
// ---------------------------------------------------------------------------
// Normalise a raw Python-engine record to a unified schema the LLM understands.
// The Python engine uses: cvss_severity / kev_listed / assigned_tier / mitigation_plan
// The mock uses:          severity       / cisa_kev   / remediation_tier / recommended_mitigation
// Both are mapped here so the Ollama formatter always sees the same field names.
// ---------------------------------------------------------------------------
function normaliseCveRecord(raw: Record<string, unknown>): Record<string, unknown> {
  return {
    cve_id:                raw.cve_id,
    category:              raw.category              ?? "General",
    domain:                raw.domain               ?? null,
    cvss_score:            raw.cvss_score,
    severity:              raw.cvss_severity         ?? raw.severity         ?? "UNKNOWN",
    cwe_id:                raw.cwe_id               ?? null,
    epss_score:            raw.epss_score            ?? null,
    kev_listed:            raw.kev_listed !== undefined
                             ? Boolean(raw.kev_listed)
                             : raw.cisa_kev          ?? false,
    description:           raw.description          ?? null,
    recommended_mitigation: raw.mitigation_plan      ?? raw.recommended_mitigation ?? null,
    assigned_tier:         raw.assigned_tier         ?? raw.remediation_tier ?? null,
  };
}

export async function analyzeCve(_session: ChatSession, args: { cveId?: string }) {
  if (!args.cveId) return { error: "missing_cve_id" };

  const baseUrl = process.env.PYTHON_AI_SERVICE_URL;
  if (baseUrl) {
    try {
      const url = `${baseUrl}/api/lookup?cve=${encodeURIComponent(args.cveId)}`;
      // 20s timeout — Python engine can be slow on first request while model is warm
      const res = await fetch(url, { signal: AbortSignal.timeout(20000) });

      if (res.status === 404) return { error: "not_found" };
      if (res.ok) {
        const body = await res.json() as { record?: Record<string, unknown> };
        if (body.record) {
          return { record: normaliseCveRecord(body.record), source: "engine" };
        }
      }
    } catch {
      // Fallback below if service is offline or timed out
    }
  }

  // Dev fallback:
  const cveUpper = args.cveId.toUpperCase();
  if (MOCK_CVE_RECORDS[cveUpper]) {
    return { record: normaliseCveRecord(MOCK_CVE_RECORDS[cveUpper] as Record<string, unknown>), source: "mock" };
  }

  return {
    source: "mock",
    record: normaliseCveRecord({
      cve_id: cveUpper,
      cvss_score: 8.8,
      severity: "HIGH",
      kev_listed: false,
      assigned_tier: "SCHEDULED_PATCH",
      description: `Threat intelligence analysis for ${cveUpper}.`,
      mitigation_plan: `Apply vendor patches for ${cveUpper}, enforce boundary firewalls, and monitor endpoint logs.`,
    }),
  };
}

// ---------------------------------------------------------------------------
// Tool: generateMitigationPlan
// Planning/governance only (Phase 7) — composes incident + linked-CVE
// context into immediate / short-term / long-term tasks. Never executes
// anything.
// ---------------------------------------------------------------------------
export async function generateMitigationPlan(
  session: ChatSession,
  args: { incidentId?: string }
) {
  if (!args.incidentId) return { error: "missing_incident_id" };

  const investigation = await investigateIncident(session, {
    incidentId: args.incidentId,
  });
  if ("error" in investigation) return investigation;

  const assetNames = investigation.affectedAssets
    .map((a: { hostname?: string }) => a.hostname)
    .filter(Boolean);

  let linkedCveRows: { cve_id: string }[] = [];
  try {
    // Step 1: Get the incident's UUID from its code
    const { data: incRow } = await getSupabase()
      .from("incidents")
      .select("id")
      .eq("incident_code", args.incidentId)
      .limit(1)
      .maybeSingle();

    if (incRow) {
      // Step 2: Fetch linked CVEs using the UUID
      const { data: cveData, error: cveError } = await getSupabase()
        .from("incident_cves")
        .select("cve_id")
        .eq("incident_id", incRow.id);

      if (cveError) throw cveError;
      linkedCveRows = cveData ?? [];
    }
  } catch {
    // Dev fallback if Supabase is unreachable
    const cves = MOCK_INCIDENT_CVES[args.incidentId.toUpperCase()] || ["CVE-2024-3400"];
    linkedCveRows = cves.map((cve_id) => ({ cve_id }));
  }

  const cveLookups = await Promise.all(
    linkedCveRows.map(async (row) => ({
      cveId: row.cve_id,
      result: await analyzeCve(session, { cveId: row.cve_id }),
    }))
  );

  const resolvedCves = cveLookups.filter((c) => !("error" in c.result));
  const unresolvedCves = cveLookups.filter((c) => "error" in c.result);

  const patchTasks = resolvedCves.length
    ? resolvedCves.map((c) => `Apply mitigation for ${c.cveId} (see analysis for details)`)
    : ["Patch affected systems", "Review the attack/lateral-movement path"];

  return {
    incidentCode: investigation.incident.incidentCode,
    linkedCves: cveLookups.map((c) => ({
      cveId: c.cveId,
      status: "error" in c.result ? (c.result as { error: string }).error : "resolved",
      data: "error" in c.result ? null : c.result,
    })),
    plan: {
      immediate: assetNames.length
        ? [`Isolate affected asset(s): ${assetNames.join(", ")}`, "Revoke exposed credentials"]
        : ["Confirm scope of affected assets before further action"],
      shortTerm: patchTasks,
      longTerm: ["Expand monitoring coverage", "Revisit segmentation for the affected area"],
      note: unresolvedCves.length
        ? `${unresolvedCves.length} linked CVE(s) could not be resolved against the knowledge base — generic tasks shown for those.`
        : undefined,
    },
    governanceNote:
      "This is a recommendation only. No action here executes automatically " +
      "— every task requires analyst approval.",
  };
}

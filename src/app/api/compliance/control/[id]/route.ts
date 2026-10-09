import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import {
  getFrameworkCompliance,
  FrameworkId,
  FrameworkControl,
} from "@/lib/compliance/frameworks";
import { getPoliciesForControl } from "@/lib/compliance/policyStore";
import { getOrCreateTenantStore } from "@/lib/compliance/statefulTenantDb";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { id: rawId } = await params;
    const controlCode = decodeURIComponent(rawId).toUpperCase();

    const url = new URL(req.url);
    const frameworkId = (url.searchParams.get("framework") as FrameworkId) || "iso27001";

    const compliance = await getFrameworkCompliance(caller, frameworkId);
    let control: FrameworkControl | undefined = compliance.controls.find(
      (c) => c.code.toUpperCase() === controlCode
    );

    // If not found in current framework, search all frameworks
    if (!control) {
      for (const fid of ["iso27001", "soc2", "nist", "hipaa"] as FrameworkId[]) {
        const fc = await getFrameworkCompliance(caller, fid);
        const match = fc.controls.find((c) => c.code.toUpperCase() === controlCode);
        if (match) {
          control = match;
          break;
        }
      }
    }

    if (!control) {
      return NextResponse.json(
        { error: `Control '${controlCode}' not found in framework definitions.` },
        { status: 404 }
      );
    }

    const linkedPolicies = await getPoliciesForControl(caller, control.code);
    const tenantId = caller.tenant_id;
    const store = getOrCreateTenantStore(tenantId);

    // Gather live records tied to this control
    let records: Record<string, unknown>[] = [];
    const recordSource = control.auditEvidenceSource;

    try {
      const { query } = await import("@/lib/db");

      if (
        control.code.includes("A.8.7") ||
        control.code.includes("CC6.8") ||
        control.code.includes("DE.AE")
      ) {
        // YARA & Malware detections
        const res = await query<Record<string, unknown>>(
          `SELECT id, rule_id, agent_id, file_path, matched_strings, incident_id, created_at
           FROM yara_rule_matches
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      } else if (
        control.code.includes("A.9.2") ||
        control.code.includes("CC6.1") ||
        control.code.includes("PR.AC") ||
        control.code.includes("164.312(a)")
      ) {
        // Approval tokens & Separation of duties
        const res = await query<Record<string, unknown>>(
          `SELECT id, task_id, requested_by, approved_by, status, autonomy_tier, action_type, created_at
           FROM approval_tokens
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      } else if (
        control.code.includes("A.5.28") ||
        control.code.includes("A.8.24") ||
        control.code.includes("PR.DS") ||
        control.code.includes("164.312(c)")
      ) {
        // Cryptographic Hash Chain Audit
        const res = await query<Record<string, unknown>>(
          `SELECT id, event_type, actor_id, prev_hash, current_hash, created_at, payload
           FROM hash_chain_audit
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      } else if (
        control.code.includes("A.8.8") ||
        control.code.includes("CC7.1") ||
        control.code.includes("ID.RA")
      ) {
        // Vulnerabilities
        const res = await query<Record<string, unknown>>(
          `SELECT id, cve_id, asset_hostname, cvss_score, vendor_severity, status, first_seen_at
           FROM asset_vulnerabilities
           WHERE tenant_id = $1
           ORDER BY cvss_score DESC NULLS LAST
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      } else if (
        control.code.includes("A.8.16") ||
        control.code.includes("CC7.2") ||
        control.code.includes("DE.CM") ||
        control.code.includes("164.312(b)")
      ) {
        // Endpoint Agents & Telemetry
        const res = await query<Record<string, unknown>>(
          `SELECT id, hostname, ip_address, os_type, agent_version, status, cpu_usage, memory_usage, eps, last_heartbeat
           FROM endpoint_agents
           WHERE tenant_id = $1
           ORDER BY last_heartbeat DESC NULLS LAST
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      } else {
        // Agent Command Logs / Incident Playbooks
        const res = await query<Record<string, unknown>>(
          `SELECT id, agent_id, command, tier, status, executed_by, executed_at, output
           FROM agent_command_logs
           WHERE tenant_id = $1
           ORDER BY executed_at DESC
           LIMIT 25`,
          [tenantId]
        );
        if (res.rows && res.rows.length > 0) {
          records = res.rows;
        }
      }
    } catch {
      // Offline fallback
    }

    // Fallback to in-memory stateful store if DB returned no records
    if (records.length === 0) {
      if (
        control.code.includes("A.8.7") ||
        control.code.includes("CC6.8") ||
        control.code.includes("DE.AE")
      ) {
        records = store.yaraMatches as unknown as Record<string, unknown>[];
      } else if (
        control.code.includes("A.9.2") ||
        control.code.includes("CC6.1") ||
        control.code.includes("PR.AC") ||
        control.code.includes("164.312(a)")
      ) {
        records = store.approvalTokens as unknown as Record<string, unknown>[];
      } else if (
        control.code.includes("A.5.28") ||
        control.code.includes("A.8.24") ||
        control.code.includes("PR.DS") ||
        control.code.includes("164.312(c)")
      ) {
        records = store.hashChain as unknown as Record<string, unknown>[];
      } else if (
        control.code.includes("A.8.8") ||
        control.code.includes("CC7.1") ||
        control.code.includes("ID.RA")
      ) {
        records = store.cveRecords as unknown as Record<string, unknown>[];
      } else if (
        control.code.includes("A.8.16") ||
        control.code.includes("CC7.2") ||
        control.code.includes("DE.CM") ||
        control.code.includes("164.312(b)")
      ) {
        records = store.endpointAgents as unknown as Record<string, unknown>[];
      } else {
        records = store.agentCommandLogs as unknown as Record<string, unknown>[];
      }
    }

    const healthStatus: "COMPLIANT" | "ATTENTION_REQUIRED" | "MANUAL_REVIEW" =
      control.compliancePct >= 95
        ? "COMPLIANT"
        : control.compliancePct >= 80
        ? "MANUAL_REVIEW"
        : "ATTENTION_REQUIRED";

    return NextResponse.json({
      success: true,
      control: {
        ...control,
        evidenceHealth: healthStatus,
        evidenceRecords: records,
        evidenceRecordCount: records.length,
        auditEvidenceSource: recordSource,
        linkedPolicies,
      },
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/control/[id]" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

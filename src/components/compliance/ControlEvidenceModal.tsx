"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  ShieldCheck,
  AlertCircle,
  FileText,
  Layers,
  CheckCircle2,
  Code2,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface LinkedPolicy {
  id: string;
  policyCode: string;
  title: string;
  description: string;
  version: string;
}

interface ControlEvidenceData {
  code: string;
  title: string;
  category: string;
  horizon: string;
  compliancePct: number;
  evidenceHealth: "COMPLIANT" | "ATTENTION_REQUIRED" | "MANUAL_REVIEW";
  automationTier: string;
  clauseRequirement: string;
  shieldDeskEnforcement: string;
  auditEvidenceSource: string;
  evidenceRecords: Record<string, unknown>[];
  linkedPolicies?: LinkedPolicy[];
}

interface ControlEvidenceModalProps {
  controlCode: string | null;
  frameworkId: string;
  onClose: () => void;
  activeUserId: string;
}

export function ControlEvidenceModal({
  controlCode,
  frameworkId,
  onClose,
  activeUserId,
}: ControlEvidenceModalProps) {
  const [data, setData] = useState<ControlEvidenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inspectingRow, setInspectingRow] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    let ignore = false;
    if (!controlCode) return;

    fetch(
      `/api/compliance/control/${encodeURIComponent(controlCode)}?framework=${frameworkId}`,
      {
        headers: { "X-ShieldDesk-User": activeUserId },
      }
    )
      .then((res) => res.json())
      .then((json) => {
        if (!ignore) {
          if (json.control) {
            setData(json.control);
          } else {
            setError(json.error || "Failed to load control evidence.");
          }
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Network error");
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [controlCode, frameworkId, activeUserId]);

  if (!controlCode) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      <div className="sd-surface border border-[var(--sd-border)] rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden bg-[var(--sd-surface)] text-[var(--sd-text)]">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)] bg-[var(--sd-bg)]">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs font-semibold px-2.5 py-1 rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)]">
              {controlCode}
            </span>
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)] tracking-tight">
                {data?.title || "Control Evidence Inspector"}
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                {data?.category} · Horizon:{" "}
                <span className="capitalize font-mono text-[var(--sd-pine)]">
                  {data?.horizon?.replace("_", " ") || "continuous"}
                </span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {data?.evidenceHealth && (
              <span
                className={cn(
                  "px-2.5 py-1 rounded-full text-xs font-mono font-medium uppercase tracking-wider flex items-center gap-1.5 border",
                  data.evidenceHealth === "COMPLIANT"
                    ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]"
                    : data.evidenceHealth === "MANUAL_REVIEW"
                    ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]"
                    : "bg-red-500/10 text-red-500 border-red-500/20"
                )}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                {data.evidenceHealth.replace("_", " ")} ({data.compliancePct}%)
              </span>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {loading ? (
            <div className="py-16 text-center text-sm text-[var(--sd-text-muted)] flex flex-col items-center gap-2">
              <div className="h-6 w-6 border-2 border-[var(--sd-pine)] border-t-transparent rounded-full animate-spin" />
              <span>Querying live database telemetry and audit logs...</span>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl border border-red-500/20 bg-red-500/10 text-red-400 text-sm flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          ) : (
            <>
              {/* Clause & Enforcement Specs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[var(--sd-text-muted)]">
                    <ShieldCheck className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                    <span>Regulatory Requirement</span>
                  </div>
                  <p className="text-xs text-[var(--sd-text)] leading-relaxed">
                    {data?.clauseRequirement}
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[var(--sd-text-muted)]">
                      <Layers className="h-3.5 w-3.5 text-[var(--sd-wheat)]" />
                      <span>Platform Enforcement</span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)]">
                      {data?.automationTier}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--sd-text)] leading-relaxed">
                    {data?.shieldDeskEnforcement}
                  </p>
                </div>
              </div>

              {/* Linked Company Policies */}
              {data?.linkedPolicies && data.linkedPolicies.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-medium uppercase tracking-wider text-[var(--sd-text-muted)] flex items-center gap-1.5">
                      <FileText className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                      <span>Linked Organizational Policies ({data.linkedPolicies.length})</span>
                    </h3>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {data.linkedPolicies.map((pol: LinkedPolicy) => (
                      <div
                        key={pol.id}
                        className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] flex items-start justify-between gap-2"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono font-medium px-1.5 py-0.2 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)]">
                              {pol.policyCode}
                            </span>
                            <span className="text-xs font-medium text-[var(--sd-text)]">
                              {pol.title}
                            </span>
                          </div>
                          <p className="text-[11px] text-[var(--sd-text-muted)] mt-1 line-clamp-1">
                            {pol.description}
                          </p>
                        </div>
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)] shrink-0">
                          v{pol.version}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Live Database Evidence Records */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs font-medium uppercase tracking-wider text-[var(--sd-text-muted)] flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--sd-success)]" />
                      <span>Live Database Evidence Telemetry</span>
                    </h3>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)]">
                      {data?.evidenceRecords?.length || 0} live records
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                    Source: {data?.auditEvidenceSource}
                  </span>
                </div>

                {data?.evidenceRecords?.length === 0 ? (
                  <div className="p-8 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-center text-xs text-[var(--sd-text-muted)]">
                    No active incident records currently stored for this control.
                  </div>
                ) : (
                  <div className="rounded-xl border border-[var(--sd-border)] overflow-hidden bg-[var(--sd-bg)]">
                    <div className="overflow-x-auto max-h-[300px]">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-[var(--sd-panel-raised)] border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] font-mono text-[11px]">
                          <tr>
                            <th className="py-2.5 px-3 font-medium">Record ID / Ref</th>
                            <th className="py-2.5 px-3 font-medium">Timestamp / Seen</th>
                            <th className="py-2.5 px-3 font-medium">Entity / Actor</th>
                            <th className="py-2.5 px-3 font-medium">Status / Action</th>
                            <th className="py-2.5 px-3 font-medium text-right">Details</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[var(--sd-border)]">
                          {data?.evidenceRecords?.map((row: Record<string, unknown>, idx: number) => {
                            const idVal = String(row.id || row.rule_id || row.cve_id || row.hostname || `rec-${idx}`);
                            const timeVal = String(
                              row.created_at || row.last_heartbeat || row.first_seen_at || row.executed_at || "—"
                            );
                            const actorVal = String(
                              row.actor_id ||
                              row.requested_by ||
                              row.agent_id ||
                              row.asset_hostname ||
                              row.hostname ||
                              "—"
                            );
                            const statusVal =
                              row.status || row.decision || row.event_type || row.vendor_severity || "ACTIVE";

                            return (
                              <tr
                                key={idx}
                                className="hover:bg-[var(--sd-panel-raised)]/60 transition-colors"
                              >
                                <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--sd-text)] truncate max-w-[180px]">
                                  {String(idVal)}
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--sd-text-muted)]">
                                  {typeof timeVal === "string" ? timeVal.slice(0, 19).replace("T", " ") : "—"}
                                </td>
                                <td className="py-2.5 px-3 text-[var(--sd-text)] truncate max-w-[180px]">
                                  {String(actorVal)}
                                </td>
                                <td className="py-2.5 px-3">
                                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)] uppercase">
                                    {String(statusVal)}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 text-right">
                                  <button
                                    onClick={() => setInspectingRow(row)}
                                    className="p-1 rounded hover:bg-[var(--sd-bg)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                                    title="View Raw Record JSON"
                                  >
                                    <Code2 className="h-3.5 w-3.5" />
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Row JSON Inspector Popup */}
        {inspectingRow && (
          <div className="fixed inset-0 z-60 bg-black/60 flex items-center justify-center p-4">
            <div className="bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-2xl p-5 max-w-xl w-full space-y-3 shadow-2xl">
              <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
                <span className="font-mono text-xs font-semibold text-[var(--sd-text)]">
                  Live Record Telemetry Payload
                </span>
                <button
                  onClick={() => setInspectingRow(null)}
                  className="p-1 rounded hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] cursor-pointer"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-[var(--sd-panel-raised)] text-[11px] font-mono text-[var(--sd-text)] overflow-x-auto max-h-[300px]">
                {JSON.stringify(inspectingRow, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="p-4 border-t border-[var(--sd-border)] bg-[var(--sd-bg)] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

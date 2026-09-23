"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  Printer,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  Layers,
  Sparkles,
  RefreshCw,
  Lock,
} from "lucide-react";
import { useChat } from "@/lib/context/ChatContext";
import { AutonomyTierBadge } from "@/components/governance/AutonomyTierBadge";
import { ApprovalModal } from "@/components/governance/ApprovalModal";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

interface MitigationTask {
  id: string;
  plan_id: string;
  horizon: "immediate" | "short_term" | "long_term";
  title: string;
  description: string;
  tier: string;
  status: "pending" | "approved" | "rejected" | "in_progress" | "completed";
  blast_radius?: string;
  cve_id?: string | null;
  created_at: string;
}

interface MitigationPlanData {
  plan: {
    id: string;
    incident_id: string;
    tenant_id: string;
    version: number;
    status: string;
    summary: string;
    created_at: string;
    incident_code: string;
    incident_title: string;
    incident_severity: string;
  };
  tasks: MitigationTask[];
}

export default function PlanViewerPage() {
  const params = useParams();
  const planId = params?.id as string;
  const { activeUserId, openChatWithPrompt } = useChat();

  const [data, setData] = useState<MitigationPlanData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Approval modal state
  const [activeToken, setActiveToken] = useState<ApprovalTokenRecord | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);

  const fetchPlanData = () => {
    if (!planId) return;
    setIsLoading(true);

    fetch(`/api/plans/${encodeURIComponent(planId)}`, {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then(async (res) => {
        if (!res.ok) {
          if (res.status === 404) {
            throw new Error("Mitigation plan not found or inaccessible for your tenant.");
          }
          throw new Error("Failed to load mitigation plan.");
        }
        return res.json();
      })
      .then((planData) => {
        setData(planData);
        setError(null);
      })
      .catch((err) => {
        setError(err.message || "Failed to load plan");
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  useEffect(() => {
    fetchPlanData();
  }, [planId, activeUserId]);

  const handlePrint = () => {
    window.print();
  };

  const handleRequestApproval = async (task: MitigationTask) => {
    setActionLoadingId(task.id);
    try {
      const res = await fetch(`/api/approvals?taskId=${encodeURIComponent(task.id)}`, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const body = await res.json();
      let token: ApprovalTokenRecord | null = null;
      if (body.tokens && body.tokens.length > 0) {
        token = body.tokens[0];
      } else {
        const createRes = await fetch("/api/approvals", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ShieldDesk-User": activeUserId,
          },
          body: JSON.stringify({
            taskId: task.id,
            actionType: task.title,
            blastRadius: task.blast_radius || "Target Workstation Scope",
          }),
        });
        const createBody = await createRes.json();
        token = createBody.token;
      }

      if (token) {
        setActiveToken(token);
        setIsModalOpen(true);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleDecisionSuccess = () => {
    fetchPlanData();
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col items-center justify-center gap-3">
        <RefreshCw className="h-6 w-6 animate-spin text-[var(--sd-pine-bright)]" />
        <span className="text-xs text-[var(--sd-text-muted)] font-mono">Loading mitigation plan...</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col items-center justify-center p-6">
        <div className="max-w-md w-full p-6 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] text-center space-y-4">
          <AlertCircle className="h-10 w-10 text-[var(--sd-danger)] mx-auto" />
          <h2 className="text-sm font-bold text-[var(--sd-beige-light)]">Inaccessible or Not Found</h2>
          <p className="text-xs text-[var(--sd-text-muted)]">{error || "Could not retrieve plan data."}</p>
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[var(--sd-panel-raised)] text-xs font-semibold text-[var(--sd-beige)] hover:bg-[var(--sd-panel-hover)] transition"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Return to SOC Console
          </Link>
        </div>
      </div>
    );
  }

  const { plan, tasks } = data;
  const immediateTasks = tasks.filter((t) => t.horizon === "immediate");
  const shortTermTasks = tasks.filter((t) => t.horizon === "short_term");
  const longTermTasks = tasks.filter((t) => t.horizon === "long_term");

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] p-6 md:p-10 font-sans print:p-0 print:bg-white print:text-black">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Navigation & Action Bar */}
        <div className="flex items-center justify-between print:hidden">
          <Link
            href="/"
            className="flex items-center gap-2 text-xs font-semibold text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] transition"
          >
            <ArrowLeft className="h-4 w-4 text-[var(--sd-pine)]" />
            <span>Return to Incident Queue</span>
          </Link>

          <div className="flex items-center gap-3">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-pine)] transition cursor-pointer shadow-xs"
            >
              <Printer className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
              <span>Print / Export PDF</span>
            </button>
            <button
              onClick={() =>
                openChatWithPrompt(
                  `Review mitigation plan ${plan.id} for incident ${plan.incident_code}`
                )
              }
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[#f7f4ed] text-xs font-semibold transition cursor-pointer shadow-xs"
            >
              <Sparkles className="h-3.5 w-3.5 text-[#e6dbbf]" />
              <span>Ask AI Co-Pilot</span>
            </button>
          </div>
        </div>

        {/* Plan Header Card */}
        <div className="p-6 md:p-8 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--sd-border)] pb-4">
            <div className="flex items-center gap-3">
              <span className="rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] px-2.5 py-1 font-mono text-xs font-bold text-[var(--sd-pine)]">
                {plan.incident_code}
              </span>
              <span className="rounded-md bg-[var(--sd-danger-dim)] border border-[var(--sd-danger-border)] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-[var(--sd-danger)]">
                {plan.incident_severity}
              </span>
              <span className="rounded-md bg-white border border-[var(--sd-border)] px-2 py-0.5 text-[10px] font-semibold text-[var(--sd-pine)] font-mono shadow-xs">
                Plan v{plan.version} &bull; {plan.status.toUpperCase()}
              </span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)] font-mono">
              Generated {new Date(plan.created_at).toLocaleString()}
            </span>
          </div>

          <div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--sd-pine)]">
              {plan.incident_title}
            </h1>
            <p className="text-xs text-[var(--sd-text-muted)] mt-2 leading-relaxed max-w-4xl">
              {plan.summary}
            </p>
          </div>
        </div>

        {/* 3 Horizon Task Sections */}
        <div className="space-y-6">
          {/* Horizon 1: Immediate Containment */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[var(--sd-danger)]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Horizon 1: Immediate Containment & Isolation (&lt; 1 Hour)
                </h2>
              </div>
              <span className="text-[11px] font-mono text-[var(--sd-text-muted)] font-semibold">
                {immediateTasks.length} Actions
              </span>
            </div>

            <div className="space-y-3">
              {immediateTasks.map((t) => (
                <div
                  key={t.id}
                  className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <AutonomyTierBadge tier={t.tier} size="sm" />
                      <span className="font-semibold text-[var(--sd-text)]">{t.title}</span>
                    </div>
                    <p className="text-[11px] text-[var(--sd-text-muted)]">{t.description}</p>
                    {t.blast_radius && (
                      <span className="text-[10px] text-[var(--sd-text-muted)] font-mono block">
                        Blast Radius: {t.blast_radius}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {t.status === "completed" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-success)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Completed
                      </span>
                    ) : t.status === "approved" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-pine)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Approved
                      </span>
                    ) : (
                      <button
                        onClick={() => handleRequestApproval(t)}
                        disabled={actionLoadingId === t.id}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] hover:bg-[var(--sd-warning-border)] text-[11px] font-bold cursor-pointer transition shadow-xs disabled:opacity-50"
                      >
                        <Lock className="h-3 w-3" />
                        <span>Sign Off Action</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Horizon 2: Short-Term Remediation */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[var(--sd-warning)]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Horizon 2: Short-Term Remediation & Patching (&lt; 24-48 Hours)
                </h2>
              </div>
              <span className="text-[11px] font-mono text-[var(--sd-text-muted)] font-semibold">
                {shortTermTasks.length} Actions
              </span>
            </div>

            <div className="space-y-3">
              {shortTermTasks.map((t) => (
                <div
                  key={t.id}
                  className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <AutonomyTierBadge tier={t.tier} size="sm" />
                      <span className="font-semibold text-[var(--sd-text)]">{t.title}</span>
                      {t.cve_id && (
                        <span className="rounded bg-white px-1.5 py-0.5 font-mono text-[10px] text-[var(--sd-pine)] border border-[var(--sd-border)] font-semibold">
                          {t.cve_id}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-[var(--sd-text-muted)]">{t.description}</p>
                    {t.blast_radius && (
                      <span className="text-[10px] text-[var(--sd-text-muted)] font-mono block">
                        Blast Radius: {t.blast_radius}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {t.status === "completed" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-success)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Completed
                      </span>
                    ) : t.status === "approved" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-pine)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Approved
                      </span>
                    ) : (
                      <button
                        onClick={() => handleRequestApproval(t)}
                        disabled={actionLoadingId === t.id}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] hover:bg-[var(--sd-warning-border)] text-[11px] font-bold cursor-pointer transition shadow-xs disabled:opacity-50"
                      >
                        <Lock className="h-3 w-3" />
                        <span>Sign Off Action</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Horizon 3: Long-Term Hardening */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[var(--sd-pine)]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Horizon 3: Long-Term Architectural Hardening (&lt; 7-30 Days)
                </h2>
              </div>
              <span className="text-[11px] font-mono text-[var(--sd-text-muted)] font-semibold">
                {longTermTasks.length} Actions
              </span>
            </div>

            <div className="space-y-3">
              {longTermTasks.map((t) => (
                <div
                  key={t.id}
                  className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <AutonomyTierBadge tier={t.tier} size="sm" />
                      <span className="font-semibold text-[var(--sd-text)]">{t.title}</span>
                    </div>
                    <p className="text-[11px] text-[var(--sd-text-muted)]">{t.description}</p>
                    {t.blast_radius && (
                      <span className="text-[10px] text-[var(--sd-text-muted)] font-mono block">
                        Blast Radius: {t.blast_radius}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {t.status === "completed" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-success)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Completed
                      </span>
                    ) : t.status === "approved" ? (
                      <span className="flex items-center gap-1 text-[var(--sd-pine)] font-semibold text-[11px]">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Approved
                      </span>
                    ) : (
                      <button
                        onClick={() => handleRequestApproval(t)}
                        disabled={actionLoadingId === t.id}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] hover:bg-[var(--sd-warning-border)] text-[11px] font-bold cursor-pointer transition shadow-xs disabled:opacity-50"
                      >
                        <Lock className="h-3 w-3" />
                        <span>Sign Off Action</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Global Approval Modal */}
      <ApprovalModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        token={activeToken}
        onDecisionSuccess={handleDecisionSuccess}
      />
    </div>
  );
}

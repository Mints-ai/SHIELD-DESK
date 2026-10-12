"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  FileText,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Plus,
  RefreshCw,
  Search,
  Filter,
  Activity,
  Layers,
  History,
  CheckCheck,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useChat } from "@/lib/context/ChatContext";
import { TopNavBar } from "@/components/navigation/TopNavBar";

interface PlanSummary {
  id: string;
  incident_id: string;
  incident_code: string;
  incident_title: string;
  incident_severity: string;
  status: string;
  version: number;
  summary: string;
  task_count: number;
  completed_task_count?: number;
  created_at: string;
}

export default function PlansIndexPage() {
  const { activeUserId, openChatWithPrompt } = useChat();
  const [isSampleData, setIsSampleData] = useState(false);
  const [plans, setPlans] = useState<PlanSummary[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("all");
  const [statusTab, setStatusTab] = useState<"all" | "active" | "completed">("all");
  const [isLoading, setIsLoading] = useState(true);

  // Fallback demo plans matching seed data
  const fallbackPlans: PlanSummary[] = [
    {
      id: "p1111111-1111-1111-1111-111111111111",
      incident_id: "i1111111-1111-1111-1111-111111111111",
      incident_code: "INC-1042",
      incident_title: "Active Exploitation of Edge VPN Gateway (CVE-2024-3400)",
      incident_severity: "critical",
      status: "in_progress",
      version: 1,
      summary:
        "Emergency containment protocol for PAN-OS GlobalProtect command injection. Isolates VPN gateway, revokes active sessions, and applies hotfix hotfix-panos-10.2.9-h1.",
      task_count: 5,
      completed_task_count: 2,
      created_at: "2026-09-23T20:00:00Z",
    },
    {
      id: "p2222222-2222-2222-2222-222222222222",
      incident_id: "i2222222-2222-2222-2222-222222222222",
      incident_code: "INC-1043",
      incident_title: "Privilege Escalation on Finance Workstation WS-FIN-08",
      incident_severity: "high",
      status: "approved",
      version: 1,
      summary:
        "Containment and forensic capture for pass-the-hash lateral movement attempt. Freezes active workstation session and rotates local administrator credentials.",
      task_count: 4,
      completed_task_count: 1,
      created_at: "2026-09-23T21:15:00Z",
    },
    {
      id: "p3333333-3333-3333-3333-333333333333",
      incident_id: "i3333333-3333-3333-3333-333333333333",
      incident_code: "INC-1044",
      incident_title: "Suspicious PowerShell Execution via Macro Attachment",
      incident_severity: "medium",
      status: "completed",
      version: 2,
      summary:
        "Phishing triage and payload detonation analysis. Quarantined malicious macro template and blocked domain telemetry at firewall perimeter.",
      task_count: 3,
      completed_task_count: 3,
      created_at: "2026-09-23T18:30:00Z",
    },
  ];

  useEffect(() => {
    let isMounted = true;
    async function fetchPlans() {
      setIsLoading(true);
      try {
        const res = await fetch("/api/plans", {
          headers: { "X-ShieldDesk-User": activeUserId },
        });
        if (res.ok) {
          const data = await res.json();
          if (isMounted) {
            setPlans(data.plans || []);
            setIsSampleData(data._source === "demo_fallback");
          }
        } else {
          if (isMounted) {
            setPlans(fallbackPlans);
            setIsSampleData(true);
          }
        }
      } catch {
        if (isMounted) {
          setPlans(fallbackPlans);
          setIsSampleData(true);
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    fetchPlans();
    return () => {
      isMounted = false;
    };
  }, [activeUserId]);

  const isPlanActive = (status: string) => {
    const s = status.toLowerCase();
    return !["completed", "resolved", "archived", "closed"].includes(s);
  };

  // Metrics across all plans
  const metrics = useMemo(() => {
    const active = plans.filter((p) => isPlanActive(p.status));
    const completed = plans.filter((p) => !isPlanActive(p.status));
    const pendingTasks = active.reduce((acc, p) => {
      const comp = p.completed_task_count ?? 0;
      return acc + Math.max(0, p.task_count - comp);
    }, 0);
    const criticalActive = active.filter((p) => p.incident_severity === "critical").length;

    return {
      total: plans.length,
      activeCount: active.length,
      completedCount: completed.length,
      pendingTasks,
      criticalActive,
    };
  }, [plans]);

  // Filtered lists
  const filteredPlans = useMemo(() => {
    return plans.filter((p) => {
      const matchesSearch =
        p.incident_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.incident_title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.summary.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity =
        selectedSeverity === "all" || p.incident_severity === selectedSeverity;
      return matchesSearch && matchesSeverity;
    });
  }, [plans, searchQuery, selectedSeverity]);

  const activePlans = useMemo(
    () => filteredPlans.filter((p) => isPlanActive(p.status)),
    [filteredPlans]
  );

  const completedPlans = useMemo(
    () => filteredPlans.filter((p) => !isPlanActive(p.status)),
    [filteredPlans]
  );

  const formatRelativeTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)]">
      <TopNavBar />
      {/* Main Content Area */}
      <main className="sd-dashboard-content min-w-0 max-w-7xl mx-auto px-6 py-6 flex flex-col gap-6">
        {isSampleData && <p className="sd-sample-label w-fit">Sample plans · Local fallback data</p>}

        {/* ── Page Header Card ── */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs px-6 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 rounded-xl bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 flex items-center justify-center shrink-0">
              <FileText className="h-5 w-5 text-[var(--sd-pine)]" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[11px] font-medium text-[var(--sd-pine)] uppercase tracking-widest font-mono">
                  Phase 1 Governance
                </span>
                <span className="text-[11px] text-[var(--sd-text-muted)]">•</span>
                <span className="text-[11px] font-medium text-[var(--sd-text-muted)]">
                  Autonomous Mitigation Engine
                </span>
              </div>
              <h1 className="text-[var(--sd-text)] tracking-tight text-3xl font-light leading-tight">
                Mitigation plans
              </h1>
            </div>
          </div>
          <button
            onClick={() => openChatWithPrompt("Generate a mitigation plan for active incident")}
            className="sd-button sd-button-primary inline-flex items-center gap-2 px-4 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium shadow-xs transition-colors cursor-pointer shrink-0"
          >
            <Plus className="h-4 w-4" />
            <span>Generate New Plan</span>
          </button>
        </div>

        {/* ── Operational Metrics Strip ── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Active In-Flight Sequences */}
          <div className="rounded-xl border border-[var(--sd-border)] sd-surface p-4 flex items-center justify-between shadow-xs relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-[var(--sd-pine)]" />
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--sd-pine)] opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--sd-pine)]"></span>
                </span>
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                  Active In-Flight
                </span>
              </div>
              <div className="text-2xl font-light tracking-tight text-[var(--sd-text)] flex items-baseline gap-2">
                <span>{metrics.activeCount}</span>
                <span className="text-[12px] font-normal text-[var(--sd-text-muted)]">
                  {metrics.activeCount === 1 ? "runbook executing" : "runbooks executing"}
                </span>
              </div>
            </div>
            <div className="h-10 w-10 rounded-lg bg-[var(--sd-pine)]/10 border border-[var(--sd-pine)]/20 flex items-center justify-center shrink-0">
              <Activity className="h-5 w-5 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Pending Tasks In-Flight */}
          <div className="rounded-xl border border-[var(--sd-border)] sd-surface p-4 flex items-center justify-between shadow-xs relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-amber-500/80" />
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                  Tasks In-Flight
                </span>
              </div>
              <div className="text-2xl font-light tracking-tight text-[var(--sd-text)] flex items-baseline gap-2">
                <span>{metrics.pendingTasks}</span>
                <span className="text-[12px] font-normal text-[var(--sd-text-muted)]">
                  containment steps pending
                </span>
              </div>
            </div>
            <div className="h-10 w-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
              <Layers className="h-5 w-5 text-amber-400" />
            </div>
          </div>

          {/* Resolved & Audited Runbooks */}
          <div className="rounded-xl border border-[var(--sd-border)] sd-surface p-4 flex items-center justify-between shadow-xs relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-emerald-500/40" />
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="h-2 w-2 rounded-full bg-emerald-400/80" />
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                  Resolved Archive
                </span>
              </div>
              <div className="text-2xl font-light tracking-tight text-[var(--sd-text)] flex items-baseline gap-2">
                <span>{metrics.completedCount}</span>
                <span className="text-[12px] font-normal text-[var(--sd-text-muted)]">
                  mitigations verified & closed
                </span>
              </div>
            </div>
            <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
            </div>
          </div>
        </div>

        {/* ── Controls: Segmented Status Tabs, Search & Severity Filters ── */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 pt-1">
          {/* Status Tab Switcher */}
          <div className="inline-flex p-1 rounded-xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] shrink-0 self-start lg:self-auto">
            <button
              onClick={() => setStatusTab("all")}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all cursor-pointer ${
                statusTab === "all"
                  ? "bg-[var(--sd-surface)] text-[var(--sd-text)] shadow-xs border border-[var(--sd-border)]"
                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              }`}
            >
              <span>All Plans</span>
              <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-[var(--sd-bg)] text-[var(--sd-text-muted)] font-mono">
                {metrics.total}
              </span>
            </button>
            <button
              onClick={() => setStatusTab("active")}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all cursor-pointer ${
                statusTab === "active"
                  ? "bg-[var(--sd-surface)] text-[var(--sd-pine)] shadow-xs border border-[var(--sd-pine)]/40"
                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              }`}
            >
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--sd-pine)] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[var(--sd-pine)]"></span>
              </span>
              <span>Active Runbooks</span>
              <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-[var(--sd-pine)]/15 text-[var(--sd-pine)] font-mono font-medium">
                {metrics.activeCount}
              </span>
            </button>
            <button
              onClick={() => setStatusTab("completed")}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all cursor-pointer ${
                statusTab === "completed"
                  ? "bg-[var(--sd-surface)] text-[var(--sd-text)] shadow-xs border border-[var(--sd-border)]"
                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              }`}
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>Completed Archive</span>
              <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-[var(--sd-bg)] text-[var(--sd-text-muted)] font-mono">
                {metrics.completedCount}
              </span>
            </button>
          </div>

          {/* Search & Severity Filters */}
          <div className="flex flex-col sm:flex-row items-center gap-3 flex-1 lg:justify-end">
            <div className="relative w-full sm:w-72">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--sd-text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search incident, title, action..."
                className="sd-input w-full pl-9 pr-3 py-1.5 rounded-xl border border-[var(--sd-border)] sd-surface text-[12px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)] shadow-xs"
              />
            </div>

            <div className="flex items-center gap-1.5 self-start sm:self-auto shrink-0">
              <span className="text-[12px] font-medium text-[var(--sd-text-muted)] flex items-center gap-1 mr-1">
                <Filter className="h-3 w-3" /> Severity:
              </span>
              {["all", "critical", "high", "medium"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  aria-pressed={selectedSeverity === sev}
                  className={`px-2.5 py-1 rounded-lg text-[12px] font-medium transition-colors cursor-pointer capitalize ${
                    selectedSeverity === sev
                      ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] shadow-xs"
                      : "sd-surface border border-[var(--sd-border)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* ── Content Body ── */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <RefreshCw className="h-8 w-8 animate-spin text-[var(--sd-pine)] mb-3" />
            <p className="text-[13px] text-[var(--sd-text-muted)] font-mono">
              Loading mitigation plans...
            </p>
          </div>
        ) : filteredPlans.length === 0 ? (
          <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-12 text-center shadow-xs">
            <FileText className="h-10 w-10 text-[var(--sd-text-muted)] mx-auto mb-3 opacity-60" />
            <h3 className="text-sm font-medium text-[var(--sd-pine)]">
              No mitigation plans found
            </h3>
            <p className="text-[13px] text-[var(--sd-text-muted)] max-w-sm mx-auto mt-1">
              No records match your active search or severity filter. Try resetting filters or generate a new runbook.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-8">
            {/* ════ SECTION 1: ACTIVE IN-FLIGHT RUNBOOKS ════ */}
            {(statusTab === "all" || statusTab === "active") && (
              <section className="flex flex-col gap-4">
                {/* Section Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-[var(--sd-border)] gap-2">
                  <div className="flex items-center gap-3">
                    <div className="h-7 w-7 rounded-lg bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30 flex items-center justify-center">
                      <Activity className="h-4 w-4 text-[var(--sd-pine)]" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-sm font-semibold tracking-wide uppercase font-mono text-[var(--sd-text)]">
                          Active Remediation Sequences
                        </h2>
                        <span className="px-2 py-0.2 rounded-full text-[11px] font-mono font-medium bg-[var(--sd-pine)]/15 text-[var(--sd-pine)] border border-[var(--sd-pine)]/30">
                          {activePlans.length} in-flight
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--sd-text-muted)]">
                        Remediation sequences currently in-flight, awaiting operator sign-off, or actively dispatching containment.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Active Cards Grid */}
                {activePlans.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-[var(--sd-border)] p-8 text-center bg-[var(--sd-surface)]/50">
                    <ShieldCheck className="h-8 w-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                    <p className="text-[13px] font-medium text-[var(--sd-text)]">
                      No active remediation runbooks requiring immediate action
                    </p>
                    <p className="text-[12px] text-[var(--sd-text-muted)] mt-0.5">
                      All incident containment steps have been verified or completed.
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    {activePlans.map((plan) => {
                      const completedCount =
                        plan.completed_task_count ??
                        (plan.status === "completed" ? plan.task_count : 0);
                      const percent =
                        plan.task_count > 0
                          ? Math.round((completedCount / plan.task_count) * 100)
                          : 0;

                      return (
                        <div
                          key={plan.id}
                          className="rounded-2xl border border-[var(--sd-pine)]/35 sd-surface p-5 flex flex-col justify-between hover:shadow-lg hover:border-[var(--sd-pine)]/70 transition-all group relative overflow-hidden shadow-xs"
                        >
                          {/* Top Accent Gradient Bar */}
                          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[var(--sd-pine)] via-emerald-400 to-[var(--sd-pine)]/30" />

                          <div>
                            {/* Card Header: Code, Severity, and Live Status Badge */}
                            <div className="flex items-center justify-between gap-2 mb-2.5 pt-0.5">
                              <div className="flex items-center gap-1.5">
                                <span className="font-mono text-[12px] font-medium px-2 py-0.5 rounded bg-[var(--sd-bg-alt)] text-[var(--sd-pine)] border border-[var(--sd-border)]">
                                  {plan.incident_code}
                                </span>
                                <span
                                  className={`text-[10px] font-medium uppercase tracking-wider px-2 py-0.5 rounded font-mono ${
                                    plan.incident_severity === "critical"
                                      ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                                      : plan.incident_severity === "high"
                                      ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                                      : "bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                                  }`}
                                >
                                  {plan.incident_severity}
                                </span>
                              </div>

                              {/* Prominent Live Pulsing Status Badge */}
                              <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium uppercase bg-[var(--sd-pine)]/15 text-[var(--sd-pine)] border border-[var(--sd-pine)]/30 shadow-xs">
                                <span className="relative flex h-1.5 w-1.5">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--sd-pine)] opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[var(--sd-pine)]"></span>
                                </span>
                                <span>{plan.status.replace("_", " ")}</span>
                              </div>
                            </div>

                            {/* Title */}
                            <h3 className="text-sm font-medium text-[var(--sd-text)] leading-snug line-clamp-2 mb-2 group-hover:text-[var(--sd-pine)] transition-colors">
                              {plan.incident_title}
                            </h3>

                            {/* Summary */}
                            <p className="text-[12px] text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed mb-4">
                              {plan.summary}
                            </p>

                            {/* In-Flight Task Progress Bar */}
                            <div className="bg-[var(--sd-bg-alt)]/60 rounded-xl p-2.5 border border-[var(--sd-border)] mb-4">
                              <div className="flex items-center justify-between text-[11px] mb-1.5">
                                <span className="font-mono text-[var(--sd-text-muted)] flex items-center gap-1">
                                  <Layers className="h-3 w-3 text-[var(--sd-pine)]" />
                                  Execution Progress
                                </span>
                                <span className="font-mono font-medium text-[var(--sd-pine)]">
                                  {completedCount} / {plan.task_count} Tasks ({percent}%)
                                </span>
                              </div>
                              <div className="w-full h-1.5 rounded-full bg-[var(--sd-bg)] overflow-hidden border border-[var(--sd-border)]">
                                <div
                                  className="h-full bg-gradient-to-r from-[var(--sd-pine)] to-emerald-400 rounded-full transition-all duration-500"
                                  style={{ width: `${Math.max(8, percent)}%` }}
                                />
                              </div>
                            </div>
                          </div>

                          {/* Footer with Operational Action */}
                          <div className="border-t border-[var(--sd-border)] pt-3.5 flex items-center justify-between text-[12px]">
                            <span className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                              v{plan.version} • {formatRelativeTime(plan.created_at)}
                            </span>

                            <Link
                              href={`/dashboard/plans/${plan.id}`}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-medium text-[12px] shadow-xs hover:brightness-110 transition-all"
                            >
                              <span>Continue Remediation</span>
                              <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
                            </Link>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            )}

            {/* ════ SECTION 2: RESOLVED & ARCHIVED RUNBOOKS ════ */}
            {(statusTab === "all" || statusTab === "completed") && (
              <section className="flex flex-col gap-4">
                {/* Section Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-[var(--sd-border)] gap-2">
                  <div className="flex items-center gap-3">
                    <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                      <CheckCheck className="h-4 w-4 text-emerald-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-sm font-semibold tracking-wide uppercase font-mono text-[var(--sd-text-muted)]">
                          Resolved & Archived Runbooks
                        </h2>
                        <span className="px-2 py-0.2 rounded-full text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400/90 border border-emerald-500/20">
                          {completedPlans.length} closed
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--sd-text-muted)]">
                        Historical containment sequences with verified mitigation evidence, Merkle audit trails, and closed runbooks.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Completed Cards Grid */}
                {completedPlans.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-[var(--sd-border)] p-8 text-center bg-[var(--sd-surface)]/50">
                    <History className="h-8 w-8 text-[var(--sd-text-muted)] mx-auto mb-2 opacity-60" />
                    <p className="text-[13px] font-medium text-[var(--sd-text-muted)]">
                      No archived mitigation plans match your filter
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    {completedPlans.map((plan) => (
                      <div
                        key={plan.id}
                        className="rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)]/85 p-5 flex flex-col justify-between hover:border-[var(--sd-border-focus)] hover:bg-[var(--sd-surface)] transition-all group relative shadow-xs opacity-90 hover:opacity-100"
                      >
                        {/* Top Muted Border */}
                        <div className="absolute top-0 left-0 right-0 h-0.5 bg-emerald-500/40" />

                        <div>
                          {/* Card Header: Code, Severity, and Resolved Badge */}
                          <div className="flex items-center justify-between gap-2 mb-2.5 pt-0.5">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[12px] font-medium px-2 py-0.5 rounded bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]">
                                {plan.incident_code}
                              </span>
                              <span
                                className={`text-[10px] font-medium uppercase tracking-wider px-2 py-0.5 rounded font-mono ${
                                  plan.incident_severity === "critical"
                                    ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                                    : plan.incident_severity === "high"
                                    ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                                    : "bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                                }`}
                              >
                                {plan.incident_severity}
                              </span>
                            </div>

                            {/* Verified Resolved Status Pill */}
                            <div className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-medium uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                              <span>Resolved</span>
                            </div>
                          </div>

                          {/* Title */}
                          <h3 className="text-sm font-medium text-[var(--sd-text)] leading-snug line-clamp-2 mb-2 group-hover:text-[var(--sd-pine)] transition-colors">
                            {plan.incident_title}
                          </h3>

                          {/* Summary */}
                          <p className="text-[12px] text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed mb-4">
                            {plan.summary}
                          </p>

                          {/* Resolution & Verification Metadata */}
                          <div className="bg-[var(--sd-bg-alt)]/40 rounded-xl p-2.5 border border-[var(--sd-border)] mb-4 flex items-center justify-between text-[11px]">
                            <span className="font-mono text-[var(--sd-text-muted)] flex items-center gap-1.5">
                              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                              100% Remediated
                            </span>
                            <span className="font-mono text-emerald-400/90 font-medium">
                              {plan.task_count} / {plan.task_count} Tasks Verified
                            </span>
                          </div>
                        </div>

                        {/* Footer with Audit Log Action */}
                        <div className="border-t border-[var(--sd-border)] pt-3.5 flex items-center justify-between text-[12px]">
                          <span className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                            Archived • {formatRelativeTime(plan.created_at)}
                          </span>

                          <Link
                            href={`/dashboard/plans/${plan.id}`}
                            className="inline-flex items-center gap-1 font-medium text-[12px] text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] transition-colors"
                          >
                            <span>View Audit Log</span>
                            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}
          </div>
        )}
      </main>
    </div>
  );
}


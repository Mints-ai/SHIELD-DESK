"use client";

import React, { useState, useEffect } from "react";
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
  created_at: string;
}

export default function PlansIndexPage() {
  const { activeUserId, openChatWithPrompt } = useChat();
  const [isSampleData, setIsSampleData] = useState(false);
  const [plans, setPlans] = useState<PlanSummary[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("all");
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

  const filteredPlans = plans.filter((p) => {
    const matchesSearch =
      p.incident_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.incident_title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.summary.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity =
      selectedSeverity === "all" || p.incident_severity === selectedSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)]">
      <TopNavBar />
      {/* Main Content Area */}
      <main className="sd-dashboard-content min-w-0 max-w-7xl mx-auto px-6 py-6 flex flex-col gap-5">
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
              <h1 className="text-[var(--sd-text)] tracking-tight leading-none text-3xl font-light leading-tight">
                Mitigation plans
              </h1>
            </div>
          </div>
          <button
            onClick={() => openChatWithPrompt("Generate a mitigation plan for INC-1042")}
            className="sd-button sd-button-primary inline-flex items-center gap-2 px-4 py-2 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium shadow-xs transition-colors cursor-pointer shrink-0"
          >
            <Plus className="h-4 w-4" />
            <span>Generate New Plan</span>
          </button>
        </div>


        {/* Search & Filters */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative flex-1 w-full max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--sd-text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by incident code, title, or action..."
              className="sd-input w-full pl-10 pr-4 py-2 rounded-xl border border-[var(--sd-border)] sd-surface text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)] shadow-xs"
            />
          </div>

          <div className="flex max-w-full flex-wrap items-center gap-2 self-start sm:self-auto">
            <span className="text-[13px] font-medium text-[var(--sd-text-muted)] flex items-center gap-1">
              <Filter className="h-3.5 w-3.5" /> Severity:
            </span>
            {["all", "critical", "high", "medium"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                aria-pressed={selectedSeverity === sev}
                className={`px-3 py-1.5 rounded-lg text-[13px] font-medium transition-colors cursor-pointer capitalize ${
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

        {/* Plan Cards Grid */}
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
              Try adjusting your search criteria or ask the autonomous co-pilot
              to generate a new plan.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredPlans.map((plan) => (
              <div
                key={plan.id}
                className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 flex flex-col justify-between hover:shadow-md hover:border-[var(--sd-pine)]/40 transition-all group shadow-xs"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-mono text-[13px] font-medium px-2 py-0.5 rounded bg-[var(--sd-bg-alt)] text-[var(--sd-pine)] border border-[var(--sd-border)]">
                      {plan.incident_code}
                    </span>
                    <span
                      className={`text-[11px] font-medium uppercase tracking-wider px-2 py-0.5 rounded font-mono ${
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

                  <h3 className="text-sm font-medium text-[var(--sd-pine)] leading-snug line-clamp-2 mb-2 group-hover:text-[var(--sd-pine-dark)]">
                    {plan.incident_title}
                  </h3>

                  <p className="text-[13px] text-[var(--sd-text-muted)] line-clamp-3 leading-relaxed mb-4">
                    {plan.summary}
                  </p>
                </div>

                <div className="border-t border-[var(--sd-border)] pt-3.5 flex items-center justify-between text-[13px]">
                  <div className="flex items-center gap-2 text-[var(--sd-text-muted)]">
                    <span className="font-mono text-[11px] font-medium text-[var(--sd-pine)]">
                      {plan.task_count} Tasks
                    </span>
                    <span>•</span>
                    <span className="capitalize font-medium text-[11px]">
                      {plan.status.replace("_", " ")}
                    </span>
                  </div>

                  <Link
                    href={`/dashboard/plans/${plan.id}`}
                    className="inline-flex items-center gap-1 font-medium text-[13px] text-[var(--sd-pine)] hover:underline"
                  >
                    <span>View Plan</span>
                    <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

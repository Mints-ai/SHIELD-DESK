"use client";

import React, { useState, useEffect } from "react";
import {
  CheckSquare,
  Lock,
  Plus,
  Filter,
  ArrowRight,
  ShieldCheck,
  Clock,
  Layers,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import { AutonomyTierBadge } from "@/components/governance/AutonomyTierBadge";
import { ApprovalModal } from "@/components/governance/ApprovalModal";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";

interface MitigationTaskItem {
  id: string;
  plan_id: string;
  horizon: "immediate" | "short_term" | "long_term";
  title: string;
  description: string;
  tier: string;
  status: "pending" | "approved" | "rejected" | "in_progress" | "completed";
  blast_radius?: string;
  cve_id?: string | null;
  incident_code?: string;
}

const SEED_TASKS: MitigationTaskItem[] = [
  {
    id: "t1111111-1111-1111-1111-111111111111",
    plan_id: "p1111111-1111-1111-1111-111111111111",
    horizon: "immediate",
    title: "Isolate affected host FIN-WS-042",
    description: "Quarantine endpoint network interface to halt lateral movement toward database server",
    tier: "Tier 2",
    status: "pending",
    blast_radius: "Workstation FIN-WS-042 (Finance Subnet)",
    incident_code: "INC-1042",
  },
  {
    id: "t2222222-2222-2222-2222-222222222222",
    plan_id: "p1111111-1111-1111-1111-111111111111",
    horizon: "immediate",
    title: "Revoke exposed user and administrative credentials",
    description: "Terminate active session tokens for compromised user accounts",
    tier: "Tier 1",
    status: "completed",
    blast_radius: "User Sessions",
    incident_code: "INC-1042",
  },
  {
    id: "t3333333-3333-3333-3333-333333333333",
    plan_id: "p1111111-1111-1111-1111-111111111111",
    horizon: "short_term",
    title: "Deploy vendor patch for CVE-2020-6240",
    description: "Apply SAP Security Notes to resolve NetWeaver DoS vulnerability",
    tier: "Tier 2",
    status: "approved",
    blast_radius: "Finance Subnet Application Servers",
    cve_id: "CVE-2020-6240",
    incident_code: "INC-1042",
  },
  {
    id: "t4444444-4444-4444-4444-444444444444",
    plan_id: "p1111111-1111-1111-1111-111111111111",
    horizon: "long_term",
    title: "Implement zero-trust microsegmentation",
    description: "Enforce strict firewall ACLs between general workstations and financial database tier",
    tier: "Tier 2",
    status: "pending",
    blast_radius: "Entire Finance Zone",
    incident_code: "INC-1042",
  },
  {
    id: "t5555555-5555-5555-5555-555555555555",
    plan_id: "p1111111-1111-1111-1111-111111111111",
    horizon: "immediate",
    title: "Block outbound egress to suspicious domain",
    description: "Add DNS filter entry for newly registered domain detected in INC-1031",
    tier: "Tier 1",
    status: "completed",
    blast_radius: "Perimeter Gateway",
    incident_code: "INC-1031",
  },
];

export default function SOCTaskBoardPage() {
  const { activeUserId, activeUser } = useChat();
  const [tasks, setTasks] = useState<MitigationTaskItem[]>([]);
  const [filterHorizon, setFilterHorizon] = useState<string>("all");
  const [activeModalToken, setActiveModalToken] = useState<ApprovalTokenRecord | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isCreatingTask, setIsCreatingTask] = useState(false);
  const [newTaskTitle, setNewTaskTitle] = useState("");
  const [newTaskTier, setNewTaskTier] = useState<"Tier 1" | "Tier 2" | "Tier 3">("Tier 2");

  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let isMounted = true;
    async function loadTasks() {
      setIsLoading(true);
      try {
        const res = await fetch("/api/tasks", {
          headers: { "X-ShieldDesk-User": activeUserId },
        });
        if (res.ok) {
          const data = await res.json();
          if (isMounted) {
            setTasks(data.tasks || []);
          }
        } else {
          if (isMounted) setTasks(activeUserId === "dev-other" ? [] : SEED_TASKS);
        }
      } catch {
        if (isMounted) setTasks(activeUserId === "dev-other" ? [] : SEED_TASKS);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    loadTasks();
    return () => {
      isMounted = false;
    };
  }, [activeUserId]);

  const handleOpenApproval = async (task: MitigationTaskItem) => {
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
            blastRadius: task.blast_radius || "Host Scope",
          }),
        });
        const createBody = await createRes.json();
        token = createBody.token;
      }

      if (token) {
        setActiveModalToken(token);
        setIsModalOpen(true);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDecisionSuccess = (updatedToken: ApprovalTokenRecord) => {
    const taskStatus: MitigationTaskItem["status"] =
      updatedToken.status === "approved"
        ? "approved"
        : updatedToken.status === "rejected"
          ? "rejected"
          : "pending";

    setTasks((prev) =>
      prev.map((t) => (t.id === updatedToken.task_id ? { ...t, status: taskStatus } : t))
    );
  };

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTaskTitle.trim() || isSubmitting) return;

    setIsSubmitting(true);
    try {
      const res = await fetch("/api/tasks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          title: newTaskTitle.trim(),
          description: "Analyst-initiated custom mitigation task",
          tier: newTaskTier,
          horizon: "immediate",
          blastRadius: "Target Workstation Scope",
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.task) {
          setTasks((prev) => [data.task, ...prev]);
        }
      } else {
        const errBody = await res.json().catch(() => null);
        console.error("Task creation failed:", errBody?.error || "Server rejected task creation");
      }
    } catch (err) {
      console.error("Network error during task creation:", err);
    } finally {
      setIsSubmitting(false);
      setNewTaskTitle("");
      setIsCreatingTask(false);
    }
  };

  const filteredTasks = tasks.filter((t) => {
    if (filterHorizon !== "all" && t.horizon !== filterHorizon) return false;
    return true;
  });

  const columns = [
    {
      id: "pending",
      label: "Pending Authorization",
      headerBadge: "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]",
      items: filteredTasks.filter((t) => t.status === "pending"),
    },
    {
      id: "approved",
      label: "Authorized & Queued",
      headerBadge: "bg-[var(--sd-bg-alt)] text-[var(--sd-pine)] border-[var(--sd-border)]",
      items: filteredTasks.filter((t) => t.status === "approved"),
    },
    {
      id: "in_progress",
      label: "In Progress",
      headerBadge: "bg-[var(--sd-bg)] text-[var(--sd-text)] border-[var(--sd-border)]",
      items: filteredTasks.filter((t) => t.status === "in_progress"),
    },
    {
      id: "completed",
      label: "Completed & Audited",
      headerBadge: "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]",
      items: filteredTasks.filter((t) => t.status === "completed"),
    },
  ];

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-6">
        {/* Header & Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs">
                <CheckSquare className="h-4.5 w-4.5" />
              </div>
              <h1 className="text-xl font-bold tracking-tight text-[var(--sd-pine)]">SOC Task Board</h1>
              <span className="rounded-md bg-white border border-[var(--sd-border)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--sd-pine)] font-mono shadow-xs">
                Tenant: {activeUser.tenantName}
              </span>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              Multi-Tenant Remediation Task Board with Tier-Gated Approvals
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Horizon Filter */}
            <div className="flex items-center gap-1 bg-white border border-[var(--sd-border)] rounded-xl p-1 text-xs shadow-xs">
              <span className="text-[10px] uppercase font-semibold text-[var(--sd-text-muted)] px-2 flex items-center gap-1 font-mono">
                <Filter className="h-3 w-3 text-[var(--sd-pine)]" /> Horizon:
              </span>
              {["all", "immediate", "short_term", "long_term"].map((h) => (
                <button
                  key={h}
                  onClick={() => setFilterHorizon(h)}
                  className={cn(
                    "px-2.5 py-1 rounded-lg text-xs capitalize transition cursor-pointer font-medium",
                    filterHorizon === h
                      ? "bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)]"
                  )}
                >
                  {h.replace("_", " ")}
                </button>
              ))}
            </div>

            {/* Quick Add Task */}
            <button
              onClick={() => setIsCreatingTask(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[#f7f4ed] text-xs font-semibold transition cursor-pointer shadow-xs"
            >
              <Plus className="h-3.5 w-3.5 text-[#e6dbbf]" />
              <span>Add Custom Task</span>
            </button>
          </div>
        </div>

        {/* Add Custom Task Modal */}
        {isCreatingTask && (
          <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
              className="absolute inset-0 bg-black/40 backdrop-blur-sm"
              onClick={() => { setIsCreatingTask(false); setNewTaskTitle(""); }}
            />
            {/* Modal Panel */}
            <div className="relative z-10 w-full max-w-lg mx-4 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xl">
              {/* Modal Header */}
              <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)]">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--sd-pine)] text-[#f7f4ed]">
                    <Plus className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-[var(--sd-pine)]">Draft New Remediation Task</h3>
                    <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-0.5">New task will land in <span className="font-semibold text-[var(--sd-pine)]">Pending Authorization</span></p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => { setIsCreatingTask(false); setNewTaskTitle(""); }}
                  className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--sd-text-muted)] hover:bg-[var(--sd-bg-alt)] hover:text-[var(--sd-pine)] transition cursor-pointer text-lg leading-none"
                  aria-label="Close modal"
                >
                  ×
                </button>
              </div>

              {/* Modal Body */}
              <form onSubmit={handleCreateTask} className="p-5 space-y-4">
                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                    Task Title <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g., Flush ARP table on Gateway router"
                    value={newTaskTitle}
                    onChange={(e) => setNewTaskTitle(e.target.value)}
                    className="w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2.5 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] focus:ring-1 focus:ring-[var(--sd-pine)]/20 transition"
                    autoFocus
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
                    Autonomy Tier
                  </label>
                  <select
                    value={newTaskTier}
                    onChange={(e) => setNewTaskTier(e.target.value as "Tier 1" | "Tier 2" | "Tier 3")}
                    className="w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3 py-2.5 text-xs text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] focus:ring-1 focus:ring-[var(--sd-pine)]/20 transition"
                  >
                    <option value="Tier 1">Tier 1 — Automatic Action</option>
                    <option value="Tier 2">Tier 2 — Human Sign-off Required</option>
                    <option value="Tier 3">Tier 3 — Dual Sign-off Required</option>
                  </select>
                  <p className="text-[10.5px] text-[var(--sd-text-muted)]">
                    {newTaskTier === "Tier 1" && "Agent executes autonomously with no human gate."}
                    {newTaskTier === "Tier 2" && "Requires one authorised analyst to sign off before execution."}
                    {newTaskTier === "Tier 3" && "Requires two independent approvals — high blast-radius actions only."}
                  </p>
                </div>

                {/* Modal Footer Actions */}
                <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-[var(--sd-border)]">
                  <button
                    type="button"
                    onClick={() => { setIsCreatingTask(false); setNewTaskTitle(""); }}
                    className="px-4 py-2 rounded-xl border border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] hover:border-[var(--sd-pine)]/40 transition cursor-pointer font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting || !newTaskTitle.trim()}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] disabled:opacity-50 disabled:cursor-not-allowed text-[#f7f4ed] text-xs font-semibold transition cursor-pointer shadow-xs"
                  >
                    {isSubmitting ? (
                      <>
                        <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                        </svg>
                        <span>Creating…</span>
                      </>
                    ) : (
                      <>
                        <Plus className="h-3.5 w-3.5" />
                        <span>Create Task</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* 4-Column Board */}
        <div className="w-full overflow-x-auto pb-2">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 min-w-[720px] lg:min-w-0">
            {columns.map((col) => (
              <div
                key={col.id}
                className="rounded-2xl border border-[var(--sd-border)] bg-white flex flex-col h-[600px] lg:h-[calc(100vh-230px)] min-h-[480px] max-h-[850px] overflow-hidden shadow-xs"
              >
                {/* Column Header */}
                <div className="p-3.5 border-b border-[var(--sd-border)] flex items-center justify-between bg-[var(--sd-bg-alt)]/50 shrink-0">
                  <span className="text-xs font-bold text-[var(--sd-pine)]">{col.label}</span>
                  <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border", col.headerBadge)}>
                    {col.items.length}
                  </span>
                </div>

                {/* Tasks List */}
                <div className="p-3 space-y-3 flex-1 min-h-0 overflow-y-auto bg-white">
                {col.items.length === 0 ? (
                  <div className="py-12 text-center text-xs text-[var(--sd-text-muted)] border border-dashed border-[var(--sd-border)] rounded-xl my-2 bg-[var(--sd-panel-raised)]">
                    No tasks in this lane
                  </div>
                ) : (
                  col.items.map((task) => (
                    <div
                      key={task.id}
                      className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:border-[var(--sd-border-strong)] transition-all shadow-xs space-y-2.5 text-xs group"
                    >
                      <div className="flex items-center justify-between">
                        <AutonomyTierBadge tier={task.tier} size="sm" showLabel={false} />
                        <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-pine)] font-semibold">
                          {task.horizon.replace("_", " ")}
                        </span>
                      </div>

                      <h4 className="font-semibold text-xs text-[var(--sd-text)] leading-snug group-hover:text-[var(--sd-pine)] transition-colors">
                        {task.title}
                      </h4>

                      <p className="text-[11px] text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed">
                        {task.description}
                      </p>

                      <div className="pt-2 border-t border-[var(--sd-border)] flex items-center justify-between text-[10.5px]">
                        <span className="text-[var(--sd-text-muted)] font-mono truncate max-w-[130px]">
                          {task.blast_radius}
                        </span>

                        {task.status === "pending" && (
                          <button
                            onClick={() => handleOpenApproval(task)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] hover:bg-[var(--sd-warning-border)] text-[11px] font-bold cursor-pointer transition shadow-xs"
                          >
                            <Lock className="h-3 w-3" />
                            <span>Sign Off</span>
                          </button>
                        )}

                        {task.status === "approved" && (
                          <span className="flex items-center gap-1 text-[var(--sd-pine)] font-semibold text-[11px]">
                            <ShieldCheck className="h-3.5 w-3.5" />
                            <span>Approved</span>
                          </span>
                        )}

                        {task.status === "completed" && (
                          <span className="flex items-center gap-1 text-[var(--sd-success)] font-semibold text-[11px]">
                            <ShieldCheck className="h-3.5 w-3.5" />
                            <span>Executed</span>
                          </span>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ))}
          </div>
        </div>
      </main>

      {/* Global Approval Modal */}
      <ApprovalModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        token={activeModalToken}
        onDecisionSuccess={handleDecisionSuccess}
      />
    </div>
  );
}

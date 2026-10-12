"use client";

import React, { useState, useEffect, useId, useCallback } from "react";
import Link from "next/link";
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
  Play,
  RefreshCw,
  Terminal,
  Search,
  Trash2,
  ExternalLink,
  AlertCircle,
  CheckCircle2,
  Server,
  ShieldAlert,
  UserCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import { AutonomyTierBadge } from "@/components/governance/AutonomyTierBadge";
import { ApprovalModal } from "@/components/governance/ApprovalModal";
import { GlassDialog } from "@/components/ui/GlassDialog";
import type { ApprovalTokenRecord } from "@/lib/governance/approvalTokens";
import { DEV_USERS, type DevUserId } from "@/lib/constants/devUsers";

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
  assigned_to?: string | null;
  incident_code?: string;
  created_at?: string;
}

interface TaskDetailData {
  task: MitigationTaskItem & {
    incident_title?: string;
    incident_severity?: string;
    plan_version?: number;
    plan_status?: string;
  };
  approvalTokens?: ApprovalTokenRecord[];
  commandLogs?: Array<{
    id: string;
    command: string;
    status: string;
    output: string;
    executed_at: string;
  }>;
}

export default function SOCTaskBoardPage() {
  const taskDialogId = useId();
  const detailDialogId = useId();
  const { activeUserId, activeUser } = useChat();

  const canEditTask = activeUser.role !== "analyst";
  const canAssignTask = activeUser.role !== "analyst";
  const canDispatch = activeUser.role === "system_admin" || activeUser.role === "super_admin" || activeUser.role === "responder";
  // Responders can approve Tier 1 & Tier 2; Admins can approve all tiers; Analysts cannot approve any tier
  const canUserSignOffTask = (taskTier?: string) => {
    if (activeUser.role === "system_admin" || activeUser.role === "super_admin") {
      return true;
    }
    if (activeUser.role === "responder") {
      return taskTier === "Tier 1" || taskTier === "Tier 2";
    }
    return false;
  };

  const [isSampleData, setIsSampleData] = useState(false);
  const [tasks, setTasks] = useState<MitigationTaskItem[]>([]);
  const [filterHorizon, setFilterHorizon] = useState<string>("all");
  const [filterTier, setFilterTier] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const [activeModalToken, setActiveModalToken] = useState<ApprovalTokenRecord | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const [isCreatingTask, setIsCreatingTask] = useState(false);
  const [newTaskTitle, setNewTaskTitle] = useState("");
  const [newTaskTier, setNewTaskTier] = useState<"Tier 1" | "Tier 2" | "Tier 3">("Tier 2");
  const [newTaskPlanId, setNewTaskPlanId] = useState("");
  const [newTaskAssignedTo, setNewTaskAssignedTo] = useState<string>("dev-responder");
  const [availablePlans, setAvailablePlans] = useState<
    Array<{
      id: string;
      incident_code: string;
      incident_title: string;
      version: number;
    }>
  >([]);

  // Execution & detail state
  const [executingTaskId, setExecutingTaskId] = useState<string | null>(null);
  const [executionNotice, setExecutionNotice] = useState<{
    taskId: string;
    message: string;
    isError?: boolean;
  } | null>(null);

  const [selectedTask, setSelectedTask] = useState<MitigationTaskItem | null>(null);
  const [detailData, setDetailData] = useState<TaskDetailData | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);

  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const loadTasks = useCallback(async () => {
    try {
      const [resTasks, resPlans] = await Promise.all([
        fetch("/api/tasks", { headers: { "X-ShieldDesk-User": activeUserId } }),
        fetch("/api/plans", { headers: { "X-ShieldDesk-User": activeUserId } }),
      ]);
      if (resTasks.ok) {
        const data = await resTasks.json();
        setTasks(data.tasks || []);
        setIsSampleData(data._source === "demo_fallback");
      }
      if (resPlans.ok) {
        const plansData = await resPlans.json();
        setAvailablePlans(plansData.plans || []);
      }
    } catch {
      // fallback
    } finally {
      setIsLoading(false);
    }
  }, [activeUserId]);

  useEffect(() => {
    setIsLoading(true);
    loadTasks();
  }, [loadTasks]);

  useEffect(() => {
    const handleApprovalsChanged = (event: Event) => {
      const customEvent = event as CustomEvent<{ action?: string; token?: ApprovalTokenRecord }>;
      if (customEvent.detail?.token) {
        const updatedToken = customEvent.detail.token;
        const taskStatus: MitigationTaskItem["status"] =
          updatedToken.status === "approved"
            ? "approved"
            : updatedToken.status === "rejected"
              ? "rejected"
              : "pending";

        setTasks((prev) =>
          prev.map((t) => (t.id === updatedToken.task_id ? { ...t, status: taskStatus } : t))
        );
      }
      loadTasks();
    };

    window.addEventListener("shielddesk:approvals-changed", handleApprovalsChanged);
    const interval = setInterval(() => {
      loadTasks();
    }, 4000);

    return () => {
      window.removeEventListener("shielddesk:approvals-changed", handleApprovalsChanged);
      clearInterval(interval);
    };
  }, [loadTasks]);

  // Load Task Detail Drawer
  const openTaskDetail = async (task: MitigationTaskItem) => {
    setSelectedTask(task);
    setIsLoadingDetail(true);
    setDetailData(null);
    try {
      const res = await fetch(`/api/tasks/${encodeURIComponent(task.id)}`, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        const data = await res.json();
        setDetailData(data);
      }
    } catch (err) {
      console.error("Failed to load task details:", err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const handleOpenApproval = async (task: MitigationTaskItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    try {
      const res = await fetch(`/api/approvals?taskId=${encodeURIComponent(task.id)}&status=pending`, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const body = await res.json();
      let token: ApprovalTokenRecord | null = null;
      if (body.tokens && body.tokens.length > 0) {
        token = body.tokens.find((t: ApprovalTokenRecord) => t.status === "pending") || null;
      }
      
      if (!token) {
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
            tier: task.tier,
          }),
        });
        const createBody = await createRes.json();
        token = createBody.token;
      }

      if (token) {
        const syncedToken: ApprovalTokenRecord = {
          ...token,
          tier: (task.tier as any) || token.tier,
        };
        setActiveModalToken(syncedToken);
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

    if (selectedTask?.id === updatedToken.task_id) {
      setSelectedTask((prev) => (prev ? { ...prev, status: taskStatus } : null));
    }

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("shielddesk:approvals-changed"));
    }
  };

  // Execution Handler with realistic execution progression
  const handleExecuteTask = async (task: MitigationTaskItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setExecutingTaskId(task.id);
    setExecutionNotice(null);

    // Optimistically shift to in_progress
    setTasks((prev) =>
      prev.map((t) => (t.id === task.id ? { ...t, status: "in_progress" } : t))
    );

    try {
      const [res] = await Promise.all([
        fetch(`/api/tasks/${encodeURIComponent(task.id)}/execute`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ShieldDesk-User": activeUserId,
          },
        }),
        // Maintain visible In-Progress phase for 2 seconds so analyst can observe active endpoint execution
        new Promise((resolve) => setTimeout(resolve, 2000)),
      ]);

      const body = await res.json();
      if (res.ok && body.success) {
        setTasks((prev) =>
          prev.map((t) => (t.id === task.id ? { ...t, status: "completed" } : t))
        );
        if (selectedTask?.id === task.id) {
          setSelectedTask((prev) => (prev ? { ...prev, status: "completed" } : null));
          openTaskDetail({ ...task, status: "completed" });
        }
        setExecutionNotice({
          taskId: task.id,
          message: `Executed on ${body.agent?.hostname || "Endpoint"}: ${body.output || "Execution verified & recorded in audit log."}`,
        });
        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("shielddesk:approvals-changed"));
        }
      } else {
        setExecutionNotice({
          taskId: task.id,
          message: body.error || "Execution failed",
          isError: true,
        });
        loadTasks();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network error during execution";
      setExecutionNotice({
        taskId: task.id,
        message: msg,
        isError: true,
      });
      loadTasks();
    } finally {
      setExecutingTaskId(null);
    }
  };

  // Plan Switcher Handler
  const handleUpdatePlan = async (taskId: string, newPlanId: string) => {
    try {
      const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ planId: newPlanId }),
      });
      if (res.ok) {
        if (selectedTask && selectedTask.id === taskId) {
          openTaskDetail({ ...selectedTask, plan_id: newPlanId });
        }
        loadTasks();
      }
    } catch (err) {
      console.error("Failed to update plan association:", err);
    }
  };

  // Autonomy Tier Switcher Handler
  const handleUpdateTier = async (taskId: string, newTier: string) => {
    try {
      const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ tier: newTier }),
      });
      if (res.ok) {
        setTasks((prev) =>
          prev.map((t) => (t.id === taskId ? { ...t, tier: newTier } : t))
        );
        if (selectedTask && selectedTask.id === taskId) {
          setSelectedTask((prev) => (prev ? { ...prev, tier: newTier } : null));
          openTaskDetail({ ...selectedTask, tier: newTier });
        }
        loadTasks();
      }
    } catch (err) {
      console.error("Failed to update task tier:", err);
    }
  };

  // Status override (Mark Complete / Revert)
  const handleUpdateStatus = async (
    task: MitigationTaskItem,
    newStatus: MitigationTaskItem["status"],
    e?: React.MouseEvent
  ) => {
    if (e) e.stopPropagation();
    try {
      const res = await fetch(`/api/tasks/${encodeURIComponent(task.id)}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        setTasks((prev) =>
          prev.map((t) => (t.id === task.id ? { ...t, status: newStatus } : t))
        );
        if (selectedTask?.id === task.id) {
          setSelectedTask((prev) => (prev ? { ...prev, status: newStatus } : null));
        }
      }
    } catch (err) {
      console.error("Failed to update status:", err);
    }
  };

  // Delete Task
  const handleDeleteTask = async (taskId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!confirm("Are you sure you want to delete this remediation task?")) return;
    try {
      const res = await fetch(`/api/tasks/${encodeURIComponent(taskId)}`, {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        setTasks((prev) => prev.filter((t) => t.id !== taskId));
        if (selectedTask?.id === taskId) {
          setSelectedTask(null);
        }
      }
    } catch (err) {
      console.error("Failed to delete task:", err);
    }
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
          planId: newTaskPlanId || undefined,
          assignedTo: newTaskAssignedTo || undefined,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.task) {
          setTasks((prev) => [data.task, ...prev]);
          if (typeof window !== "undefined") {
            window.dispatchEvent(new CustomEvent("shielddesk:approvals-changed"));
          }
        }
      }
    } catch (err) {
      console.error("Network error during task creation:", err);
    } finally {
      setIsSubmitting(false);
      setNewTaskTitle("");
      setIsCreatingTask(false);
    }
  };

  // Filtering
  const filteredTasks = tasks.filter((t) => {
    if (filterHorizon !== "all" && t.horizon !== filterHorizon) return false;
    if (filterTier !== "all" && t.tier !== filterTier) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = t.title.toLowerCase().includes(q);
      const matchDesc = (t.description || "").toLowerCase().includes(q);
      const matchRadius = (t.blast_radius || "").toLowerCase().includes(q);
      const matchCve = (t.cve_id || "").toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchRadius && !matchCve) return false;
    }
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
      headerBadge: "bg-[var(--sd-pine-dim)] text-[var(--sd-pine)] border-[var(--sd-border)]",
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
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-6">
        {isSampleData && <p className="sd-sample-label w-fit">Sample tasks · Local fallback data</p>}

        {/* Execution Banner Notice */}
        {executionNotice && (
          <div
            className={cn(
              "p-4 rounded-xl border flex items-center justify-between text-xs transition-all shadow-sm",
              executionNotice.isError
                ? "bg-[var(--sd-danger-dim)] border-[var(--sd-danger-border)] text-[var(--sd-danger)]"
                : "bg-[var(--sd-pine-dim)] border-[var(--sd-pine)] text-[var(--sd-pine)]"
            )}
          >
            <div className="flex items-center gap-2.5">
              {executionNotice.isError ? (
                <AlertCircle className="h-4 w-4 shrink-0" />
              ) : (
                <CheckCircle2 className="h-4 w-4 shrink-0" />
              )}
              <span className="font-medium font-mono">{executionNotice.message}</span>
            </div>
            <button
              onClick={() => setExecutionNotice(null)}
              className="px-2 py-0.5 text-xs opacity-75 hover:opacity-100 cursor-pointer"
            >
              ×
            </button>
          </div>
        )}

        {/* Header & Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl sd-surface border border-[var(--sd-border)] text-[var(--sd-wheat)] shadow-xs">
                <CheckSquare className="h-4.5 w-4.5" />
              </div>
              <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                Task board
              </h1>
              <span className="rounded-md sd-surface border border-[var(--sd-border)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--sd-pine)] font-mono shadow-xs">
                Tenant: {activeUser.tenantName}
              </span>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              Multi-Tenant Remediation Task Board with Closed-Loop Agent Dispatch
            </p>
          </div>

          <div className="flex min-w-0 max-w-full flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[var(--sd-text-muted)]" />
              <input
                type="text"
                placeholder="Search tasks, CVE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="sd-input pl-8 pr-3 py-1.5 text-xs rounded-xl w-44 md:w-56"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-2 text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                >
                  ×
                </button>
              )}
            </div>

            {/* Tier Filter */}
            <div className="sd-tabs">
              <select
                value={filterTier}
                onChange={(e) => setFilterTier(e.target.value)}
                className="bg-transparent text-[11px] text-[var(--sd-text)] outline-none cursor-pointer py-1 px-1 font-mono uppercase"
              >
                <option value="all" className="bg-[var(--sd-bg-alt)]">All Tiers</option>
                <option value="Tier 1" className="bg-[var(--sd-bg-alt)]">Tier 1</option>
                <option value="Tier 2" className="bg-[var(--sd-bg-alt)]">Tier 2</option>
                <option value="Tier 3" className="bg-[var(--sd-bg-alt)]">Tier 3</option>
              </select>
            </div>

            {/* Horizon Filter */}
            <div className="sd-tabs">
              <span className="shrink-0 text-[11px] uppercase font-medium text-[var(--sd-text-muted)] px-2 flex items-center gap-1 font-mono">
                <Filter className="h-3 w-3 text-[var(--sd-pine)]" /> Horizon:
              </span>
              {["all", "immediate", "short_term", "long_term"].map((h) => (
                <button
                  key={h}
                  onClick={() => setFilterHorizon(h)}
                  aria-pressed={filterHorizon === h}
                  className="capitalize"
                >
                  {h.replace("_", " ")}
                </button>
              ))}
            </div>

            {/* Quick Add Task */}
            {canAssignTask && (
              <button
                onClick={() => setIsCreatingTask(true)}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-gradient-to-r from-[#0E8563] to-[#0B6B50] hover:from-[#119E76] hover:to-[#0D7558] text-[#FFFFFF] border border-[#D8C49A]/30 text-[13px] font-bold shadow-[0_2px_12px_rgba(11,107,80,0.3)] transition cursor-pointer"
              >
                <Plus className="h-3.5 w-3.5 text-[#FFFFFF]" />
                <span>Add Custom Task</span>
              </button>
            )}
          </div>
        </div>

        {/* 4-Column Board */}
        <div className="w-full overflow-x-auto pb-2">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 min-w-[720px] lg:min-w-0">
            {columns.map((col) => (
              <div
                key={col.id}
                className="sd-surface rounded-2xl border border-[var(--sd-border)] flex flex-col h-[600px] lg:h-[calc(100vh-230px)] min-h-[480px] max-h-[850px] overflow-hidden"
              >
                {/* Column Header */}
                <div className="p-3.5 border-b border-[var(--sd-border)] flex items-center justify-between bg-[var(--sd-bg-alt)]/50 shrink-0">
                  <span className="text-xs font-bold text-[var(--sd-pine)]">{col.label}</span>
                  <span
                    className={cn(
                      "px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border",
                      col.headerBadge
                    )}
                  >
                    {col.items.length}
                  </span>
                </div>

                {/* Tasks List */}
                <div className="p-3 space-y-3 flex-1 min-h-0 overflow-y-auto">
                  {col.items.length === 0 ? (
                    <div className="py-12 text-center text-[13px] text-[var(--sd-text-muted)] border border-dashed border-[var(--sd-border)] rounded-xl my-2 bg-[var(--sd-panel-raised)]">
                      No tasks in this lane
                    </div>
                  ) : (
                    col.items.map((task) => (
                      <div
                        key={task.id}
                        onClick={() => openTaskDetail(task)}
                        className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:border-[var(--sd-border-strong)] transition-all shadow-xs space-y-2.5 text-[13px] group cursor-pointer relative"
                      >
                        <div className="flex items-center justify-between">
                          <AutonomyTierBadge tier={task.tier} size="sm" showLabel={false} />
                          <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-pine)] font-medium">
                            {task.horizon.replace("_", " ")}
                          </span>
                        </div>

                        <h4 className="font-medium text-[13px] text-[var(--sd-text)] leading-snug group-hover:text-[var(--sd-pine)] transition-colors">
                          {task.title}
                        </h4>

                        <p className="text-[11px] text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed">
                          {task.description}
                        </p>

                        {task.assigned_to && (
                          <div className="flex items-center gap-1.5 text-[10.5px] font-mono text-[var(--sd-wheat)]/85 bg-[#D8C49A]/10 border border-[#D8C49A]/20 rounded-md px-2 py-0.5 w-fit">
                            <UserCheck className="h-3 w-3 text-[var(--sd-wheat)]" />
                            <span>Assigned: {DEV_USERS[task.assigned_to as DevUserId]?.label || task.assigned_to.replace("dev-", "")}</span>
                          </div>
                        )}

                        <div className="pt-2 border-t border-[var(--sd-border)] flex items-center justify-between text-[11px]">
                          <span className="text-[var(--sd-text-muted)] font-mono truncate max-w-[110px]">
                            {task.blast_radius || "Host Scope"}
                          </span>

                          {/* Column-Specific Action Controls */}
                          {task.status === "pending" && (
                            canUserSignOffTask(task.tier) ? (
                              <button
                                onClick={(e) => handleOpenApproval(task, e)}
                                className="flex items-center gap-1 px-3 py-1 rounded-full border border-[#D8C49A]/50 bg-[#D8C49A]/15 text-[#F2EFE9] hover:bg-[#D8C49A]/25 text-[11px] font-medium cursor-pointer transition shadow-xs"
                              >
                                <Lock className="h-3 w-3 text-[#D8C49A]" />
                                <span>Sign Off</span>
                              </button>
                            ) : (
                              <span className="text-[11px] font-mono text-[var(--sd-text-dim)] italic">
                                {activeUser.role === "responder" && (task.tier === "Tier 2" || task.tier === "Tier 3")
                                  ? "Requires Admin Sign-off"
                                  : "Awaiting Sign-off"}
                              </span>
                            )
                          )}

                          {task.status === "approved" && (
                            canDispatch ? (
                              <button
                                onClick={(e) => handleExecuteTask(task, e)}
                                disabled={executingTaskId === task.id}
                                className="flex items-center gap-1.5 px-3.5 py-1 rounded-full bg-gradient-to-r from-[#0E8563] to-[#0B6B50] hover:from-[#119E76] hover:to-[#0D7558] text-[#FFFFFF] border border-[#D8C49A]/30 text-[11px] font-bold shadow-[0_2px_10px_rgba(11,107,80,0.35)] transition cursor-pointer disabled:opacity-50"
                              >
                                {executingTaskId === task.id ? (
                                  <>
                                    <RefreshCw className="h-3 w-3 animate-spin text-[#FFFFFF]" />
                                    <span>Dispatching…</span>
                                  </>
                                ) : (
                                  <>
                                    <Play className="h-3 w-3 fill-current" />
                                    <span>Dispatch</span>
                                  </>
                                )}
                              </button>
                            ) : (
                              <span className="text-[11px] font-mono text-[var(--sd-text-dim)] italic">
                                Authorized · Awaiting Dispatch
                              </span>
                            )
                          )}

                          {task.status === "in_progress" && (
                            <div className="flex items-center gap-2">
                              <span className="flex items-center gap-1 text-[var(--sd-warning)] font-mono text-[10.5px]">
                                <RefreshCw className="h-3 w-3 animate-spin text-[var(--sd-warning)]" />
                                <span>Executing</span>
                              </span>
                              <button
                                onClick={(e) => handleUpdateStatus(task, "completed", e)}
                                className="px-2.5 py-0.5 rounded-lg border border-[#D8C49A]/50 bg-[#D8C49A]/10 text-[#D8C49A] hover:bg-[#D8C49A]/20 text-[10.5px] font-medium transition cursor-pointer"
                              >
                                Done
                              </button>
                            </div>
                          )}

                          {task.status === "completed" && (
                            <span className="flex items-center gap-1 text-[var(--sd-success)] font-medium text-[11px]">
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

      {/* Draft New Remediation Task Modal */}
      {isCreatingTask && (
        <GlassDialog
          open={isCreatingTask}
          onClose={() => {
            setIsCreatingTask(false);
            setNewTaskTitle("");
          }}
          labelledBy={taskDialogId}
          closeOnBackdrop
          className="max-w-lg"
        >
          <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)]">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--sd-pine-dim)] text-[var(--sd-wheat)] border border-[var(--sd-border)]">
                <Plus className="h-4 w-4" />
              </div>
              <div>
                <h3 id={taskDialogId} className="text-base font-medium text-[var(--sd-text)]">
                  Draft New Remediation Task
                </h3>
                <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-0.5">
                  New task will land in{" "}
                  <span className="font-semibold text-[var(--sd-pine)]">Pending Authorization</span>
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => {
                setIsCreatingTask(false);
                setNewTaskTitle("");
              }}
              className="sd-button flex h-9 w-9 items-center justify-center p-0 text-[var(--sd-text-muted)] transition cursor-pointer text-lg leading-none"
              aria-label="Close modal"
            >
              ×
            </button>
          </div>

          <form onSubmit={handleCreateTask} className="p-5 space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor={`${taskDialogId}-title`}
                className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono"
              >
                Task Title <span className="text-[var(--sd-danger)]">*</span>
              </label>
              <input
                id={`${taskDialogId}-title`}
                type="text"
                placeholder="e.g., Flush ARP table on Gateway router"
                value={newTaskTitle}
                onChange={(e) => setNewTaskTitle(e.target.value)}
                className="sd-input w-full rounded-xl px-3.5 py-2.5 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] transition"
                autoFocus
                data-autofocus
                required
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor={`${taskDialogId}-tier`}
                className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono"
              >
                Autonomy Tier
              </label>
              <select
                id={`${taskDialogId}-tier`}
                value={newTaskTier}
                onChange={(e) => setNewTaskTier(e.target.value as "Tier 1" | "Tier 2" | "Tier 3")}
                className="sd-input w-full rounded-xl px-3 py-2.5 text-[13px] text-[var(--sd-text)] transition"
              >
                <option value="Tier 1">Tier 1 — Automatic Action</option>
                <option value="Tier 2">Tier 2 — Human Sign-off Required</option>
                <option value="Tier 3">Tier 3 — Dual Sign-off Required</option>
              </select>
              <p className="text-[10.5px] text-[var(--sd-text-muted)]">
                {newTaskTier === "Tier 1" && "Agent executes autonomously with no human gate."}
                {newTaskTier === "Tier 2" &&
                  "Requires one authorised analyst to sign off before execution."}
                {newTaskTier === "Tier 3" &&
                  "Requires two independent approvals — high blast-radius actions only."}
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor={`${taskDialogId}-assignee`}
                className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono"
              >
                Assign Task To
              </label>
              <select
                id={`${taskDialogId}-assignee`}
                value={newTaskAssignedTo}
                onChange={(e) => setNewTaskAssignedTo(e.target.value)}
                className="sd-input w-full rounded-xl px-3 py-2.5 text-[13px] text-[var(--sd-text)] transition"
              >
                <option value="dev-responder">Responder (dev-responder)</option>
                <option value="dev-admin">System Admin (dev-admin)</option>
                <option value="dev-super">Super Admin (dev-super)</option>
                <option value="dev-analyst">SOC Analyst (dev-analyst)</option>
                <option value="">Unassigned</option>
              </select>
              <p className="text-[10.5px] text-[var(--sd-text-muted)]">
                Assign this task to an operator responsible for execution and verification.
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor={`${taskDialogId}-plan`}
                className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono"
              >
                Target Mitigation Plan (Incident)
              </label>
              <select
                id={`${taskDialogId}-plan`}
                value={newTaskPlanId}
                onChange={(e) => setNewTaskPlanId(e.target.value)}
                className="sd-input w-full rounded-xl px-3 py-2.5 text-[13px] text-[var(--sd-text)] transition"
              >
                <option value="">
                  {availablePlans.length > 0
                    ? `Default Incident Plan (${availablePlans[0]?.incident_code})`
                    : "Default Remediation Plan"}
                </option>
                {availablePlans.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.incident_code}: {p.incident_title} (Plan v{p.version})
                  </option>
                ))}
              </select>
              <p className="text-[10.5px] text-[var(--sd-text-muted)]">
                Select an incident mitigation plan to link this task to, or use the active incident sequence.
              </p>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-[var(--sd-border)]">
              <button
                type="button"
                onClick={() => {
                  setIsCreatingTask(false);
                  setNewTaskTitle("");
                }}
                className="sd-button px-4 py-2 text-[13px] text-[var(--sd-text-muted)] transition cursor-pointer font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting || !newTaskTitle.trim()}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-[#0E8563] to-[#0B6B50] hover:from-[#119E76] hover:to-[#0D7558] text-[#FFFFFF] border border-[#D8C49A]/30 text-[13px] font-bold shadow-[0_2px_12px_rgba(11,107,80,0.3)] transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="animate-spin h-3 w-3 text-[#FFFFFF]" />
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
        </GlassDialog>
      )}

      {/* Task Detail & Audit Drawer Modal */}
      {selectedTask && (
        <GlassDialog
          open={Boolean(selectedTask)}
          onClose={() => setSelectedTask(null)}
          labelledBy={detailDialogId}
          closeOnBackdrop
          className="max-w-2xl"
        >
          <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)]">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--sd-pine-dim)] text-[var(--sd-pine)] border border-[var(--sd-border)]">
                <CheckSquare className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 id={detailDialogId} className="text-base font-medium text-[var(--sd-text)]">
                    {selectedTask.title}
                  </h3>
                  <AutonomyTierBadge tier={selectedTask.tier} size="sm" showLabel={false} />
                  {!canEditTask && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text-dim)]">
                      Read-Only
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5 font-mono">
                  Task ID: {selectedTask.id}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSelectedTask(null)}
              className="sd-button flex h-9 w-9 items-center justify-center p-0 text-[var(--sd-text-muted)] transition cursor-pointer text-lg leading-none"
            >
              ×
            </button>
          </div>

          <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto text-[13px]">
            {/* Overview Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded-xl sd-surface border border-[var(--sd-border)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)]">
                  Status
                </span>
                <p className="font-semibold text-xs mt-1 capitalize text-[var(--sd-pine)]">
                  {selectedTask.status.replace("_", " ")}
                </p>
              </div>
              <div className="p-3 rounded-xl sd-surface border border-[var(--sd-border)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)]">
                  Horizon
                </span>
                <p className="font-semibold text-xs mt-1 capitalize text-[var(--sd-text)]">
                  {selectedTask.horizon.replace("_", " ")}
                </p>
              </div>
              <div className="p-3 rounded-xl sd-surface border border-[var(--sd-border)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)] block">
                  Autonomy Tier
                </span>
                {canEditTask ? (
                  <select
                    value={selectedTask.tier}
                    onChange={async (e) => {
                      const newTier = e.target.value;
                      await handleUpdateTier(selectedTask.id, newTier);
                    }}
                    className="mt-1 w-full bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-wheat)] font-semibold border border-[var(--sd-border)] rounded-lg px-2 py-1 outline-none font-mono cursor-pointer"
                  >
                    <option value="Tier 1">Tier 1 — Automatic</option>
                    <option value="Tier 2">Tier 2 — Human Sign-off</option>
                    <option value="Tier 3">Tier 3 — Dual Sign-off</option>
                  </select>
                ) : (
                  <p className="font-semibold text-xs mt-1 text-[var(--sd-wheat)] font-mono">
                    {selectedTask.tier}
                  </p>
                )}
              </div>
              <div className="p-3 rounded-xl sd-surface border border-[var(--sd-border)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)]">
                  Blast Radius
                </span>
                <p className="font-semibold text-xs mt-1 text-[var(--sd-text)] truncate">
                  {selectedTask.blast_radius || "Host Scope"}
                </p>
              </div>
            </div>

            {/* Task Assignee Selector */}
            <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-surface)] flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[var(--sd-pine-dim)] text-[var(--sd-wheat)] border border-[var(--sd-border)]">
                  <UserCheck className="h-3.5 w-3.5" />
                </div>
                <div>
                  <span className="text-[10.5px] uppercase font-mono text-[var(--sd-text-muted)] block">
                    Assigned Operator
                  </span>
                  <span className="text-xs font-semibold text-[var(--sd-text)]">
                    {selectedTask.assigned_to
                      ? DEV_USERS[selectedTask.assigned_to as DevUserId]?.label || selectedTask.assigned_to
                      : "Unassigned"}
                  </span>
                </div>
              </div>
              {canEditTask && (
                <div className="flex items-center gap-2">
                  <span className="text-[10.5px] font-mono text-[var(--sd-text-muted)] uppercase">
                    Re-assign:
                  </span>
                  <select
                    value={selectedTask.assigned_to || ""}
                    onChange={async (e) => {
                      const newAssignee = e.target.value || null;
                      try {
                        await fetch(`/api/tasks/${encodeURIComponent(selectedTask.id)}`, {
                          method: "PATCH",
                          headers: {
                            "Content-Type": "application/json",
                            "X-ShieldDesk-User": activeUserId,
                          },
                          body: JSON.stringify({ assignedTo: newAssignee }),
                        });
                        setSelectedTask((prev) => prev ? { ...prev, assigned_to: newAssignee } : null);
                        setTasks((prev) => prev.map((t) => t.id === selectedTask.id ? { ...t, assigned_to: newAssignee } : t));
                      } catch (err) {
                        console.error("Failed to re-assign task:", err);
                      }
                    }}
                    className="bg-[var(--sd-panel-raised)] text-[11px] text-[var(--sd-wheat)] font-semibold border border-[var(--sd-border)] rounded-lg px-2.5 py-1.5 outline-none font-mono cursor-pointer"
                  >
                    <option value="dev-responder">Responder (dev-responder)</option>
                    <option value="dev-admin">System Admin (dev-admin)</option>
                    <option value="dev-super">Super Admin (dev-super)</option>
                    <option value="dev-analyst">Analyst (dev-analyst)</option>
                    <option value="">Unassigned</option>
                  </select>
                </div>
              )}
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <h4 className="text-[11px] uppercase tracking-wider font-mono text-[var(--sd-text-muted)]">
                Description & Mitigation Scope
              </h4>
              <p className="p-3.5 rounded-xl bg-[var(--sd-bg-alt)]/60 border border-[var(--sd-border)] text-xs leading-relaxed text-[var(--sd-text)]">
                {selectedTask.description || "No specific instructions provided."}
              </p>
            </div>

            {/* Incident Context & Plan Switcher */}
            <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-surface)] space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <ShieldAlert className="h-4 w-4 text-[var(--sd-wheat)] shrink-0" />
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-[var(--sd-text)] truncate block">
                      Incident {detailData?.task.incident_code || (availablePlans[0]?.incident_code ?? "INC-4223")}: {detailData?.task.incident_title || (availablePlans[0]?.incident_title ?? "Active Incident Remediation")}
                    </span>
                    <span className="text-[10.5px] text-[var(--sd-text-muted)] font-mono block">
                      Plan Version {detailData?.task.plan_version || 1} · Severity: {detailData?.task.incident_severity || "Routine"}
                    </span>
                  </div>
                </div>

                {detailData?.task.plan_id && (
                  <Link
                    href={`/dashboard/plans/${detailData.task.plan_id}`}
                    className="sd-button flex items-center gap-1 text-[11px] px-2.5 py-1 text-[var(--sd-pine)] hover:underline shrink-0"
                  >
                    <span>View Plan</span>
                    <ExternalLink className="h-3 w-3" />
                  </Link>
                )}
              </div>

              {/* Plan Switcher Dropdown (Editable roles only) */}
              {canEditTask && (
                <div className="pt-2 border-t border-[var(--sd-border-subtle)] flex items-center justify-between gap-2 text-xs">
                  <span className="text-[10.5px] font-mono text-[var(--sd-text-muted)] uppercase">
                    Re-assign to Plan:
                  </span>
                  <select
                    value={selectedTask.plan_id || ""}
                    onChange={async (e) => {
                      const newPlanId = e.target.value;
                      if (!newPlanId || newPlanId === selectedTask.plan_id) return;
                      await handleUpdatePlan(selectedTask.id, newPlanId);
                    }}
                    className="bg-[var(--sd-panel-raised)] text-[11px] text-[var(--sd-pine)] border border-[var(--sd-border)] rounded-lg px-2.5 py-1 outline-none font-mono cursor-pointer max-w-[280px] truncate"
                  >
                    <option value="">Select Target Plan...</option>
                    {availablePlans.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.incident_code} ({p.incident_title.slice(0, 24)}…)
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* Governance & Approval Token History */}
            <div className="space-y-2">
              <h4 className="text-[11px] uppercase tracking-wider font-mono text-[var(--sd-text-muted)] flex items-center gap-1.5">
                <Lock className="h-3 w-3 text-[var(--sd-pine)]" /> Governance Sign-Off History
              </h4>
              {isLoadingDetail ? (
                <div className="p-4 text-center text-xs text-[var(--sd-text-muted)] font-mono">
                  Loading token verification…
                </div>
              ) : detailData?.approvalTokens && detailData.approvalTokens.length > 0 ? (
                <div className="space-y-2">
                  {detailData.approvalTokens.map((tok) => (
                    <div
                      key={tok.id}
                      className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11px] text-[var(--sd-pine)] font-semibold">
                          Token: {tok.id.slice(0, 18)}…
                        </span>
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold",
                            tok.status === "approved"
                              ? "bg-[var(--sd-pine-dim)] text-[var(--sd-pine)]"
                              : tok.status === "rejected"
                                ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)]"
                                : "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)]"
                          )}
                        >
                          {tok.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 text-[11px] text-[var(--sd-text-muted)]">
                        <span>Requester: <strong className="text-[var(--sd-text)]">{tok.requested_by}</strong></span>
                        <span>Approver: <strong className="text-[var(--sd-text)]">{tok.approved_by || "Pending"}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="p-3 rounded-xl border border-dashed border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)]">
                  {selectedTask.tier === "Tier 1"
                    ? "Tier 1 action: Autonomous execution permitted without human sign-off."
                    : "No governance approval token generated yet."}
                </p>
              )}
            </div>

            {/* Execution Logs / Console Output */}
            <div className="space-y-2">
              <h4 className="text-[11px] uppercase tracking-wider font-mono text-[var(--sd-text-muted)] flex items-center gap-1.5">
                <Terminal className="h-3 w-3 text-[var(--sd-pine)]" /> Agent Dispatch Logs
              </h4>
              {detailData?.commandLogs && detailData.commandLogs.length > 0 ? (
                <div className="space-y-2">
                  {detailData.commandLogs.map((log) => (
                    <div
                      key={log.id}
                      className="p-3.5 rounded-xl bg-black/60 border border-[var(--sd-border)] font-mono text-[11.5px] space-y-2"
                    >
                      <div className="flex items-center justify-between text-[var(--sd-pine)] text-[10.5px]">
                        <span>Command: {log.command}</span>
                        <span>{new Date(log.executed_at).toLocaleTimeString()}</span>
                      </div>
                      <div className="text-[var(--sd-text)] whitespace-pre-wrap leading-relaxed">
                        {log.output}
                      </div>
                    </div>
                  ))}
                </div>
              ) : selectedTask.status === "completed" ? (
                <div className="p-3.5 rounded-xl bg-black/60 border border-[var(--sd-border)] font-mono text-[11.5px] text-[var(--sd-success)]">
                  [+] Action verified and recorded in tamper-evident hash-chain audit trail.
                </div>
              ) : (
                <p className="p-3 rounded-xl border border-dashed border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)]">
                  Action has not been dispatched to an endpoint agent yet.
                </p>
              )}
            </div>
          </div>

          {/* Modal Footer Controls */}
          <div className="p-4 border-t border-[var(--sd-border)] flex items-center justify-between">
            {canEditTask ? (
              <button
                type="button"
                onClick={(e) => handleDeleteTask(selectedTask.id, e)}
                className="sd-button flex items-center gap-1.5 px-3 py-1.5 text-xs text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)] rounded-lg transition"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Delete Task</span>
              </button>
            ) : (
              <span className="text-[11px] font-mono text-[var(--sd-text-dim)]">
                Read-only view
              </span>
            )}

            <div className="flex items-center gap-2">
              {selectedTask.status === "pending" && (
                canUserSignOffTask(selectedTask.tier) ? (
                  <button
                    type="button"
                    onClick={(e) => handleOpenApproval(selectedTask, e)}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-[#D8C49A]/60 bg-[#D8C49A]/15 text-[#F2EFE9] hover:bg-[#D8C49A]/25 font-semibold text-xs transition cursor-pointer"
                  >
                    <Lock className="h-3.5 w-3.5 text-[#D8C49A]" />
                    <span>Sign Off Now</span>
                  </button>
                ) : (
                  <span className="text-[11px] font-mono text-[var(--sd-text-dim)] italic px-2 py-1">
                    {!canEditTask
                      ? "Awaiting Sign-off (Read-Only)"
                      : activeUser.role === "responder" && selectedTask.tier === "Tier 3"
                        ? "Tier 3 requires Admin Sign-off"
                        : "Awaiting Admin Sign-off"}
                  </span>
                )
              )}

              {(selectedTask.status === "approved" || selectedTask.status === "completed") && (
                canDispatch ? (
                  <button
                    type="button"
                    onClick={(e) => handleExecuteTask(selectedTask, e)}
                    disabled={executingTaskId === selectedTask.id}
                    className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#0E8563] to-[#0B6B50] hover:from-[#119E76] hover:to-[#0D7558] text-[#FFFFFF] border border-[#D8C49A]/30 font-bold text-xs shadow-[0_4px_16px_rgba(11,107,80,0.35)] transition cursor-pointer disabled:opacity-50"
                  >
                    {executingTaskId === selectedTask.id ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-[#FFFFFF]" />
                        <span>Dispatching…</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5 fill-current" />
                        <span>
                          {selectedTask.status === "completed" ? "Re-execute Task" : "Dispatch to Agent"}
                        </span>
                      </>
                    )}
                  </button>
                ) : (
                  <span className="text-xs font-mono text-[var(--sd-text-dim)] italic px-2 py-1">
                    {selectedTask.status === "completed" ? "Executed" : "Authorized · Awaiting dispatch by Responder"}
                  </span>
                )
              )}
            </div>
          </div>
        </GlassDialog>
      )}

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

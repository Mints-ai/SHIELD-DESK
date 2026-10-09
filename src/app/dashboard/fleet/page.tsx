"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import type { EndpointAgentRecord } from "@/lib/fleet/fleet";
import {
  Server,
  ShieldAlert,
  Cpu,
  HardDrive,
  Activity,
  Terminal,
  PowerOff,
  RefreshCw,
  Lock,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Wifi,
  Pause,
  Key,
  Plus,
  Copy,
  ClipboardCheck,
  Plug,
  MonitorDot,
  ExternalLink,
  Trash2,
  Unplug,
  WifiOff,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface CommandLogEntry {
  id: string;
  time: string;
  command: string;
  tier: string;
  status: "succeeded" | "failed" | "executing";
  output: string;
  agentId?: string;
  executedAt?: string;
}

interface EnrollResult {
  token: string;
  expiresAt: string;
  tenantId: string;
}

// Maps each command value to its required autonomy tier
const COMMAND_TIERS: Record<string, "Tier 1" | "Tier 2"> = {
  take_safety_snapshot: "Tier 1",
  block_ip: "Tier 1",
  isolate_host: "Tier 2",
  restore_host: "Tier 2",
  kill_process: "Tier 2",
  rollback_snapshot: "Tier 2",
  custom: "Tier 1",
};

export default function FleetPage() {
  const { activeUserId, activeUser } = useChat();
  const canManageFleetAgents =
    activeUser.role === "system_admin" ||
    activeUser.role === "super_admin" ||
    activeUser.role === "responder";


  const [agents, setAgents] = useState<EndpointAgentRecord[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgentRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [isStreaming, setIsStreaming] = useState(true);
  const [lastHeartbeatTime, setLastHeartbeatTime] = useState<Date>(new Date());
  const [selectedAction, setSelectedAction] = useState<string>("take_safety_snapshot");
  const [targetIp, setTargetIp] = useState<string>("");
  const [targetPid, setTargetPid] = useState<string>("");
  const [customCommand, setCustomCommand] = useState<string>("");
  const [selectedTier, setSelectedTier] = useState<"Tier 1" | "Tier 2">("Tier 1");
  const [tokenIdInput, setTokenIdInput] = useState("");
  const [commandLogs, setCommandLogs] = useState<CommandLogEntry[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [killSwitchEngaged, setKillSwitchEngaged] = useState(false);
  const [filterAgentId, setFilterAgentId] = useState<string>("all");
  const [reconnectingAgentId, setReconnectingAgentId] = useState<string | null>(null);
  // Map of agentId -> timestamp (ms) when 5-second reconnect grace window expires
  const [disconnectGracePeriods, setDisconnectGracePeriods] = useState<Record<string, number>>({});
  const [currentTime, setCurrentTime] = useState<number>(() => Date.now());

  // High-frequency clock to tick countdowns smoothly
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(Date.now());
    }, 200);
    return () => clearInterval(timer);
  }, []);

  const [dispatchFeedback, setDispatchFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  // Enrollment panel state
  const [showEnrollPanel, setShowEnrollPanel] = useState(false);
  const [enrollLabel, setEnrollLabel] = useState("");
  const [enrollExpiry, setEnrollExpiry] = useState("24");
  const [enrollResult, setEnrollResult] = useState<EnrollResult | null>(null);
  const [enrollLoading, setEnrollLoading] = useState(false);
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);

  // Fetch real-time audit logs from the database
  const fetchLogs = useCallback(async () => {
    try {
      const res = await fetch("/api/fleet/logs", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (data.logs && Array.isArray(data.logs)) {
        setCommandLogs(data.logs);
      }
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    }
  }, [activeUserId]);

  // One-shot or manual refresh of fleet
  const fetchFleet = useCallback(async (forceRefresh = false) => {
    try {
      setLoading(true);
      const url = forceRefresh ? "/api/fleet?refresh=true" : "/api/fleet";
      const res = await fetch(url, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (data.agents) {
        setAgents(data.agents);
        setSelectedAgent((prev) => {
          if (!prev && data.agents.length > 0) return data.agents[0];
          if (prev) {
            const updated = data.agents.find(
              (a: EndpointAgentRecord) => a.id === prev.id
            );
            return updated || prev;
          }
          return null;
        });
        const anyKilled = data.agents.some(
          (a: EndpointAgentRecord) => a.kill_switch_active
        );
        setKillSwitchEngaged(anyKilled);
        setLastHeartbeatTime(new Date());
      }
    } catch (err) {
      console.error("Failed to load fleet:", err);
    } finally {
      setLoading(false);
    }
  }, [activeUserId]);

  // Real-Time Server-Sent Events (SSE) Stream
  useEffect(() => {
    fetchFleet();
    fetchLogs();

    if (!isStreaming) return;

    let pollInterval: NodeJS.Timeout | null = null;

    try {
      const sse = new EventSource("/api/fleet/stream");
      eventSourceRef.current = sse;

      sse.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.agents !== undefined) {
            setAgents(payload.agents);
            setSelectedAgent((prev) => {
              if (!prev && payload.agents.length > 0) return payload.agents[0];
              if (prev) {
                const updated = payload.agents.find(
                  (a: EndpointAgentRecord) => a.id === prev.id
                );
                // If selected agent was removed, clear selection
                return updated || (payload.agents.length > 0 ? prev : null);
              }
              return null;
            });
            if (payload.stats?.killSwitchActive !== undefined) {
              setKillSwitchEngaged(payload.stats.killSwitchActive);
            }
            setLastHeartbeatTime(new Date());
            setLoading(false);
          }
        } catch (e) {
          console.error("SSE parse error:", e);
        }
      };

      sse.onerror = () => {
        if (!pollInterval) {
          pollInterval = setInterval(() => {
            fetchFleet();
          }, 5000);
        }
      };
    } catch {
      pollInterval = setInterval(() => {
        fetchFleet();
      }, 5000);
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [activeUserId, isStreaming, fetchFleet, fetchLogs]);

  // Handle Emergency Kill Switch
  const handleToggleKillSwitch = async () => {
    const nextState = !killSwitchEngaged;
    const confirmText = nextState
      ? "EMERGENCY: Are you sure you want to engage the Emergency Kill Switch? All endpoint agents will be severed immediately and traffic dropped."
      : "Restore endpoint agent connectivity across the fleet?";
    if (!confirm(confirmText)) return;

    try {
      const res = await fetch("/api/fleet/kill-switch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ active: nextState }),
      });
      const data = await res.json();
      if (res.ok) {
        setKillSwitchEngaged(data.killSwitchActive ?? nextState);
        fetchFleet();
        fetchLogs();
      } else {
        alert(data.error || "Action failed");
      }
    } catch {
      alert("Network error toggling kill switch");
    }
  };

  // Dispatch live command
  const handleExecuteCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent || isExecuting) return;

    let cmd = selectedAction;
    if (selectedAction === "block_ip") {
      const cleanIp = targetIp.trim();
      if (!cleanIp) {
        setDispatchFeedback({
          type: "error",
          message: "Please specify an IP address to block (e.g. 203.0.113.15 or 10.0.0.1).",
        });
        return;
      }
      cmd = `block_ip ${cleanIp}`;
    } else if (selectedAction === "kill_process") {
      const cleanPid = targetPid.trim();
      if (!cleanPid) {
        setDispatchFeedback({
          type: "error",
          message: "Please enter a Process ID (PID) to terminate.",
        });
        return;
      }
      cmd = `kill_process ${cleanPid}`;
    } else if (selectedAction === "custom") {
      const cleanCmd = customCommand.trim();
      if (!cleanCmd) {
        setDispatchFeedback({
          type: "error",
          message: "Please enter a custom command to execute.",
        });
        return;
      }
      cmd = cleanCmd;
    }

    setIsExecuting(true);
    setDispatchFeedback(null);
    const newLogId = crypto.randomUUID();
    const newLog: CommandLogEntry = {
      id: newLogId,
      time: new Date().toLocaleTimeString(),
      command: cmd,
      tier: selectedTier,
      status: "executing",
      output: `Dispatching ${selectedTier} instruction to ${selectedAgent.hostname}...`,
      agentId: selectedAgent.id,
    };

    setCommandLogs((prev) => [newLog, ...prev]);

    try {
      const res = await fetch("/api/fleet/execute", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          agentId: selectedAgent.id,
          command: cmd,
          tier: selectedTier,
          approvalTokenId:
            selectedTier === "Tier 2" ? tokenIdInput || undefined : undefined,
        }),
      });

      const data = await res.json();

      setCommandLogs((prev) =>
        prev.map((log) => {
          if (log.id !== newLogId) return log;
          if (res.ok && data.success) {
            return {
              ...log,
              id: data.commandId || log.id,
              status: "succeeded",
              output:
                data.output ||
                "Instruction executed with status SUCCESS. Telemetry updated.",
            };
          } else {
            return {
              ...log,
              status: "failed",
              output: `Execution rejected (${data.error || "Policy violation"}): ${data.message || ""}`,
            };
          }
        })
      );

      if (res.ok && data.success) {
        setDispatchFeedback({
          type: "success",
          message: `Successfully executed ${cmd} on ${selectedAgent.hostname}. Live telemetry updated.`,
        });
      } else {
        setDispatchFeedback({
          type: "error",
          message: data.error || "Command execution failed.",
        });
      }

      fetchFleet();
      fetchLogs();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network failure";
      setCommandLogs((prev) =>
        prev.map((log) =>
          log.id === newLogId ? { ...log, status: "failed", output: msg } : log
        )
      );
      setDispatchFeedback({ type: "error", message: msg });
    } finally {
      setIsExecuting(false);
    }
  };

  // Clear command audit logs
  const handleClearLogs = async () => {
    if (!confirm("Are you sure you want to clear the audit logs?")) return;
    try {
      const url =
        filterAgentId !== "all"
          ? `/api/fleet/logs?agentId=${filterAgentId}`
          : "/api/fleet/logs";
      await fetch(url, {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      fetchLogs();
    } catch (err) {
      console.error("Failed to clear audit logs:", err);
    }
  };

  // Disconnect an agent (starts 5s reconnect grace period; marks as disconnected in DB)
  const handleDisconnectAgent = async (agentId: string) => {
    // Start 5-second countdown grace period immediately
    setDisconnectGracePeriods((prev) => ({
      ...prev,
      [agentId]: Date.now() + 5000,
    }));

    // Optimistically update agent status locally
    setAgents((prev) =>
      prev.map((a) =>
        a.id === agentId
          ? { ...a, status: "disconnected", cpu_usage: 0, eps: 0 }
          : a
      )
    );
    setSelectedAgent((prev) =>
      prev?.id === agentId
        ? { ...prev, status: "disconnected", cpu_usage: 0, eps: 0 }
        : prev
    );

    try {
      const res = await fetch(`/api/fleet/${agentId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "disconnect" }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        fetchFleet();
      } else {
        // Revert grace period on error
        setDisconnectGracePeriods((prev) => {
          const next = { ...prev };
          delete next[agentId];
          return next;
        });
        await fetchFleet(true);
        alert(data.error || "Failed to disconnect agent");
      }
    } catch {
      setDisconnectGracePeriods((prev) => {
        const next = { ...prev };
        delete next[agentId];
        return next;
      });
      await fetchFleet(true);
      alert("Network error disconnecting agent");
    }
  };

  // Reconnect/refresh a disconnected agent
  const handleReconnectAgent = async (agentId: string) => {
    setReconnectingAgentId(agentId);
    // Clear grace period so countdown is removed immediately
    setDisconnectGracePeriods((prev) => {
      const next = { ...prev };
      delete next[agentId];
      return next;
    });

    const nowIso = new Date().toISOString();
    setAgents((prev) =>
      prev.map((a) =>
        a.id === agentId
          ? { ...a, status: "connected", last_heartbeat: nowIso, cpu_usage: 0, memory_usage: 0, eps: 0 }
          : a
      )
    );
    setSelectedAgent((prev) =>
      prev?.id === agentId
        ? { ...prev, status: "connected", last_heartbeat: nowIso, cpu_usage: 0, memory_usage: 0, eps: 0 }
        : prev
    );
    try {
      const res = await fetch(`/api/fleet/${agentId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "reconnect" }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        await fetchFleet(true);
      } else {
        // Revert optimistic update on failure
        await fetchFleet(true);
        alert(data.error || "Failed to reconnect endpoint");
      }
    } catch {
      await fetchFleet(true);
      alert("Network error reconnecting endpoint");
    } finally {
      setReconnectingAgentId(null);
    }
  };

  // Remove/unenroll an agent (deletes from DB entirely)
  const handleRemoveAgent = async (agentId: string, hostname: string) => {
    if (!confirm(`Remove endpoint "${hostname}" from the fleet? This cannot be undone.`)) return;
    try {
      const res = await fetch(`/api/fleet/${agentId}`, {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setDisconnectGracePeriods((prev) => {
          const next = { ...prev };
          delete next[agentId];
          return next;
        });
        setAgents((prev) => prev.filter((a) => a.id !== agentId));
        setSelectedAgent((prev) => (prev?.id === agentId ? null : prev));
        fetchFleet();
      } else {
        alert(data.error || "Failed to remove agent");
      }
    } catch {
      alert("Network error removing agent");
    }
  };

  // Generate enrollment token
  const handleGenerateToken = async () => {
    setEnrollLoading(true);
    setEnrollError(null);
    setEnrollResult(null);
    try {
      const res = await fetch("/api/fleet/enrollment-tokens", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          label: enrollLabel || "Manual enrollment",
          expiresInHours: Number(enrollExpiry) || 24,
          maxUses: 1,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setEnrollResult({
          token: data.token,
          expiresAt: data.expiresAt,
          tenantId: data.tenantId,
        });
      } else {
        setEnrollError(data.error || "Failed to generate token");
      }
    } catch (err) {
      setEnrollError(err instanceof Error ? err.message : "Network error");
    } finally {
      setEnrollLoading(false);
    }
  };

  const handleCopy = async (text: string, type: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  const serverURL =
    typeof window !== "undefined"
      ? window.location.origin
      : "http://localhost:3000";

  const goCommand = enrollResult
    ? `.\\shielddesk-agent.exe -token ${enrollResult.token} -control-url ${serverURL}`
    : "";

  const nodeCommand = enrollResult
    ? `node agent/agent-daemon.js --token ${enrollResult.token} --control-url ${serverURL}`
    : "";

  const filteredLogs = commandLogs.filter((log) => {
    if (filterAgentId === "all") return true;
    return (
      log.agentId === filterAgentId ||
      (selectedAgent && log.output.includes(selectedAgent.hostname))
    );
  });

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-6">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl sd-surface border border-[var(--sd-border)] text-[var(--sd-wheat)] shadow-xs">
                <Server className="h-4.5 w-4.5" />
              </div>
              <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                Fleet &amp; hosts
              </h1>
              <span className="rounded-md sd-surface border border-[var(--sd-border)] px-2.5 py-0.5 text-[11px] font-medium text-[var(--sd-pine)] font-mono shadow-xs">
                {agents.length} Enrolled Host{agents.length !== 1 ? "s" : ""}
              </span>

              {/* Real-Time Live Beacon */}
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[11px] font-mono">
                <span className="relative flex h-2 w-2">
                  {isStreaming && !killSwitchEngaged ? (
                    <>
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </>
                  ) : (
                    <span className="inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
                  )}
                </span>
                <span
                  className={cn(
                    "font-medium",
                    isStreaming ? "text-emerald-400" : "text-amber-400"
                  )}
                >
                  {killSwitchEngaged
                    ? "TELEMETRY SEVERED"
                    : isStreaming
                    ? "STREAM ACTIVE"
                    : "STREAM PAUSED"}
                </span>
              </div>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              Real endpoint agents reporting live telemetry via the ShieldDesk
              Universal Endpoint Agent
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Connect Endpoint Button */}
            <button
              onClick={() => {
                setShowEnrollPanel((v) => !v);
                setEnrollResult(null);
                setEnrollError(null);
              }}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 rounded-full border text-[12px] font-medium transition cursor-pointer shadow-xs",
                showEnrollPanel
                  ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] border-[var(--sd-pine)]"
                  : "sd-surface border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)]"
              )}
            >
              <Plus className="h-3 w-3" />
              <span>Connect Endpoint</span>
            </button>

            {/* Toggle Pause / Resume Live Stream */}
            <button
              onClick={() => setIsStreaming((prev) => !prev)}
              className="sd-button flex items-center gap-1.5 px-3 py-2 rounded-full border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-[12px] font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
              title={
                isStreaming
                  ? "Pause real-time streaming"
                  : "Resume real-time streaming"
              }
            >
              {isStreaming ? (
                <>
                  <Pause className="h-3 w-3 text-amber-400" />
                  <span>Pause Stream</span>
                </>
              ) : (
                <>
                  <Radio className="h-3 w-3 text-emerald-400" />
                  <span>Resume Stream</span>
                </>
              )}
            </button>

            {/* Manual Refresh */}
            <button
              onClick={() => {
                fetchFleet(true);
                fetchLogs();
              }}
              className="sd-button flex items-center gap-1.5 px-3 py-2 rounded-full border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-[12px] font-medium text-[var(--sd-pine)] transition cursor-pointer shadow-xs"
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", loading && "animate-spin text-[var(--sd-pine)]")}
              />
              <span>Refresh Now</span>
            </button>

            {/* Emergency Admin Kill Switch */}
            <button
              onClick={handleToggleKillSwitch}
              className={cn(
                "flex items-center gap-2 px-3.5 py-2 rounded-xl text-[13px] font-medium transition cursor-pointer border shadow-xs",
                killSwitchEngaged
                  ? "bg-[var(--sd-success)] text-[var(--sd-on-accent)] border-[var(--sd-success-border)]"
                  : "bg-[var(--sd-danger)] text-[var(--sd-on-accent)] border-[var(--sd-danger-border)] hover:opacity-90"
              )}
            >
              <PowerOff className="h-3.5 w-3.5" />
              <span>
                {killSwitchEngaged
                  ? "Disengage Kill Switch (Restore Fleet)"
                  : "Emergency Kill Switch"}
              </span>
            </button>
          </div>
        </div>

        {/* ── Connect Endpoint Enrollment Panel ── */}
        {showEnrollPanel && (
          <div className="rounded-2xl border border-[var(--sd-pine)]/40 bg-[var(--sd-panel-raised)] p-6 space-y-5 shadow-md">
            <div className="flex items-center gap-2 mb-1">
              <Plug className="h-4 w-4 text-[var(--sd-pine)]" />
              <h2 className="text-[14px] font-medium text-[var(--sd-pine)] uppercase tracking-wider font-mono">
                Connect a Real Endpoint
              </h2>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] leading-relaxed max-w-2xl">
              Generate a one-time enrollment token. Run the ShieldDesk agent
              binary on your target machine with this token — it will self-register
              and start reporting live telemetry immediately.
            </p>

            {!enrollResult ? (
              <div className="flex flex-wrap gap-3 items-end">
                <div className="flex-1 min-w-[180px]">
                  <label className="text-[11px] font-medium text-[var(--sd-text-muted)] block mb-1.5">
                    Label (optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. My Laptop, Server-01"
                    value={enrollLabel}
                    onChange={(e) => setEnrollLabel(e.target.value)}
                    className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                  />
                </div>
                <div className="w-36">
                  <label className="text-[11px] font-medium text-[var(--sd-text-muted)] block mb-1.5">
                    Expires in
                  </label>
                  <select
                    value={enrollExpiry}
                    onChange={(e) => setEnrollExpiry(e.target.value)}
                    className="sd-input w-full bg-[var(--sd-bg)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                  >
                    <option value="1">1 hour</option>
                    <option value="6">6 hours</option>
                    <option value="24">24 hours</option>
                    <option value="72">72 hours</option>
                  </select>
                </div>
                <button
                  onClick={handleGenerateToken}
                  disabled={enrollLoading}
                  className="sd-button sd-button-primary px-5 py-2 rounded-xl text-[13px] font-medium flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Key className="h-3.5 w-3.5" />
                  {enrollLoading ? "Generating..." : "Generate Token"}
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-2 text-emerald-400 text-[13px] font-mono">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>
                    Token generated — expires{" "}
                    {new Date(enrollResult.expiresAt).toLocaleString()}
                  </span>
                </div>

                {/* Token display */}
                <div className="rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] p-4 space-y-3">
                  <div>
                    <p className="text-[11px] font-mono text-[var(--sd-text-muted)] mb-1.5 uppercase tracking-wider">
                      Enrollment Token (shown once)
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 text-[12px] font-mono text-[var(--sd-pine)] bg-[var(--sd-panel-raised)] px-3 py-2 rounded-lg border border-[var(--sd-border)] break-all select-all">
                        {enrollResult.token}
                      </code>
                      <button
                        onClick={() => handleCopy(enrollResult.token, "token")}
                        className="p-2 rounded-lg hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer"
                        title="Copy token"
                      >
                        {copied === "token" ? (
                          <ClipboardCheck className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Copy className="h-4 w-4 text-[var(--sd-text-muted)]" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Option 1: Native Go Agent Binary (Primary / Recommended) */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider font-semibold">
                        Option 1: Native Go Agent (Recommended & Production-Grade)
                      </p>
                      <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                        Go Native Binary
                      </span>
                    </div>
                    <div className="flex items-start gap-2">
                      <code className="flex-1 text-[11px] font-mono text-emerald-300 bg-[var(--sd-panel-raised)] px-3 py-2 rounded-lg border border-[var(--sd-border)] break-all select-all whitespace-pre-wrap">
                        {goCommand}
                      </code>
                      <button
                        onClick={() => handleCopy(goCommand, "go-cmd")}
                        className="p-2 rounded-lg hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer mt-0.5"
                        title="Copy Go command"
                      >
                        {copied === "go-cmd" ? (
                          <ClipboardCheck className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Copy className="h-4 w-4 text-[var(--sd-text-muted)]" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Option 2: Node.js Agent Daemon (Fallback) */}
                  <div className="space-y-1.5 pt-2 border-t border-[var(--sd-border)]">
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase tracking-wider">
                        Option 2: Node.js Agent Daemon (Dev / Script Fallback)
                      </p>
                      <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                        node agent/agent-daemon.js
                      </span>
                    </div>
                    <div className="flex items-start gap-2">
                      <code className="flex-1 text-[11px] font-mono text-amber-300 bg-[var(--sd-panel-raised)] px-3 py-2 rounded-lg border border-[var(--sd-border)] break-all select-all whitespace-pre-wrap">
                        {nodeCommand}
                      </code>
                      <button
                        onClick={() => handleCopy(nodeCommand, "node-cmd")}
                        className="p-2 rounded-lg hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer mt-0.5"
                        title="Copy Node command"
                      >
                        {copied === "node-cmd" ? (
                          <ClipboardCheck className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Copy className="h-4 w-4 text-[var(--sd-text-muted)]" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => {
                    setEnrollResult(null);
                    setEnrollLabel("");
                  }}
                  className="text-[12px] text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] underline font-mono cursor-pointer transition"
                >
                  Generate another token
                </button>
              </div>
            )}

            {enrollError && (
              <div className="flex items-center gap-2 text-red-400 text-[12px] font-mono bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{enrollError}</span>
              </div>
            )}
          </div>
        )}

        {/* Fleet KPI Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                Active Endpoints
              </span>
              <div className="text-2xl font-medium font-mono text-[var(--sd-pine)] mt-1 flex items-baseline gap-1.5">
                <span>
                  {
                    agents.filter(
                      (a) =>
                        a.status === "connected" &&
                        Date.now() - new Date(a.last_heartbeat).getTime() <= 15000
                    ).length
                  }
                </span>
                <span className="text-[14px] text-[var(--sd-text-muted)] font-normal">
                  / {agents.length}
                </span>
                {agents.some((a) => a.status === "isolated") && (
                  <span className="text-[11px] text-amber-400 font-mono ml-1">
                    ({agents.filter((a) => a.status === "isolated").length} quarantined)
                  </span>
                )}
              </div>
            </div>
            <Server className="h-6 w-6 text-[var(--sd-pine)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                Aggregate Telemetry
              </span>
              <div className="text-2xl font-medium font-mono text-[var(--sd-pine)] mt-1 transition-all duration-300">
                {agents.reduce(
                  (acc, a) =>
                    acc +
                    (a.status === "connected" &&
                    Date.now() - new Date(a.last_heartbeat).getTime() <= 15000
                      ? a.eps || 0
                      : 0),
                  0
                )}{" "}
                <span className="text-[13px] font-normal text-[var(--sd-text-muted)]">
                  EPS
                </span>
              </div>
            </div>
            <Activity className="h-6 w-6 text-[var(--sd-pine)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                Safety Baselines Active
              </span>
              <div className="text-2xl font-medium font-mono text-[var(--sd-success)] mt-1">
                {agents.filter((a) => a.safety_snapshot_id).length}
              </div>
            </div>
            <ShieldAlert className="h-6 w-6 text-[var(--sd-success)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                Kill Switch Status
              </span>
              <div
                className={cn(
                  "text-[13px] font-medium font-mono mt-2 uppercase tracking-wider",
                  killSwitchEngaged
                    ? "text-[var(--sd-danger)]"
                    : "text-[var(--sd-success)]"
                )}
              >
                {killSwitchEngaged ? "ACTIVE (Fleet Severed)" : "NOMINAL (Listening)"}
              </div>
            </div>
            <PowerOff
              className={cn(
                "h-6 w-6 opacity-70",
                killSwitchEngaged
                  ? "text-[var(--sd-danger)]"
                  : "text-[var(--sd-success)]"
              )}
            />
          </div>
        </div>

        {/* ── Agent Cards Grid or Empty State ── */}
        {loading && agents.length === 0 ? (
          <div className="flex items-center justify-center h-48">
            <RefreshCw className="h-6 w-6 animate-spin text-[var(--sd-pine)] opacity-60" />
          </div>
        ) : agents.length === 0 ? (
          /* Empty State — No Real Agents Connected */
          <div className="rounded-2xl border border-dashed border-[var(--sd-border)] bg-[var(--sd-panel-raised)]/40 p-12 flex flex-col items-center justify-center text-center space-y-5">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text-muted)]">
              <MonitorDot className="h-8 w-8 opacity-50" />
            </div>
            <div className="space-y-2 max-w-md">
              <h3 className="text-[17px] font-medium text-[var(--sd-text)]">
                No Endpoints Connected
              </h3>
              <p className="text-[13px] text-[var(--sd-text-muted)] leading-relaxed">
                There are no real agents reporting to this control plane yet.
                Generate an enrollment token and run the ShieldDesk agent binary
                on your endpoint to connect it.
              </p>
            </div>
            <button
              onClick={() => setShowEnrollPanel(true)}
              className="sd-button sd-button-primary flex items-center gap-2 px-5 py-2.5 rounded-xl text-[13px] font-medium cursor-pointer shadow-xs"
            >
              <Plus className="h-4 w-4" />
              Connect Your First Endpoint
            </button>
          </div>
        ) : (
          /* Real Agent Cards Grid */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {agents.map((agent) => {
              const isSelected = selectedAgent?.id === agent.id;
              const msAgo = Math.max(0, Date.now() - new Date(agent.last_heartbeat).getTime());
              const secondsAgo = Math.floor(msAgo / 1000);
              const minutesAgo = Math.floor(secondsAgo / 60);
              const isTimedOut = secondsAgo > 15;
              const isDisconnected = agent.status === "disconnected" || isTimedOut;
              const effectiveStatus = isDisconnected ? "disconnected" : agent.status;
              const isStale = !isDisconnected && secondsAgo > 8;

              const cleanIp =
                agent.ip_address && agent.ip_address !== "Unknown"
                  ? agent.ip_address
                  : "Unavailable";

              const cpuVal = isDisconnected || isStale ? 0 : agent.cpu_usage;
              const memVal = isDisconnected || isStale ? 0 : agent.memory_usage;
              const epsVal = isDisconnected || isStale ? 0 : agent.eps;

              const graceExpiresAt = disconnectGracePeriods[agent.id];
              const remainingGraceMs = graceExpiresAt ? Math.max(0, graceExpiresAt - currentTime) : 0;
              const isWithinGrace = isDisconnected && remainingGraceMs > 0;
              const remainingSeconds = Math.ceil(remainingGraceMs / 1000);

              return (
                <div
                  key={agent.id}
                  onClick={() => setSelectedAgent(agent)}
                  className={cn(
                    "p-4 rounded-2xl border transition-all duration-300 cursor-pointer space-y-3 relative overflow-hidden",
                    isSelected
                      ? "border-[var(--sd-pine)] bg-[var(--sd-bg-alt)]/70 shadow-md ring-1 ring-[var(--sd-pine)]/30"
                      : "border-[var(--sd-border)] sd-surface hover:border-[var(--sd-border-strong)] hover:bg-[var(--sd-panel-hover)]/40 shadow-xs"
                  )}
                >
                  {/* Stale heartbeat warning badge */}
                  {isStale && (
                    <div className="absolute top-0 right-0 bg-amber-500/15 border-b border-l border-amber-500/30 text-amber-400 text-[9px] font-mono px-2 py-0.5 rounded-bl-lg font-medium flex items-center gap-1">
                      <AlertTriangle className="h-2.5 w-2.5" />
                      <span>STALE</span>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          "h-2 w-2 rounded-full",
                          effectiveStatus === "connected" &&
                            !isStale &&
                            "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]",
                          effectiveStatus === "connected" &&
                            isStale &&
                            "bg-amber-400",
                          effectiveStatus === "isolated" && "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]",
                          effectiveStatus === "disconnected" && "bg-red-400"
                        )}
                      />
                      <span
                        className="font-mono font-medium text-[13px] text-[var(--sd-pine)] truncate max-w-[160px]"
                        title={agent.hostname}
                      >
                        {agent.hostname}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] border border-[var(--sd-border)] font-medium">
                      {agent.os_type}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-[11px] text-[var(--sd-text-muted)] font-mono">
                    <div className="flex justify-between">
                      <span>IP Address:</span>
                      <span className="text-[var(--sd-text)] font-medium">
                        {cleanIp}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Agent Version:</span>
                      <span className="text-[var(--sd-text)]">
                        v{agent.agent_version}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Events/sec:</span>
                      <span className="text-[var(--sd-pine)] font-medium transition-all duration-300">
                        {epsVal} EPS
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-[10px] pt-0.5 border-t border-[var(--sd-border)]/40">
                      <span className="text-[var(--sd-text-dim)]">
                        {isDisconnected ? "State:" : "Last heartbeat:"}
                      </span>
                      <span
                        className={cn(
                          "font-medium",
                          isDisconnected
                            ? "text-red-400"
                            : isStale
                            ? "text-amber-400"
                            : "text-emerald-400"
                        )}
                      >
                        {isDisconnected
                          ? "Offline / Severed"
                          : secondsAgo < 10
                          ? "just now"
                          : secondsAgo < 60
                          ? `${secondsAgo}s ago`
                          : `${minutesAgo}m ago`}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="text-[var(--sd-text-dim)]">Status:</span>
                      <span
                        className={cn(
                          "uppercase font-medium",
                          effectiveStatus === "connected" && !isStale && "text-emerald-400",
                          effectiveStatus === "connected" && isStale && "text-amber-400",
                          effectiveStatus === "isolated" && "text-amber-400",
                          effectiveStatus === "disconnected" && "text-red-400"
                        )}
                      >
                        {isStale && effectiveStatus === "connected"
                          ? "stale"
                          : effectiveStatus}
                      </span>
                    </div>
                  </div>

                  {/* Real-time CPU & Memory Progress Bars */}
                  <div className="pt-2 border-t border-[var(--sd-border)] space-y-2 text-[11px]">
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-[var(--sd-text-muted)] flex items-center gap-1">
                          <Cpu className="h-3 w-3 opacity-70" /> CPU Usage
                        </span>
                        <span className="font-mono text-[var(--sd-text)] font-medium transition-all duration-300">
                          {cpuVal}%
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full transition-all duration-500",
                            cpuVal > 80
                              ? "bg-red-400"
                              : cpuVal > 50
                              ? "bg-amber-400"
                              : "bg-[var(--sd-pine)]"
                          )}
                          style={{
                            width: `${Math.min(100, Math.max(0, cpuVal))}%`,
                          }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-[var(--sd-text-muted)] flex items-center gap-1">
                          <HardDrive className="h-3 w-3 opacity-70" /> Memory Usage
                        </span>
                        <span className="font-mono text-[var(--sd-text)] font-medium transition-all duration-300">
                          {memVal}%
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full transition-all duration-500",
                            memVal > 85 ? "bg-red-400" : "bg-[var(--sd-pine)]/70"
                          )}
                          style={{
                            width: `${Math.min(100, Math.max(0, memVal))}%`,
                          }}
                        />
                      </div>
                    </div>
                  </div>

                    <div className="flex items-center gap-2 pt-2 border-t border-[var(--sd-border)]/40">
                      {!isDisconnected ? (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDisconnectAgent(agent.id);
                          }}
                          className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2.5 rounded-xl text-[11px] font-mono font-medium border border-amber-500/30 text-amber-300 hover:bg-amber-500/10 hover:border-amber-500/60 transition cursor-pointer"
                          title="Disconnect this endpoint"
                        >
                          <Unplug className="h-3.5 w-3.5" />
                          <span>Disconnect</span>
                        </button>
                      ) : isWithinGrace ? (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (reconnectingAgentId !== agent.id) {
                              handleReconnectAgent(agent.id);
                            }
                          }}
                          disabled={reconnectingAgentId === agent.id}
                          className="w-full flex items-center justify-center gap-2 py-1.5 px-2.5 rounded-xl text-[11px] font-mono font-semibold border border-emerald-500/50 text-emerald-300 bg-emerald-500/15 hover:bg-emerald-500/25 hover:border-emerald-500/80 transition cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed shadow-xs shadow-emerald-500/10 animate-pulse"
                          title={`Reconnect host — window expires in ${remainingSeconds}s`}
                        >
                          <RefreshCw className={cn("h-3.5 w-3.5", reconnectingAgentId === agent.id && "animate-spin")} />
                          <span>
                            {reconnectingAgentId === agent.id
                              ? "Reconnecting..."
                              : `Reconnect Host (${remainingSeconds}s)`}
                          </span>
                        </button>
                      ) : (
                        canManageFleetAgents ? (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemoveAgent(agent.id, agent.hostname);
                            }}
                            className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2.5 rounded-xl text-[11px] font-mono font-medium border border-red-500/40 text-red-400 bg-red-500/10 hover:bg-red-500/20 hover:border-red-500/70 transition cursor-pointer"
                            title="Remove endpoint from fleet"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            <span>Delete Host</span>
                          </button>
                        ) : (
                          <div className="w-full py-1.5 text-center text-[10px] font-mono text-[var(--sd-text-dim)]">
                            Endpoint Severed
                          </div>
                        )
                      )}
                    </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Live Command Console + Real-Time Execution Audit Trail */}
        {selectedAgent && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Terminal Command Dispatcher */}
            <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-[var(--sd-pine)]" />
                  <h3 className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                    Live Instruction Console: {selectedAgent.hostname}
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                  OS: {selectedAgent.os_type} &bull; v{selectedAgent.agent_version}
                </span>
              </div>

              {dispatchFeedback && (
                <div
                  className={cn(
                    "p-3 rounded-xl border text-[12px] font-mono flex items-start gap-2",
                    dispatchFeedback.type === "success"
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                      : "bg-red-500/10 border-red-500/30 text-red-300"
                  )}
                >
                  {dispatchFeedback.type === "success" ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                  )}
                  <span>{dispatchFeedback.message}</span>
                </div>
              )}

              <form onSubmit={handleExecuteCommand} className="space-y-4 text-[13px]">
                <div>
                  <label className="text-[11px] font-medium text-[var(--sd-pine)] block mb-1">
                    Select Endpoint Command
                  </label>
                  <select
                    value={selectedAction}
                    onChange={(e) => {
                      const action = e.target.value;
                      setSelectedAction(action);
                      const requiredTier = COMMAND_TIERS[action];
                      if (requiredTier) setSelectedTier(requiredTier);
                    }}
                    className="sd-input w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2.5 text-[13px] text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                  >
                    <option value="take_safety_snapshot">
                      take_safety_snapshot — Capture routing + process baseline [Tier 1 Auto]
                    </option>
                    <option value="block_ip">
                      block_ip — Block specific IP address via local firewall [Tier 1 Auto]
                    </option>
                    <option value="isolate_host">
                      isolate_host — Quarantine network interface [Tier 2 Gated]
                    </option>
                    <option value="restore_host">
                      restore_host — Restore network routing [Tier 2 Gated]
                    </option>
                    <option value="kill_process">
                      kill_process — Terminate suspicious executable [Tier 2 Gated]
                    </option>
                    <option value="rollback_snapshot">
                      rollback_snapshot — Revert host to safety snapshot [Tier 2 Gated]
                    </option>
                    <option value="custom">
                      custom — Run custom endpoint instruction
                    </option>
                  </select>
                </div>

                {selectedAction === "block_ip" && (
                  <div className="space-y-2 p-3.5 rounded-xl bg-[var(--sd-panel-raised)]/80 border border-[var(--sd-border)]">
                    <div className="flex items-center justify-between">
                      <label className="text-[11px] font-medium text-[var(--sd-pine)] flex items-center gap-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                        Target IP Address to Block <span className="text-red-400">*</span>
                      </label>
                      {selectedAgent.ip_address && (
                        <button
                          type="button"
                          onClick={() => setTargetIp(selectedAgent.ip_address)}
                          className="text-[10px] font-mono text-[var(--sd-pine)] hover:underline opacity-80 cursor-pointer"
                        >
                          Fill Host IP ({selectedAgent.ip_address})
                        </button>
                      )}
                    </div>
                    <input
                      type="text"
                      placeholder="Enter target IP, e.g. 203.0.113.15 or 10.0.0.1"
                      value={targetIp}
                      onChange={(e) => setTargetIp(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-panel)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                      autoFocus
                    />
                    <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-muted)] pt-0.5">
                      <span>Command to dispatch:</span>
                      <code className="text-emerald-400 font-mono text-[11px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                        block_ip {targetIp.trim() || "<ip-address>"}
                      </code>
                    </div>
                  </div>
                )}

                {selectedAction === "kill_process" && (
                  <div className="space-y-2 p-3.5 rounded-xl bg-[var(--sd-panel-raised)]/80 border border-[var(--sd-border)]">
                    <label className="text-[11px] font-medium text-[var(--sd-pine)] block">
                      Target Process ID (PID) <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 1240 or 4096"
                      value={targetPid}
                      onChange={(e) => setTargetPid(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-panel)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    />
                    <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-muted)] pt-0.5">
                      <span>Command to dispatch:</span>
                      <code className="text-emerald-400 font-mono text-[11px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                        kill_process {targetPid.trim() || "<pid>"}
                      </code>
                    </div>
                  </div>
                )}

                {selectedAction === "custom" && (
                  <div className="space-y-2 p-3.5 rounded-xl bg-[var(--sd-panel-raised)]/80 border border-[var(--sd-border)]">
                    <label className="text-[11px] font-medium text-[var(--sd-pine)] block">
                      Custom Instruction <span className="text-red-400">*</span>
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. block_ip 10.0.0.5 or flush_routing"
                      value={customCommand}
                      onChange={(e) => setCustomCommand(e.target.value)}
                      className="sd-input w-full bg-[var(--sd-panel)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-medium text-[var(--sd-pine)] block mb-1">
                      Autonomy Tier
                    </label>
                    <select
                      value={selectedTier}
                      onChange={(e) =>
                        setSelectedTier(e.target.value as "Tier 1" | "Tier 2")
                      }
                      className="sd-input w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2.5 text-[13px] text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    >
                      <option value="Tier 1">Tier 1 (Automatic Action)</option>
                      <option value="Tier 2">Tier 2 (Requires Approval Token)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-medium text-[var(--sd-pine)] block mb-1">
                      Approval Token ID{" "}
                      {selectedTier === "Tier 2" && (
                        <span className="text-[var(--sd-warning)]">*</span>
                      )}
                    </label>
                    <input
                      type="text"
                      placeholder={
                        selectedTier === "Tier 2"
                          ? "Auto-signed or enter token ID"
                          : "N/A (Tier 1)"
                      }
                      value={tokenIdInput}
                      onChange={(e) => setTokenIdInput(e.target.value)}
                      disabled={selectedTier === "Tier 1"}
                      className="sd-input w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono disabled:opacity-40"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isExecuting || killSwitchEngaged}
                  className="sd-button sd-button-primary w-full py-2.5 px-4 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition flex items-center justify-center gap-2 shadow-xs cursor-pointer disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-current text-[var(--sd-on-accent)]" />
                  <span>
                    {isExecuting ? "Executing Instruction..." : "Dispatch Instruction to Agent"}
                  </span>
                </button>
              </form>
            </div>

            {/* Real-time Command Log Audit Trail */}
            <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <h3 className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                    Agent Instruction Audit Trail
                  </h3>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[var(--sd-panel-raised)] text-[var(--sd-wheat)] border border-[var(--sd-border)]">
                    {filteredLogs.length} Records
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() =>
                      setFilterAgentId((prev) =>
                        prev === "all" ? selectedAgent.id : "all"
                      )
                    }
                    className="text-[11px] font-mono text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] transition underline cursor-pointer"
                  >
                    {filterAgentId === "all" ? "Filter: This Host" : "Show All Hosts"}
                  </button>
                  {commandLogs.length > 0 && (
                    <button
                      onClick={handleClearLogs}
                      className="text-[11px] font-mono text-red-400/80 hover:text-red-300 transition underline cursor-pointer"
                    >
                      Clear Logs
                    </button>
                  )}
                  <span className="text-[11px] text-[var(--sd-text-muted)] font-mono hidden sm:inline">
                    &bull; SHA-256 Chained
                  </span>
                </div>
              </div>

              <div className="space-y-2 flex-1 overflow-y-auto max-h-[300px] pr-1">
                {filteredLogs.length === 0 ? (
                  <div className="h-48 flex flex-col items-center justify-center text-center p-4 border border-dashed border-[var(--sd-border)] rounded-xl text-[var(--sd-text-muted)] font-mono text-[12px] space-y-2">
                    <Terminal className="h-6 w-6 opacity-40 text-[var(--sd-wheat)]" />
                    <span>No instructions recorded yet.</span>
                    <span className="text-[11px] text-[var(--sd-text-dim)]">
                      Dispatch any command above to trigger live agent execution.
                    </span>
                  </div>
                ) : (
                  filteredLogs.map((log) => (
                    <div
                      key={log.id}
                      className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] font-mono text-[13px] space-y-1 hover:border-[var(--sd-border-strong)] transition"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-[var(--sd-pine)]">
                          {log.command}
                        </span>
                        <span
                          className={cn(
                            "text-[11px] uppercase font-medium px-2 py-0.5 rounded border",
                            log.status === "succeeded" &&
                              "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
                            log.status === "failed" &&
                              "text-red-400 border-red-500/30 bg-red-500/10",
                            log.status === "executing" &&
                              "text-amber-400 border-amber-500/30 bg-amber-500/10 animate-pulse"
                          )}
                        >
                          {log.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-[var(--sd-text-muted)] line-clamp-2">
                        {log.output}
                      </div>
                      <div className="text-[10px] text-[var(--sd-text-dim)] flex items-center justify-between pt-1 border-t border-[var(--sd-border)]/30">
                        <span className="text-[var(--sd-wheat)]">{log.tier}</span>
                        <span>{log.time}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

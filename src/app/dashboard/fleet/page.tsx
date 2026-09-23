"use client";

import React, { useState, useEffect } from "react";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

interface CommandLogEntry {
  id: string;
  time: string;
  command: string;
  tier: string;
  status: "succeeded" | "failed" | "executing";
  output: string;
}

export default function FleetPage() {
  const { activeUserId } = useChat();

  const [agents, setAgents] = useState<EndpointAgentRecord[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgentRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [commandInput, setCommandInput] = useState("take_safety_snapshot");
  const [selectedTier, setSelectedTier] = useState<"Tier 1" | "Tier 2">("Tier 1");
  const [tokenIdInput, setTokenIdInput] = useState("");
  const [commandLogs, setCommandLogs] = useState<CommandLogEntry[]>([
    {
      id: "init-1",
      time: new Date(Date.now() - 3600000).toLocaleTimeString(),
      command: "take_safety_snapshot",
      tier: "Tier 1",
      status: "succeeded",
      output: "Safety snapshot captured: routing table + process tree baseline stored.",
    },
  ]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [killSwitchEngaged, setKillSwitchEngaged] = useState(false);

  const fetchFleet = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/fleet", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (data.agents) {
        setAgents(data.agents);
        if (!selectedAgent && data.agents.length > 0) {
          setSelectedAgent(data.agents[0]);
        } else if (selectedAgent) {
          const updated = data.agents.find((a: EndpointAgentRecord) => a.id === selectedAgent.id);
          if (updated) setSelectedAgent(updated);
        }
        const anyKilled = data.agents.some((a: EndpointAgentRecord) => a.kill_switch_active);
        setKillSwitchEngaged(anyKilled);
      }
    } catch (err) {
      console.error("Failed to load fleet:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFleet();
  }, [activeUserId]);

  const handleToggleKillSwitch = async () => {
    const nextState = !killSwitchEngaged;
    const confirmText = nextState
      ? "EMERGENCY: Are you sure you want to engage the Emergency Kill Switch? All endpoint agents will be severed and revoked immediately."
      : "Restore endpoint agent connectivity?";
    if (!confirm(confirmText)) return;

    try {
      const res = await fetch("/api/fleet/kill-switch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ enable: nextState }),
      });
      const data = await res.json();
      if (res.ok) {
        setKillSwitchEngaged(data.killSwitchActive);
        fetchFleet();
      } else {
        alert(data.error || "Action failed");
      }
    } catch {
      alert("Network error toggling kill switch");
    }
  };

  const handleExecuteCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent || isExecuting) return;

    setIsExecuting(true);
    const newLogId = crypto.randomUUID();
    const newLog: CommandLogEntry = {
      id: newLogId,
      time: new Date().toLocaleTimeString(),
      command: commandInput,
      tier: selectedTier,
      status: "executing",
      output: `Dispatching ${selectedTier} instruction to ${selectedAgent.hostname}...`,
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
          command: commandInput,
          tier: selectedTier,
          approvalTokenId: selectedTier === "Tier 2" ? tokenIdInput || undefined : undefined,
        }),
      });

      const data = await res.json();

      setCommandLogs((prev) =>
        prev.map((log) => {
          if (log.id !== newLogId) return log;
          if (res.ok) {
            return {
              ...log,
              status: "succeeded",
              output: data.output || "Instruction executed with status SUCCESS. Telemetry updated.",
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

      fetchFleet();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network failure";
      setCommandLogs((prev) =>
        prev.map((log) => (log.id === newLogId ? { ...log, status: "failed", output: msg } : log))
      );
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-6">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs">
                <Server className="h-4.5 w-4.5" />
              </div>
              <h1 className="text-xl font-bold tracking-tight text-[var(--sd-pine)]">
                Universal Endpoint Fleet & Live Command
              </h1>
              <span className="rounded-md bg-white border border-[var(--sd-border)] px-2.5 py-0.5 text-[11px] font-semibold text-[var(--sd-pine)] font-mono shadow-xs">
                {agents.length} Enrolled Hosts
              </span>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              Low-overhead Cross-Platform Endpoint Agent Fleet (Windows, Linux, macOS) with Real-Time Telemetry
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchFleet}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-pine)] transition cursor-pointer shadow-xs"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin text-[var(--sd-pine)]")} />
              <span>Refresh Fleet</span>
            </button>

            {/* Emergency Admin Kill Switch */}
            <button
              onClick={handleToggleKillSwitch}
              className={cn(
                "flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition cursor-pointer border shadow-xs",
                killSwitchEngaged
                  ? "bg-[var(--sd-success)] text-white border-[var(--sd-success-border)]"
                  : "bg-[var(--sd-danger)] text-white border-[var(--sd-danger-border)] hover:bg-[#b91c1c]"
              )}
            >
              <PowerOff className="h-3.5 w-3.5" />
              <span>{killSwitchEngaged ? "Disengage Kill Switch (Restore)" : "Emergency Kill Switch"}</span>
            </button>
          </div>
        </div>

        {/* Fleet KPI Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-semibold">Active Endpoints</span>
              <div className="text-2xl font-bold font-mono text-[var(--sd-pine)] mt-1">
                {agents.filter((a) => a.status === "connected").length} / {agents.length}
              </div>
            </div>
            <Server className="h-6 w-6 text-[var(--sd-pine)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-semibold">Aggregate Telemetry</span>
              <div className="text-2xl font-bold font-mono text-[var(--sd-pine)] mt-1">
                {agents.reduce((acc, a) => acc + (a.eps || 0), 0)} <span className="text-xs font-normal text-[var(--sd-text-muted)]">EPS</span>
              </div>
            </div>
            <Activity className="h-6 w-6 text-[var(--sd-pine)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-semibold">Safety Baselines Active</span>
              <div className="text-2xl font-bold font-mono text-[var(--sd-success)] mt-1">
                {agents.filter((a) => a.safety_snapshot_id).length}
              </div>
            </div>
            <ShieldAlert className="h-6 w-6 text-[var(--sd-success)] opacity-70" />
          </div>

          <div className="p-4 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs flex items-center justify-between">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-semibold">Kill Switch Status</span>
              <div className={cn("text-xs font-bold font-mono mt-2 uppercase tracking-wider", killSwitchEngaged ? "text-[var(--sd-danger)]" : "text-[var(--sd-success)]")}>
                {killSwitchEngaged ? "ACTIVE (Fleet Severed)" : "NOMINAL (Listening)"}
              </div>
            </div>
            <PowerOff className={cn("h-6 w-6 opacity-70", killSwitchEngaged ? "text-[var(--sd-danger)]" : "text-[var(--sd-success)]")} />
          </div>
        </div>

        {/* Agent Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {agents.map((agent) => {
            const isSelected = selectedAgent?.id === agent.id;
            return (
              <div
                key={agent.id}
                onClick={() => setSelectedAgent(agent)}
                className={cn(
                  "p-4 rounded-2xl border transition-all cursor-pointer space-y-3",
                  isSelected
                    ? "border-[var(--sd-pine)] bg-[var(--sd-bg-alt)]/50 shadow-xs ring-1 ring-[var(--sd-pine)]/20"
                    : "border-[var(--sd-border)] bg-white hover:border-[var(--sd-border-strong)] hover:bg-[var(--sd-panel-hover)]/40 shadow-xs"
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={cn("h-2 w-2 rounded-full", agent.status === "connected" ? "bg-[var(--sd-success)]" : "bg-[var(--sd-danger)]")} />
                    <span className="font-mono font-bold text-xs text-[var(--sd-pine)]">{agent.hostname}</span>
                  </div>
                  <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] border border-[var(--sd-border)] font-medium">
                    {agent.os_type}
                  </span>
                </div>

                <div className="space-y-1.5 text-[11px] text-[var(--sd-text-muted)] font-mono">
                  <div className="flex justify-between">
                    <span>IP Address:</span>
                    <span className="text-[var(--sd-text)] font-semibold">{agent.ip_address}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Agent Version:</span>
                    <span className="text-[var(--sd-text)]">v{agent.agent_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Events/sec:</span>
                    <span className="text-[var(--sd-pine)] font-semibold">{agent.eps} EPS</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-[var(--sd-border)] space-y-2 text-[10px]">
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-[var(--sd-text-muted)]">CPU Usage</span>
                      <span className="font-mono text-[var(--sd-text)] font-semibold">{agent.cpu_usage}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden">
                      <div className="h-full bg-[var(--sd-pine)] rounded-full" style={{ width: `${agent.cpu_usage}%` }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-[var(--sd-text-muted)]">Memory Usage</span>
                      <span className="font-mono text-[var(--sd-text)] font-semibold">{agent.memory_usage}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden">
                      <div className="h-full bg-[var(--sd-pine)]/60 rounded-full" style={{ width: `${agent.memory_usage}%` }} />
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Live Command Console + Execution Audit Trail */}
        {selectedAgent && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Terminal Command Dispatcher */}
            <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-[var(--sd-pine)]" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                    Live Instruction Console: {selectedAgent.hostname}
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                  OS: {selectedAgent.os_type} &bull; v{selectedAgent.agent_version}
                </span>
              </div>

              <form onSubmit={handleExecuteCommand} className="space-y-4 text-xs">
                <div>
                  <label className="text-[11px] font-semibold text-[var(--sd-pine)] block mb-1">
                    Select Endpoint Command
                  </label>
                  <select
                    value={commandInput}
                    onChange={(e) => setCommandInput(e.target.value)}
                    className="w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2.5 text-xs text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                  >
                    <option value="take_safety_snapshot">take_safety_snapshot (Capture routing + process tree baseline)</option>
                    <option value="isolate_host">isolate_host (Quarantine network interface - Tier 2 Gated)</option>
                    <option value="restore_host">restore_host (Restore network routing - Tier 2 Gated)</option>
                    <option value="block_ip">block_ip (Block suspicious C2 IP address - Tier 1 Auto)</option>
                    <option value="terminate_process">terminate_process (Kill suspicious executable - Tier 2 Gated)</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-semibold text-[var(--sd-pine)] block mb-1">
                      Autonomy Tier
                    </label>
                    <select
                      value={selectedTier}
                      onChange={(e) => setSelectedTier(e.target.value as "Tier 1" | "Tier 2")}
                      className="w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2.5 text-xs text-[var(--sd-text)] focus:outline-none focus:border-[var(--sd-pine)] font-mono"
                    >
                      <option value="Tier 1">Tier 1 (Automatic Action)</option>
                      <option value="Tier 2">Tier 2 (Requires Approval Token)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-semibold text-[var(--sd-pine)] block mb-1">
                      Approval Token ID {selectedTier === "Tier 2" && <span className="text-[var(--sd-warning)]">*</span>}
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. tok11111-..."
                      value={tokenIdInput}
                      onChange={(e) => setTokenIdInput(e.target.value)}
                      disabled={selectedTier === "Tier 1"}
                      className="w-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] rounded-xl px-3.5 py-2 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] font-mono disabled:opacity-40"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isExecuting || killSwitchEngaged}
                  className="w-full py-2.5 px-4 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[#f7f4ed] text-xs font-semibold transition flex items-center justify-center gap-2 shadow-xs cursor-pointer disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-current text-[#e6dbbf]" />
                  <span>{isExecuting ? "Executing Instruction..." : "Dispatch Instruction to Agent"}</span>
                </button>
              </form>
            </div>

            {/* Real-time Command Log */}
            <div className="rounded-2xl border border-[var(--sd-border)] bg-white p-5 shadow-xs flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Agent Instruction Audit Trail
                </h3>
                <span className="text-[10px] text-[var(--sd-text-muted)] font-mono">Immutable SHA-256 Chained</span>
              </div>

              <div className="space-y-2 flex-1 overflow-y-auto max-h-[300px]">
                {commandLogs.map((log) => (
                  <div
                    key={log.id}
                    className="p-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] font-mono text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[var(--sd-pine)]">{log.command}</span>
                      <span className={cn(
                        "text-[10px] uppercase font-bold",
                        log.status === "succeeded" && "text-[var(--sd-success)]",
                        log.status === "failed" && "text-[var(--sd-danger)]",
                        log.status === "executing" && "text-[var(--sd-warning)] animate-pulse"
                      )}>
                        {log.status}
                      </span>
                    </div>
                    <div className="text-[10.5px] text-[var(--sd-text-muted)]">{log.output}</div>
                    <div className="text-[9.5px] text-[var(--sd-text-muted)] flex items-center justify-between pt-1">
                      <span>{log.tier}</span>
                      <span>{log.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

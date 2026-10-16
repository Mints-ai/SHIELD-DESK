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
  Plus,
  MonitorDot,
  ExternalLink,
  Trash2,
  Unplug,
  WifiOff,
  AlertCircle,
  ShieldCheck,
  Eye,
  Network,
  Sliders,
  Key,
  X,
  Shield,
  Zap,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { validateIpAddress } from "@/lib/utils/ipValidation";
import { CORE_FUNCTION_SCOPES, type CoreFunctionScope } from "@/lib/fleet/monitoringTypes";
import { ConnectEndpointModal } from "@/components/fleet/ConnectEndpointModal";

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

// Maps each command value to its required autonomy tier
const COMMAND_TIERS: Record<string, "Tier 1" | "Tier 2"> = {
  take_safety_snapshot: "Tier 1",
  block_ip: "Tier 1",
  unblock_ip: "Tier 1",
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

  // Connect endpoint modal state
  const [showConnectModal, setShowConnectModal] = useState(false);

  // Governed Core Function Monitoring state
  const [activeConsoleTab, setActiveConsoleTab] = useState<"console" | "monitoring">("console");
  const [monitoringPolicy, setMonitoringPolicy] = useState<{
    enabled_scopes: CoreFunctionScope[];
    approved_by: string;
    approved_at: string;
    approval_token_id?: string | null;
    policy_hash: string;
    status: string;
  } | null>(null);
  const [monitoringData, setMonitoringData] = useState<any>(null);
  const [monitoringLoading, setMonitoringLoading] = useState(false);
  const [requestedScopes, setRequestedScopes] = useState<CoreFunctionScope[]>(["system_performance"]);
  const [hasUserModifiedScopes, setHasUserModifiedScopes] = useState(false);
  const [monitoringTokenId, setMonitoringTokenId] = useState("");
  const [monitoringFeedback, setMonitoringFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [monitoringLastFetchedAt, setMonitoringLastFetchedAt] = useState<Date | null>(null);
  const [processSearchQuery, setProcessSearchQuery] = useState("");

  // Endpoint Firewall Authority & Management State
  const [showFwModal, setShowFwModal] = useState(false);
  const [fwActionLoading, setFwActionLoading] = useState(false);
  const [fwFeedback, setFwFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [fwRuleName, setFwRuleName] = useState("");
  const [fwRuleDir, setFwRuleDir] = useState<"in" | "out">("in");
  const [fwRuleAction, setFwRuleAction] = useState<"block" | "allow">("block");
  const [fwRuleProto, setFwRuleProto] = useState<"TCP" | "UDP" | "ANY">("TCP");
  const [fwRulePort, setFwRulePort] = useState("");
  const [fwRuleIp, setFwRuleIp] = useState("");
  const [fwRuleTokenId, setFwRuleTokenId] = useState("");

  // Microsoft Defender Authority & Remediation State
  const [showDefenderModal, setShowDefenderModal] = useState(false);
  const [defenderActionLoading, setDefenderActionLoading] = useState(false);
  const [defenderFeedback, setDefenderFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [defenderExclusionPath, setDefenderExclusionPath] = useState("");
  const [defenderTokenId, setDefenderTokenId] = useState("");
  const [defenderDetectionSearch, setDefenderDetectionSearch] = useState("");

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
        await fetchFleet(true);
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
    if (selectedAction === "block_ip" || selectedAction === "unblock_ip") {
      const cleanIp = targetIp.trim();
      if (!cleanIp) {
        setDispatchFeedback({
          type: "error",
          message: `Please specify an IP address to ${selectedAction === "unblock_ip" ? "unblock" : "block"} (e.g. 203.0.113.15 or 10.0.0.1).`,
        });
        return;
      }
      const val = validateIpAddress(cleanIp);
      if (!val.valid) {
        setDispatchFeedback({
          type: "error",
          message: val.error || "Invalid IP address format.",
        });
        return;
      }
      cmd = `${selectedAction} ${cleanIp}`;
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
        if (cmd.startsWith("block_ip")) {
          setSelectedAgent((prev) => (prev ? { ...prev, status: "disconnected", cpu_usage: 0, memory_usage: 0, eps: 0 } : null));
          setAgents((prev) =>
            prev.map((a) =>
              a.id === selectedAgent.id || a.ip_address === targetIp.trim()
                ? { ...a, status: "disconnected", cpu_usage: 0, memory_usage: 0, eps: 0 }
                : a
            )
          );
        } else if (cmd.startsWith("unblock_ip")) {
          setSelectedAgent((prev) => (prev ? { ...prev, status: "connected" } : null));
          setAgents((prev) =>
            prev.map((a) =>
              a.id === selectedAgent.id || a.ip_address === targetIp.trim()
                ? { ...a, status: "connected" }
                : a
            )
          );
        }
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
        await fetchFleet(true);
      } else {
        alert(data.error || "Failed to remove agent");
      }
    } catch {
      alert("Network error removing agent");
    }
  };

  const serverURL =
    typeof window !== "undefined"
      ? window.location.origin
      : "http://localhost:3000";

  const fetchMonitoring = useCallback(async (agentId: string, isSilent = false) => {
    try {
      if (!isSilent) setMonitoringLoading(true);
      const res = await fetch(`/api/fleet/${agentId}/monitoring`, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setMonitoringPolicy(data.policy);
        setMonitoringData(data.data);
        setMonitoringLastFetchedAt(new Date());
        // CRITICAL FIX: Only initialize requestedScopes on initial explicit agent load.
        // NEVER overwrite user's in-progress scope selections during the 3s silent background stream!
        if (!isSilent && data.policy?.enabled_scopes) {
          setRequestedScopes(data.policy.enabled_scopes);
          setHasUserModifiedScopes(false);
        }
      }
    } catch (err) {
      console.error("Failed to fetch monitoring data:", err);
    } finally {
      if (!isSilent) setMonitoringLoading(false);
    }
  }, [activeUserId]);

  useEffect(() => {
    if (selectedAgent && activeConsoleTab === "monitoring") {
      setHasUserModifiedScopes(false);
      fetchMonitoring(selectedAgent.id, false);
      const interval = setInterval(() => {
        fetchMonitoring(selectedAgent.id, true);
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [selectedAgent?.id, activeConsoleTab, fetchMonitoring]);

  const handleSaveMonitoringPolicy = async () => {
    if (!selectedAgent) return;
    setSavingPolicy(true);
    setMonitoringFeedback(null);
    try {
      const res = await fetch(`/api/fleet/${selectedAgent.id}/monitoring`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          requestedScopes,
          approvalTokenId: monitoringTokenId.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setMonitoringFeedback({
          type: "success",
          message: data.message || "Monitoring policy approved and enforced successfully.",
        });
        setHasUserModifiedScopes(false);
        if (data.policy?.enabled_scopes) {
          setRequestedScopes(data.policy.enabled_scopes);
          setMonitoringPolicy(data.policy);
        }
        fetchMonitoring(selectedAgent.id, true);
        fetchLogs();
      } else {
        setMonitoringFeedback({
          type: "error",
          message: data.error || "Failed to update monitoring policy.",
        });
      }
    } catch {
      setMonitoringFeedback({
        type: "error",
        message: "Network failure while updating monitoring policy.",
      });
    } finally {
      setSavingPolicy(false);
    }
  };

  // Firewall Authority & Dynamic Enforcement Handlers
  const handleFirewallAction = async (payload: Record<string, unknown>) => {
    if (!selectedAgent) return;
    setFwActionLoading(true);
    setFwFeedback(null);
    try {
      const res = await fetch(`/api/fleet/${selectedAgent.id}/firewall`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setFwFeedback({
          type: "success",
          message: data.message || "Firewall rule enforced successfully with snapshot protection.",
        });
        fetchMonitoring(selectedAgent.id, true);
        fetchLogs();
      } else {
        setFwFeedback({
          type: "error",
          message: data.error || "Failed to execute firewall action.",
        });
      }
    } catch {
      setFwFeedback({
        type: "error",
        message: "Network error communicating with endpoint firewall.",
      });
    } finally {
      setFwActionLoading(false);
    }
  };

  const handleCreateRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = fwRuleName.trim();
    if (!cleanName) {
      setFwFeedback({ type: "error", message: "Rule name is required." });
      return;
    }
    await handleFirewallAction({
      action: "add_rule",
      rule: {
        name: cleanName,
        direction: fwRuleDir,
        action: fwRuleAction,
        protocol: fwRuleProto,
        port: fwRulePort.trim() || undefined,
        remoteIp: fwRuleIp.trim() || undefined,
      },
      approvalTokenId: fwRuleTokenId.trim() || undefined,
    });
    setFwRuleName("");
    setFwRulePort("");
    setFwRuleIp("");
  };

  const handleDeleteRule = async (ruleName: string) => {
    if (!confirm(`Permanently remove firewall rule '${ruleName}' from ${selectedAgent?.hostname}?`)) return;
    await handleFirewallAction({
      action: "delete_rule",
      ruleName,
      approvalTokenId: fwRuleTokenId.trim() || undefined,
    });
  };

  const handleToggleProfile = async (profileName: string, currentState: string) => {
    const nextState = currentState === "ON" ? "off" : "on";
    await handleFirewallAction({
      action: "set_profile",
      profile: profileName.toLowerCase(),
      state: nextState,
      approvalTokenId: fwRuleTokenId.trim() || undefined,
    });
  };

  const handleToggleDefaultInbound = async (currentInbound: string) => {
    const nextIn = currentInbound === "BLOCK" ? "allow" : "block";
    const currentOut = monitoringData?.firewall_baseline?.baseline?.defaultOutbound || "ALLOW";
    await handleFirewallAction({
      action: "set_default",
      inbound: nextIn,
      outbound: currentOut.toLowerCase(),
      approvalTokenId: fwRuleTokenId.trim() || undefined,
    });
  };

  // Microsoft Defender Authority Handlers
  const handleDefenderAction = async (payload: Record<string, unknown>) => {
    if (!selectedAgent) return;
    setDefenderActionLoading(true);
    setDefenderFeedback(null);
    try {
      const res = await fetch(`/api/fleet/${selectedAgent.id}/defender`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setDefenderFeedback({
          type: "success",
          message: data.message || "Defender operation executed successfully.",
        });
        fetchMonitoring(selectedAgent.id, true);
        fetchLogs();
      } else {
        setDefenderFeedback({
          type: "error",
          message: data.error || "Failed to execute Defender operation.",
        });
      }
    } catch {
      setDefenderFeedback({
        type: "error",
        message: "Network error communicating with endpoint Defender agent.",
      });
    } finally {
      setDefenderActionLoading(false);
    }
  };

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
            {/* Connect Endpoints Button */}
            <button
              onClick={() => setShowConnectModal(true)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 rounded-full border text-[12px] font-medium transition cursor-pointer shadow-xs",
                showConnectModal
                  ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] border-[var(--sd-pine)]"
                  : "sd-surface border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)]"
              )}
              title="Connect a real endpoint to the ShieldDesk fleet"
            >
              <Plus className="h-3 w-3" />
              <span>Connect Endpoints</span>
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

        {/* ── Connect Endpoint Modal ── */}
        <ConnectEndpointModal
          isOpen={showConnectModal}
          onClose={() => setShowConnectModal(false)}
          activeUserId={activeUserId}
          serverUrl={serverURL}
          existingAgents={agents}
          onEndpointConnected={() => {
            fetchFleet(true);
            fetchLogs();
          }}
        />

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
                        Date.now() - new Date(a.last_heartbeat).getTime() <= 45000
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
                    Date.now() - new Date(a.last_heartbeat).getTime() <= 45000
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
              onClick={() => setShowConnectModal(true)}
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
              const isTimedOut = secondsAgo > 45;
              const isDisconnected = agent.status === "disconnected" || isTimedOut;
              const effectiveStatus = isDisconnected ? "disconnected" : agent.status;
              const isStale = !isDisconnected && secondsAgo > 25;

              const cleanIp =
                agent.ip_address && agent.ip_address !== "Unknown"
                  ? agent.ip_address
                  : "Unavailable";

              const cpuNum = isDisconnected || isStale ? 0 : Number(agent.cpu_usage || 0);
              const memNum = isDisconnected || isStale ? 0 : Number(agent.memory_usage || 0);
              const cpuVal = cpuNum.toFixed(1);
              const memVal = memNum.toFixed(1);
              const epsVal = isDisconnected || isStale ? 0 : Math.round(Number(agent.eps || 0));

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
                            cpuNum > 80
                              ? "bg-red-400"
                              : cpuNum > 50
                              ? "bg-amber-400"
                              : "bg-[var(--sd-pine)]"
                          )}
                          style={{
                            width: `${Math.min(100, Math.max(0, cpuNum))}%`,
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
                            memNum > 85 ? "bg-red-400" : "bg-[var(--sd-pine)]/70"
                          )}
                          style={{
                            width: `${Math.min(100, Math.max(0, memNum))}%`,
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

        {/* Live Command Console + Governed Monitoring Tabs */}
        {selectedAgent && (
          <div className="space-y-4">
            {/* Tab navigation */}
            <div className="flex items-center gap-3 border-b border-[var(--sd-border)] pb-3">
              <button
                type="button"
                onClick={() => setActiveConsoleTab("console")}
                className={cn(
                  "flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-mono font-medium transition cursor-pointer",
                  activeConsoleTab === "console"
                    ? "bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] border border-[var(--sd-border)] shadow-xs"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                )}
              >
                <Terminal className="h-4 w-4" />
                <span>Command Console &amp; Audit Trail</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveConsoleTab("monitoring")}
                className={cn(
                  "flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-mono font-medium transition cursor-pointer relative",
                  activeConsoleTab === "monitoring"
                    ? "bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] border border-[var(--sd-border)] shadow-xs"
                    : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                )}
              >
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <span>Endpoint Task Manager &amp; Live Telemetry</span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Authority Approved
                </span>
              </button>
            </div>

            {activeConsoleTab === "console" ? (
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
                    <option value="unblock_ip">
                      unblock_ip — Unblock IP address and restore connectivity [Tier 1 Auto]
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

                {(selectedAction === "block_ip" || selectedAction === "unblock_ip") && (() => {
                  const hasInput = targetIp.trim().length > 0;
                  const ipVal = hasInput ? validateIpAddress(targetIp.trim()) : null;
                  const isInvalid = ipVal && !ipVal.valid;
                  const isValid = ipVal && ipVal.valid;
                  const isUnblock = selectedAction === "unblock_ip";

                  return (
                    <div className="space-y-2 p-3.5 rounded-xl bg-[var(--sd-panel-raised)]/80 border border-[var(--sd-border)]">
                      <div className="flex items-center justify-between">
                        <label className="text-[11px] font-medium text-[var(--sd-pine)] flex items-center gap-1.5">
                          <ShieldAlert className={cn("h-3.5 w-3.5", isUnblock ? "text-emerald-400" : "text-amber-400")} />
                          Target IP Address to {isUnblock ? "Unblock" : "Block"} <span className="text-red-400">*</span>
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
                        placeholder="Enter valid IP, e.g. 203.0.113.15 or 10.0.0.1"
                        value={targetIp}
                        onChange={(e) => setTargetIp(e.target.value)}
                        className={cn(
                          "sd-input w-full bg-[var(--sd-panel)] border rounded-xl px-3.5 py-2 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none font-mono transition",
                          isInvalid
                            ? "border-red-500/60 focus:border-red-500 bg-red-500/5 text-red-200"
                            : isValid
                            ? "border-emerald-500/60 focus:border-emerald-500 bg-emerald-500/5 text-emerald-200"
                            : "border-[var(--sd-border)] focus:border-[var(--sd-pine)]"
                        )}
                        autoFocus
                      />
                      {isInvalid && (
                        <p className="text-[11px] text-red-400 font-mono flex items-start gap-1.5 pt-0.5">
                          <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5 text-red-400" />
                          <span>{ipVal.error}</span>
                        </p>
                      )}
                      {isValid && (
                        <p className="text-[11px] text-emerald-400 font-mono flex items-center gap-1.5 pt-0.5">
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                          <span>Valid {ipVal.isIpv6 ? "IPv6" : "IPv4"} Address{ipVal.isCidr ? " (CIDR Range)" : ""}</span>
                        </p>
                      )}
                      <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-muted)] pt-0.5">
                        <span>Command to dispatch:</span>
                        <code
                          className={cn(
                            "font-mono text-[11px] px-2 py-0.5 rounded border",
                            isInvalid
                              ? "text-red-400 bg-red-500/10 border-red-500/20"
                              : isValid
                              ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                              : "text-[var(--sd-text-dim)] bg-[var(--sd-panel)] border-[var(--sd-border)]"
                          )}
                        >
                          {selectedAction} {targetIp.trim() || "<ip-address>"}
                        </code>
                      </div>
                    </div>
                  );
                })()}

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
                  disabled={
                    isExecuting ||
                    killSwitchEngaged ||
                    ((selectedAction === "block_ip" || selectedAction === "unblock_ip") && (!targetIp.trim() || !validateIpAddress(targetIp.trim()).valid)) ||
                    (selectedAction === "kill_process" && !targetPid.trim())
                  }
                  className="sd-button sd-button-primary w-full py-2.5 px-4 rounded-full text-[var(--sd-on-accent)] text-[13px] font-medium transition flex items-center justify-center gap-2 shadow-xs cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
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
        ) : (
          <div className="space-y-6">
                {/* Header Banner */}
                <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-emerald-400" />
                        <h2 className="text-base font-semibold text-[var(--sd-text)]">
                          Core Function Monitoring Governance: {selectedAgent.hostname}
                        </h2>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          {monitoringPolicy?.approved_by ? `Signed by: ${monitoringPolicy.approved_by}` : "Tier 2 Governed"}
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--sd-text-muted)]">
                        Specify exactly which endpoint core functions are monitored. Enabling gated functions requires explicit security authority approval.
                      </p>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] font-mono">
                      <div className="px-3 py-1.5 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text-muted)]">
                        <span className="text-[var(--sd-pine)]">Overhead:</span> &lt; 0.1% CPU &bull; &lt; 25MB RAM
                      </div>
                      <div className="px-3 py-1.5 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text-muted)] truncate max-w-xs" title={monitoringPolicy?.policy_hash}>
                        <span className="text-[var(--sd-wheat)]">Policy Hash:</span> {monitoringPolicy?.policy_hash ? monitoringPolicy.policy_hash.slice(0, 16) + "..." : "sha256-pending"}
                      </div>
                    </div>
                  </div>

                  {monitoringFeedback && (
                    <div
                      className={cn(
                        "p-3 rounded-xl border text-[12px] font-mono flex items-start gap-2",
                        monitoringFeedback.type === "success"
                          ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                          : "bg-red-500/10 border-red-500/30 text-red-300"
                      )}
                    >
                      {monitoringFeedback.type === "success" ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                      )}
                      <span>{monitoringFeedback.message}</span>
                    </div>
                  )}

                  {/* Scopes Grid Header & Quick Select */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                    <span className="text-[12px] font-mono text-[var(--sd-text-dim)]">
                      Endpoint Core Functions Scope Matrix:
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setHasUserModifiedScopes(true);
                        const allScopes = Object.keys(CORE_FUNCTION_SCOPES) as CoreFunctionScope[];
                        const areAllSelected = allScopes.every((s) => requestedScopes.includes(s));
                        if (areAllSelected) {
                          setRequestedScopes(["system_performance"]);
                        } else {
                          setRequestedScopes(allScopes);
                        }
                      }}
                      className="text-[11px] font-mono px-3 py-1 rounded-lg border border-[var(--sd-border)] hover:border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition cursor-pointer flex items-center gap-1.5"
                    >
                      <Sliders className="h-3 w-3" />
                      <span>
                        {(Object.keys(CORE_FUNCTION_SCOPES) as CoreFunctionScope[]).every((s) => requestedScopes.includes(s))
                          ? "Deselect Gated Scopes"
                          : "Activate / Select All Core Functions"}
                      </span>
                    </button>
                  </div>

                  {/* Scopes Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {(Object.keys(CORE_FUNCTION_SCOPES) as CoreFunctionScope[]).map((scopeKey) => {
                      const def = CORE_FUNCTION_SCOPES[scopeKey];
                      const isChecked = requestedScopes.includes(scopeKey);
                      const isCurrentlyActive = monitoringPolicy?.enabled_scopes?.includes(scopeKey);
                      const isDefaultAlwaysOn = !def.requiresApproval;

                      return (
                        <div
                          key={scopeKey}
                          onClick={() => {
                            if (isDefaultAlwaysOn) return;
                            setHasUserModifiedScopes(true);
                            setRequestedScopes((prev) =>
                              prev.includes(scopeKey)
                                ? prev.filter((s) => s !== scopeKey)
                                : [...prev, scopeKey]
                            );
                          }}
                          className={cn(
                            "p-4 rounded-xl border transition cursor-pointer flex flex-col justify-between space-y-3",
                            isChecked
                              ? "bg-[var(--sd-panel-raised)] border-[var(--sd-pine)]/60 shadow-xs"
                              : "bg-[var(--sd-panel)] border-[var(--sd-border)] opacity-70 hover:opacity-100"
                          )}
                        >
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="text-[12px] font-semibold text-[var(--sd-text)] flex items-center gap-1.5">
                                <input
                                  type="checkbox"
                                  checked={isChecked}
                                  disabled={isDefaultAlwaysOn}
                                  onClick={(e) => e.stopPropagation()}
                                  onChange={(e) => {
                                    e.stopPropagation();
                                    if (isDefaultAlwaysOn) return;
                                    setHasUserModifiedScopes(true);
                                    setRequestedScopes((prev) =>
                                      prev.includes(scopeKey)
                                        ? prev.filter((s) => s !== scopeKey)
                                        : [...prev, scopeKey]
                                    );
                                  }}
                                  className="accent-[var(--sd-pine)] rounded h-3.5 w-3.5 cursor-pointer"
                                />
                                {def.label}
                              </span>
                              <span
                                className={cn(
                                  "text-[10px] font-mono px-2 py-0.5 rounded-full border",
                                  isCurrentlyActive
                                    ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                                    : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                                )}
                              >
                                {isCurrentlyActive ? "ACTIVE" : "GATED"}
                              </span>
                            </div>
                            <p className="text-[11px] text-[var(--sd-text-muted)] leading-relaxed">
                              {def.description}
                            </p>
                          </div>

                          <div className="flex items-center justify-between text-[10px] font-mono text-[var(--sd-text-dim)] pt-2 border-t border-[var(--sd-border)]/50">
                            <span>Cost: {def.resourceCost}</span>
                            <span>{def.tier} {def.requiresApproval ? "(Approval Req.)" : "(Auto)"}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Authority Approval & Save Action Bar */}
                  <div className="pt-4 border-t border-[var(--sd-border)] flex flex-wrap items-center justify-between gap-4">
                    <div className="flex flex-wrap items-center gap-3">
                      <label className="text-[11px] font-medium text-[var(--sd-pine)] font-mono flex items-center gap-1.5">
                        <Key className="h-3.5 w-3.5 text-amber-400" />
                        Authority Approval Token:
                      </label>
                      <input
                        type="text"
                        placeholder="Auto-signed as SecOps Admin or enter token ID"
                        value={monitoringTokenId}
                        onChange={(e) => setMonitoringTokenId(e.target.value)}
                        className="sd-input bg-[var(--sd-panel)] border border-[var(--sd-border)] rounded-xl px-3 py-1.5 text-[12px] font-mono text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)] w-72"
                      />
                    </div>

                    <button
                      type="button"
                      disabled={savingPolicy}
                      onClick={handleSaveMonitoringPolicy}
                      className="sd-button sd-button-primary py-2 px-5 rounded-full text-[var(--sd-on-accent)] text-[12px] font-medium transition flex items-center gap-2 cursor-pointer disabled:opacity-50"
                    >
                      <ShieldCheck className="h-4 w-4" />
                      <span>{savingPolicy ? "Enforcing Policy..." : "Enforce & Sign Monitoring Policy"}</span>
                    </button>
                  </div>
                </div>

                {/* Live Core Functions Monitored Data Inspector */}
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h3 className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono flex items-center gap-2">
                      <Eye className="h-4 w-4" />
                      Endpoint Task Manager, Security Subsystems &amp; Live Telemetry
                    </h3>
                    <div className="flex items-center gap-3 text-[11px] font-mono">
                      {selectedAgent?.status === "connected" ? (
                        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px]">
                          <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                          </span>
                          <span>LIVE STREAMING (3s)</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-zinc-500/10 border border-zinc-500/30 text-zinc-400 text-[10px]">
                          <span className="h-2 w-2 rounded-full bg-zinc-500"></span>
                          <span>OFFLINE / PAUSED</span>
                        </div>
                      )}
                      {monitoringLastFetchedAt && (
                        <span className="text-[var(--sd-text-dim)] hidden sm:inline">
                          Sampled: {monitoringLastFetchedAt.toLocaleTimeString()}
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => selectedAgent && fetchMonitoring(selectedAgent.id)}
                        disabled={monitoringLoading}
                        className="px-2.5 py-1 rounded-lg border border-[var(--sd-border)] hover:border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                      >
                        <RefreshCw className={cn("h-3 w-3", monitoringLoading && "animate-spin")} />
                        <span>Refresh Live Data</span>
                      </button>
                    </div>
                  </div>

                  {selectedAgent?.status === "disconnected" && (
                    <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[12px] font-mono flex items-center gap-2">
                      <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
                      <span>Endpoint is currently offline. Real-time telemetry is paused until the endpoint daemon reconnects.</span>
                    </div>
                  )}

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* 1. System Performance & Resources */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Activity className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            System Resources &amp; Hardware Telemetry
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                          {monitoringData?.system_performance?.enabled ? "MONITORED" : "EXCLUDED"}
                        </span>
                      </div>

                      {monitoringData?.system_performance?.enabled && monitoringData.system_performance.metrics ? (
                        <div className="space-y-2 text-[12px] font-mono">
                          <div className="flex justify-between py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">Host CPU Processor:</span>
                            <span className="text-emerald-400 truncate max-w-xs" title={monitoringData.system_performance.metrics.cpuModel}>
                              {monitoringData.system_performance.metrics.cpuModel || "Host Processor"}
                              {!monitoringData.system_performance.metrics.cpuModel?.toLowerCase().includes("core") &&
                                ` (${monitoringData.system_performance.metrics.cpuCores} Cores)`}
                            </span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">Physical RAM Memory:</span>
                            <span className="text-[var(--sd-text)]">
                              {monitoringData.system_performance.metrics.memoryUsedGb} GB / {monitoringData.system_performance.metrics.memoryTotalGb} GB ({monitoringData.system_performance.metrics.memoryPct}%)
                            </span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">System Uptime &amp; Load:</span>
                            <span className="text-[var(--sd-text)]">
                              {monitoringData.system_performance.metrics.uptimeHours} hrs &bull; Load [{monitoringData.system_performance.metrics.load_average}]
                            </span>
                          </div>
                          <div className="flex justify-between py-1">
                            <span className="text-[var(--sd-text-dim)]">Active Threads &amp; Sampling Overhead:</span>
                            <span className="text-emerald-400 font-semibold">
                              {monitoringData.system_performance.metrics.threads_active} processes &bull; {monitoringData.system_performance.metrics.sampling_overhead}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 System Performance Disabled by Policy</p>
                        </div>
                      )}
                    </div>

                    {/* 2. Network Sockets Inspector */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Network className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            Active Network Sockets &amp; Connections
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                          {monitoringData?.network_sockets?.enabled ? "MONITORED" : "EXCLUDED"}
                        </span>
                      </div>

                      {monitoringData?.network_sockets?.enabled ? (
                        <div className="overflow-x-auto max-h-60">
                          <table className="w-full text-left text-[11px] font-mono">
                            <thead>
                              <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-dim)] sticky top-0 bg-[var(--sd-panel)]">
                                <th className="py-1">Proto</th>
                                <th className="py-1">Local Address</th>
                                <th className="py-1">Remote</th>
                                <th className="py-1">State</th>
                                <th className="py-1">Process</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[var(--sd-border)]/40">
                              {monitoringData.network_sockets.sockets?.map((s: any, idx: number) => (
                                <tr key={idx} className="hover:bg-[var(--sd-panel-raised)]/50">
                                  <td className="py-1 text-emerald-400">{s.proto}</td>
                                  <td className="py-1 text-[var(--sd-text)]">{s.local}</td>
                                  <td className="py-1 text-[var(--sd-text-muted)]">{s.remote}</td>
                                  <td className="py-1 text-amber-300 font-semibold">{s.state}</td>
                                  <td className="py-1 text-[var(--sd-text-dim)] truncate max-w-[120px]">{s.process}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Socket Monitoring Disabled by Policy</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to capture active network socket connections.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* 3. Process Inventory Inspector & Task Manager */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Cpu className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            Windows Task Manager &amp; Process Inventory
                          </h4>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            {monitoringData?.system_performance?.metrics?.threads_active || monitoringData?.process_inventory?.processes?.length || 0} Tasks Active
                          </span>
                          <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                            {monitoringData?.process_inventory?.enabled ? "MONITORED" : "EXCLUDED"}
                          </span>
                        </div>
                      </div>

                      {monitoringData?.process_inventory?.enabled ? (
                        <>
                          {/* Search bar inside Task Manager */}
                          <div className="flex items-center gap-2">
                            <Search className="h-3.5 w-3.5 text-[var(--sd-text-dim)] shrink-0" />
                            <input
                              type="text"
                              placeholder="Search running tasks by name or PID (e.g. chrome, node, 5432)..."
                              value={processSearchQuery}
                              onChange={(e) => setProcessSearchQuery(e.target.value)}
                              className="sd-input w-full bg-[var(--sd-panel)] border border-[var(--sd-border)] rounded-lg px-2.5 py-1 text-[11px] font-mono text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-none focus:border-[var(--sd-pine)]"
                            />
                            {processSearchQuery && (
                              <button
                                type="button"
                                onClick={() => setProcessSearchQuery("")}
                                className="text-[10px] font-mono text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] px-1.5 py-0.5 rounded border border-[var(--sd-border)] cursor-pointer"
                              >
                                Clear
                              </button>
                            )}
                          </div>

                          <div className="overflow-x-auto max-h-72">
                            <table className="w-full text-left text-[11px] font-mono">
                              <thead>
                                <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-dim)] sticky top-0 bg-[var(--sd-panel)]">
                                  <th className="py-1">PID</th>
                                  <th className="py-1">Executable Name</th>
                                  <th className="py-1">RAM</th>
                                  <th className="py-1">Protection</th>
                                  <th className="py-1 text-right">Task Action</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[var(--sd-border)]/40">
                                {(monitoringData.process_inventory.processes || [])
                                  .filter((p: any) =>
                                    processSearchQuery.trim() === "" ||
                                    p.name?.toLowerCase().includes(processSearchQuery.toLowerCase()) ||
                                    String(p.pid).includes(processSearchQuery.trim())
                                  )
                                  .map((p: any, idx: number) => (
                                    <tr key={idx} className="hover:bg-[var(--sd-panel-raised)]/50">
                                      <td className="py-1 text-emerald-400">{p.pid}</td>
                                      <td className="py-1 text-[var(--sd-text)] truncate max-w-[150px]" title={p.name}>
                                        {p.name}
                                      </td>
                                      <td className="py-1 text-[var(--sd-text-muted)]">{p.memoryMb} MB</td>
                                      <td className="py-1">
                                        {p.protected ? (
                                          <span className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded text-[10px]">
                                            KERNEL PROTECTED
                                          </span>
                                        ) : (
                                          <span className="text-[var(--sd-text-dim)] text-[10px]">USER PROCESS</span>
                                        )}
                                      </td>
                                      <td className="py-1 text-right">
                                        {!p.protected && (
                                          <button
                                            type="button"
                                            onClick={async () => {
                                              if (!confirm(`Terminate process "${p.name}" (PID: ${p.pid}) on ${selectedAgent?.hostname}?`)) return;
                                              try {
                                                const res = await fetch("/api/fleet/execute", {
                                                  method: "POST",
                                                  headers: {
                                                    "Content-Type": "application/json",
                                                    "X-ShieldDesk-User": activeUserId,
                                                  },
                                                  body: JSON.stringify({
                                                    agentId: selectedAgent?.id,
                                                    command: `kill_process ${p.pid}`,
                                                    tier: "Tier 2",
                                                  }),
                                                });
                                                const data = await res.json();
                                                if (res.ok && data.success) {
                                                  setMonitoringData((prev: any) => {
                                                    if (!prev?.process_inventory?.processes) return prev;
                                                    return {
                                                      ...prev,
                                                      process_inventory: {
                                                        ...prev.process_inventory,
                                                        processes: prev.process_inventory.processes.filter((item: any) => item.pid !== p.pid),
                                                      },
                                                    };
                                                  });
                                                  if (selectedAgent) {
                                                    setTimeout(() => fetchMonitoring(selectedAgent.id, true), 1000);
                                                  }
                                                } else {
                                                  alert(`Failed to terminate process: ${data.error || data.message || "Unknown error"}`);
                                                }
                                              } catch (err: any) {
                                                alert(`Error terminating process: ${err.message}`);
                                              }
                                            }}
                                            className="px-2 py-0.5 rounded text-[10px] font-mono text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 transition cursor-pointer"
                                            title={`End task for PID ${p.pid}`}
                                          >
                                            End Task
                                          </button>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                              </tbody>
                            </table>
                          </div>
                        </>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Process Inventory Disabled by Policy</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to inspect running processes.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* 4. Firewall Ruleset Baseline & Live Authority Inspector */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            Firewall &amp; Packet Filter Authority
                          </h4>
                        </div>
                        <div className="flex items-center gap-2">
                          {monitoringData?.firewall_baseline?.enabled && (
                            <button
                              type="button"
                              onClick={() => setShowFwModal(true)}
                              className="px-2 py-0.5 rounded text-[11px] font-mono border border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition cursor-pointer flex items-center gap-1"
                            >
                              <Sliders className="h-3 w-3" />
                              <span>Manage Rules</span>
                            </button>
                          )}
                          <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                            {monitoringData?.firewall_baseline?.enabled ? "MONITORED" : "EXCLUDED"}
                          </span>
                        </div>
                      </div>

                      {monitoringData?.firewall_baseline?.enabled ? (
                        <div className="space-y-3 text-[12px] font-mono">
                          {/* Firewall Enforcement & Profiles */}
                          <div className="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">Firewall Enforcement:</span>
                            <div className="flex items-center gap-2">
                              <span
                                className={cn(
                                  "font-semibold px-2 py-0.5 rounded text-[11px] border",
                                  monitoringData.firewall_baseline.baseline?.firewallState === "ENFORCING"
                                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                    : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                                )}
                              >
                                {monitoringData.firewall_baseline.baseline?.firewallState || "ENFORCING"}
                              </span>
                              {/* Profile toggles */}
                              {monitoringData.firewall_baseline.baseline?.profiles?.map((prof: any) => (
                                <button
                                  key={prof.name}
                                  type="button"
                                  onClick={() => handleToggleProfile(prof.name, prof.state)}
                                  disabled={fwActionLoading}
                                  className={cn(
                                    "px-1.5 py-0.5 rounded text-[10px] border transition cursor-pointer disabled:opacity-50",
                                    prof.state === "ON"
                                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20"
                                      : "bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20"
                                  )}
                                  title={`Click to toggle ${prof.name} profile`}
                                >
                                  {prof.name}: {prof.state}
                                </button>
                              ))}
                            </div>
                          </div>

                          {/* Default Inbound & Outbound Policies */}
                          <div className="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">Default Policies:</span>
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => handleToggleDefaultInbound(monitoringData.firewall_baseline.baseline?.defaultInbound || "BLOCK")}
                                disabled={fwActionLoading}
                                className={cn(
                                  "px-2 py-0.5 rounded text-[10px] border transition cursor-pointer hover:opacity-80 disabled:opacity-50",
                                  monitoringData.firewall_baseline.baseline?.defaultInbound === "BLOCK"
                                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                    : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                                )}
                                title="Click to toggle default inbound traffic policy"
                              >
                                Inbound: {monitoringData.firewall_baseline.baseline?.defaultInbound || "BLOCK"}
                              </button>
                              <span className="text-[var(--sd-text-dim)]">&bull;</span>
                              <span className="text-[var(--sd-text)]">
                                Outbound: {monitoringData.firewall_baseline.baseline?.defaultOutbound || "ALLOW"}
                              </span>
                            </div>
                          </div>

                          {/* Active Rules Count */}
                          <div className="flex flex-wrap items-center justify-between gap-2 py-1 border-b border-[var(--sd-border)]/40">
                            <span className="text-[var(--sd-text-dim)]">ShieldDesk Dynamic Rules:</span>
                            <span className="text-[var(--sd-text)] font-semibold">
                              {monitoringData.firewall_baseline.baseline?.activeShieldDeskRules || 0} active rules
                            </span>
                          </div>

                          {/* Quick Action Buttons */}
                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => setShowFwModal(true)}
                              className="px-2.5 py-1 rounded-lg bg-[var(--sd-pine)]/10 hover:bg-[var(--sd-pine)]/20 border border-[var(--sd-pine)]/40 text-[var(--sd-pine)] text-[11px] font-mono transition cursor-pointer flex items-center gap-1"
                            >
                              <Plus className="h-3 w-3" />
                              <span>Add Custom Rule</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleFirewallAction({
                                action: "add_rule",
                                rule: { name: "ShieldDesk-Block-SMB-445", direction: "in", action: "block", protocol: "TCP", port: "445" }
                              })}
                              disabled={fwActionLoading}
                              className="px-2 py-1 rounded-lg bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-amber-400 text-[11px] font-mono transition cursor-pointer disabled:opacity-50"
                              title="Block Inbound SMB port 445"
                            >
                              Block SMB (445)
                            </button>
                            <button
                              type="button"
                              onClick={() => handleFirewallAction({
                                action: "add_rule",
                                rule: { name: "ShieldDesk-Block-RDP-3389", direction: "in", action: "block", protocol: "TCP", port: "3389" }
                              })}
                              disabled={fwActionLoading}
                              className="px-2 py-1 rounded-lg bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-amber-400 text-[11px] font-mono transition cursor-pointer disabled:opacity-50"
                              title="Block Inbound RDP port 3389"
                            >
                              Block RDP (3389)
                            </button>
                          </div>

                          {/* Active Rules Micro-Table */}
                          {monitoringData.firewall_baseline.baseline?.rules && monitoringData.firewall_baseline.baseline.rules.length > 0 && (
                            <div className="mt-2 space-y-1.5 border-t border-[var(--sd-border)]/40 pt-2">
                              <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium">Active Enforced Rules</span>
                              <div className="space-y-1 max-h-32 overflow-y-auto">
                                {monitoringData.firewall_baseline.baseline.rules.map((r: any, idx: number) => (
                                  <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-[var(--sd-panel)] border border-[var(--sd-border)]/60 text-[11px]">
                                    <div className="flex items-center gap-2 truncate">
                                      <span className={cn("px-1 py-0.2 rounded text-[10px] font-semibold", r.action === "block" ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400")}>
                                        {r.action.toUpperCase()} {r.direction.toUpperCase()}
                                      </span>
                                      <span className="text-[var(--sd-text)] truncate max-w-[130px] font-medium">{r.name}</span>
                                      {(r.localPort || r.remotePort || r.remoteIp) && (
                                        <span className="text-[var(--sd-text-muted)] text-[10px]">
                                          {r.localPort ? `Port:${r.localPort}` : ""} {r.remoteIp ? `IP:${r.remoteIp}` : ""}
                                        </span>
                                      )}
                                    </div>
                                    <button
                                      type="button"
                                      onClick={() => handleDeleteRule(r.name)}
                                      disabled={fwActionLoading}
                                      className="text-red-400 hover:text-red-300 p-1 cursor-pointer disabled:opacity-50"
                                      title="Delete Rule"
                                    >
                                      <Trash2 className="h-3 w-3" />
                                    </button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="pt-1 text-[11px] text-[var(--sd-text-dim)] flex items-center justify-between">
                            <span>Audit: {monitoringData.firewall_baseline.baseline?.lastSnapshotAudit}</span>
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Firewall Baseline Monitoring Disabled</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to inspect packet filter rules.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* 5. Storage Volumes & Disk Utilization */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            Storage Volumes &amp; Disk Headroom
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                          {monitoringData?.storage_disk?.enabled ? "MONITORED" : "EXCLUDED"}
                        </span>
                      </div>

                      {monitoringData?.storage_disk?.enabled ? (
                        <div className="space-y-3 text-[12px] font-mono">
                          {monitoringData.storage_disk.disks?.map((d: any, idx: number) => (
                            <div key={idx} className="space-y-1.5 p-3 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)]">
                              <div className="flex justify-between">
                                <span className="text-[var(--sd-text)] font-semibold">Drive {d.drive} ({d.filesystem})</span>
                                <span className="text-emerald-400 font-semibold">{d.usedPercent}% Used</span>
                              </div>
                              <div className="w-full bg-[var(--sd-panel-raised)] h-2 rounded-full overflow-hidden border border-[var(--sd-border)]">
                                <div
                                  className="bg-emerald-400 h-full transition-all duration-500"
                                  style={{ width: `${Math.min(100, d.usedPercent)}%` }}
                                />
                              </div>
                              <div className="flex justify-between text-[11px] text-[var(--sd-text-dim)]">
                                <span>Free: {d.freeGb} GB</span>
                                <span>Total: {d.totalGb} GB</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Storage Monitoring Disabled by Policy</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to inspect storage headroom.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* 6. Security Services & Daemon Health */}
                    <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)]">
                            Security Services &amp; Daemon Health
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                          {monitoringData?.service_health?.enabled ? "MONITORED" : "EXCLUDED"}
                        </span>
                      </div>

                      {monitoringData?.service_health?.enabled ? (
                        <div className="space-y-2 text-[12px] font-mono">
                          {monitoringData.service_health.services?.map((svc: any, idx: number) => (
                            <div key={idx} className="flex justify-between py-1 border-b border-[var(--sd-border)]/40">
                              <span className="text-[var(--sd-text)] truncate max-w-xs">{svc.name}:</span>
                              <span
                                className={cn(
                                  "font-semibold text-[11px] px-2 py-0.5 rounded-full border",
                                  svc.status === "RUNNING" || svc.status === "ACTIVE"
                                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                    : "bg-amber-500/10 text-amber-300 border-amber-500/30"
                                )}
                              >
                                {svc.status} ({svc.startup})
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Security Service Monitoring Disabled</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to inspect endpoint security daemons.
                          </p>
                        </div>
                      )}
                    </div>

                    {/* 7. Microsoft Defender & EDR Authority */}
                    <div className="lg:col-span-2 rounded-2xl border border-[var(--sd-border)] sd-surface p-5 shadow-xs space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-[var(--sd-pine)]" />
                          <h4 className="text-[13px] font-medium font-mono text-[var(--sd-text)] flex items-center gap-2">
                            Microsoft Defender &amp; EDR Authority
                            {monitoringData?.defender_authority?.defender?.activeThreatsCount > 0 ? (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold animate-pulse">
                                {monitoringData.defender_authority.defender.activeThreatsCount} DETECTED THREATS
                              </span>
                            ) : (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                PROTECTING
                              </span>
                            )}
                          </h4>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setShowDefenderModal(true)}
                            className="px-2 py-0.5 rounded text-[11px] font-mono border border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition cursor-pointer flex items-center gap-1"
                          >
                            <Sliders className="h-3 w-3" />
                            <span>Manage Defender</span>
                          </button>
                          <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">
                            {monitoringData?.defender_authority?.enabled ? "MONITORED" : "EXCLUDED"}
                          </span>
                        </div>
                      </div>

                      {defenderFeedback && (
                        <div
                          className={cn(
                            "p-2.5 rounded-xl border text-[11px] font-mono flex items-center justify-between",
                            defenderFeedback.type === "success"
                              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                              : "bg-red-500/10 border-red-500/30 text-red-300"
                          )}
                        >
                          <span>{defenderFeedback.message}</span>
                          <button
                            type="button"
                            onClick={() => setDefenderFeedback(null)}
                            className="text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] cursor-pointer"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </div>
                      )}

                      {monitoringData?.defender_authority?.enabled ? (
                        <div className="space-y-4 text-[12px] font-mono">
                          {/* Protection Subsystems & Shields Matrix */}
                          <div>
                            <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium block mb-2">
                              Active Protection Subsystems &amp; EDR Shields
                            </span>
                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5">
                              {/* 1. Real-Time Protection */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Real-Time</span>
                                  <button
                                    type="button"
                                    disabled={defenderActionLoading}
                                    onClick={() =>
                                      handleDefenderAction({
                                        action: "toggle_realtime",
                                        state: monitoringData?.defender_authority?.defender?.realTimeProtectionEnabled ? "off" : "on",
                                      })
                                    }
                                    className={cn(
                                      "px-2 py-0.5 rounded text-[10px] font-semibold border transition cursor-pointer disabled:opacity-50",
                                      monitoringData?.defender_authority?.defender?.realTimeProtectionEnabled
                                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20"
                                        : "bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20"
                                    )}
                                    title="Click to toggle Real-Time Protection"
                                  >
                                    {monitoringData?.defender_authority?.defender?.realTimeProtectionEnabled ? "ENABLED" : "DISABLED"}
                                  </button>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Continuous memory hook inspection
                                </p>
                              </div>

                              {/* 2. Behavior Monitor */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Behavior Monitor</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.behaviorMonitorEnabled ? "ACTIVE" : "STANDBY"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Heuristic &amp; zero-day anomaly engine
                                </p>
                              </div>

                              {/* 3. IOAV Protection */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">IOAV Attachment</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.ioavProtectionEnabled ? "ACTIVE" : "STANDBY"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Download payload &amp; file validation
                                </p>
                              </div>

                              {/* 4. Tamper Protection */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Tamper Guard</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.tamperProtectionSource || "ENFORCED"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Guards security configs from tampering
                                </p>
                              </div>

                              {/* 5. PUA Protection */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">PUA Protection</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.puaProtection || "Enabled (Block)"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Blocks unwanted software installers
                                </p>
                              </div>

                              {/* 6. Network Inspection (NIS) */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Network Inspection</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.nisProtectionEnabled ? "ACTIVE (NIS)" : "STANDBY"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Protocol vulnerability shielding
                                </p>
                              </div>

                              {/* 7. Controlled Folder Access / Ransomware */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Ransomware Guard</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                    {monitoringData?.defender_authority?.defender?.controlledFolderAccess || "Disabled"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  Controlled folder ransomware lockdown
                                </p>
                              </div>

                              {/* 8. Script Scanning (AMSI) */}
                              <div className="p-2.5 rounded-xl bg-[var(--sd-panel)]/60 border border-[var(--sd-border)] space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] text-[var(--sd-text-dim)]">Script &amp; AMSI</span>
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    {monitoringData?.defender_authority?.defender?.scriptScanning ? "ACTIVE" : "STANDBY"}
                                  </span>
                                </div>
                                <p className="text-[10px] text-[var(--sd-text-muted)]">
                                  PowerShell &amp; script runtime analysis
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Definitions Intelligence & Scan Operations */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 border-t border-[var(--sd-border)]/40">
                            {/* Security Intelligence */}
                            <div className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium">Security Intelligence</span>
                                <button
                                  type="button"
                                  disabled={defenderActionLoading}
                                  onClick={() => handleDefenderAction({ action: "update_signatures" })}
                                  className="px-2 py-0.5 rounded text-[10px] font-mono border border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition cursor-pointer flex items-center gap-1 disabled:opacity-50"
                                >
                                  <RefreshCw className={cn("h-2.5 w-2.5", defenderActionLoading && "animate-spin")} />
                                  <span>Update Signatures</span>
                                </button>
                              </div>
                              <div className="p-3 rounded-xl bg-[var(--sd-panel)]/40 border border-[var(--sd-border)]/60 space-y-1.5 text-[11px]">
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">Signature Version:</span>
                                  <span className="text-emerald-400 font-semibold">
                                    {monitoringData?.defender_authority?.defender?.signatureVersion || "1.459.691.0"}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">NIS Signature Version:</span>
                                  <span className="text-emerald-400 font-semibold">
                                    {monitoringData?.defender_authority?.defender?.nisSignatureVersion || "1.459.691.0"}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">Last Updated:</span>
                                  <span className="text-[var(--sd-text)]">
                                    {monitoringData?.defender_authority?.defender?.signatureLastUpdated || "Recent"}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">Engine Version:</span>
                                  <span className="text-[var(--sd-text-muted)]">
                                    {monitoringData?.defender_authority?.defender?.engineVersion || "1.1.26080.3"}
                                  </span>
                                </div>
                              </div>
                            </div>

                            {/* Scan Actions */}
                            <div className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium">Scan Operations</span>
                                <div className="flex items-center gap-1.5">
                                  <button
                                    type="button"
                                    disabled={defenderActionLoading}
                                    onClick={() => handleDefenderAction({ action: "quick_scan" })}
                                    className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold hover:opacity-90 transition cursor-pointer flex items-center gap-1 disabled:opacity-50"
                                  >
                                    <Zap className="h-2.5 w-2.5" />
                                    <span>Quick Scan</span>
                                  </button>
                                  <button
                                    type="button"
                                    disabled={defenderActionLoading}
                                    onClick={() => handleDefenderAction({ action: "full_scan" })}
                                    className="px-2.5 py-0.5 rounded text-[10px] font-mono border border-[var(--sd-border)] hover:border-[var(--sd-pine)] text-[var(--sd-pine)] hover:bg-[var(--sd-pine)]/10 transition cursor-pointer flex items-center gap-1 disabled:opacity-50"
                                  >
                                    <Shield className="h-2.5 w-2.5" />
                                    <span>Full Scan</span>
                                  </button>
                                </div>
                              </div>
                              <div className="p-3 rounded-xl bg-[var(--sd-panel)]/40 border border-[var(--sd-border)]/60 space-y-1.5 text-[11px]">
                                <div className="flex justify-between items-center">
                                  <span className="text-[var(--sd-text-dim)]">Last Quick Scan:</span>
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[var(--sd-text)]">
                                      {monitoringData?.defender_authority?.defender?.quickScanEndTime || "No record"}
                                    </span>
                                    {monitoringData?.defender_authority?.defender?.quickScanOverdue && (
                                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                        OVERDUE
                                      </span>
                                    )}
                                  </div>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">Last Full Scan:</span>
                                  <span className="text-[var(--sd-text)]">
                                    {monitoringData?.defender_authority?.defender?.fullScanEndTime || "Never completed"}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-[var(--sd-text-dim)]">Antivirus Protection:</span>
                                  <span className="text-emerald-400 font-semibold">
                                    {monitoringData?.defender_authority?.defender?.antivirusEnabled ? "ACTIVE (Enforced)" : "INACTIVE"}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Active Detected Threats */}
                          <div className="space-y-2 border-t border-[var(--sd-border)]/40 pt-2">
                            <div className="flex items-center justify-between">
                              <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium">
                                Active Threat Inventory ({monitoringData?.defender_authority?.defender?.threats?.length || 0})
                              </span>
                              {monitoringData?.defender_authority?.defender?.threats?.length > 0 && (
                                <button
                                  type="button"
                                  disabled={defenderActionLoading}
                                  onClick={() => handleDefenderAction({ action: "remediate_threat", threatId: "all" })}
                                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30 transition cursor-pointer disabled:opacity-50"
                                >
                                  Remediate All Threats
                                </button>
                              )}
                            </div>

                            {monitoringData?.defender_authority?.defender?.threats &&
                            monitoringData.defender_authority.defender.threats.length > 0 ? (
                              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                                {monitoringData.defender_authority.defender.threats.map((t: any, idx: number) => (
                                  <div
                                    key={idx}
                                    className="flex items-center justify-between p-2 rounded-xl bg-amber-500/5 border border-amber-500/20 text-[11px]"
                                  >
                                    <div className="flex items-center gap-2 truncate">
                                      <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                        SEV: {t.severity}
                                      </span>
                                      {t.category && (
                                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[var(--sd-panel)] text-[var(--sd-text-dim)] border border-[var(--sd-border)]">
                                          {t.category}
                                        </span>
                                      )}
                                      <span className="text-amber-200 font-medium truncate max-w-[220px]">
                                        {t.threatName}
                                      </span>
                                      <span className="text-[var(--sd-text-dim)] text-[10px]">
                                        ID: {t.threatId}
                                      </span>
                                    </div>
                                    <button
                                      type="button"
                                      disabled={defenderActionLoading}
                                      onClick={() =>
                                        handleDefenderAction({
                                          action: "remediate_threat",
                                          threatId: t.threatId,
                                        })
                                      }
                                      className="px-2 py-0.5 rounded text-[10px] font-mono border border-red-500/40 text-red-400 hover:bg-red-500/20 transition cursor-pointer disabled:opacity-50"
                                    >
                                      Remediate
                                    </button>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="p-2.5 rounded-xl bg-emerald-500/5 border border-emerald-500/20 flex items-center gap-2 text-[11px] text-emerald-400">
                                <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                                <span>Endpoint host is completely clean. No active or unresolved threat detections.</span>
                              </div>
                            )}
                          </div>

                          {/* Threat Detection History & Targeted File Resources */}
                          {monitoringData?.defender_authority?.defender?.detections &&
                            monitoringData.defender_authority.defender.detections.length > 0 && (
                              <div className="space-y-2 border-t border-[var(--sd-border)]/40 pt-2">
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                  <div className="flex items-center gap-2">
                                    <span className="text-[11px] text-[var(--sd-text-dim)] uppercase font-medium">
                                      Threat Detection History &amp; Targeted Resources ({monitoringData.defender_authority.defender.detections.length})
                                    </span>
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-[var(--sd-panel)] border border-[var(--sd-border)] text-[var(--sd-text-muted)]">
                                      Live EDR Forensic Log
                                    </span>
                                  </div>
                                  <div className="relative">
                                    <input
                                      type="text"
                                      value={defenderDetectionSearch}
                                      onChange={(e) => setDefenderDetectionSearch(e.target.value)}
                                      placeholder="Filter detections or infected files..."
                                      className="w-full sm:w-56 px-2.5 py-1 text-[11px] rounded-lg bg-[var(--sd-panel)] border border-[var(--sd-border)] text-[var(--sd-text)] placeholder-[var(--sd-text-muted)] outline-none focus:border-[var(--sd-pine)]"
                                    />
                                    {defenderDetectionSearch && (
                                      <button
                                        type="button"
                                        onClick={() => setDefenderDetectionSearch("")}
                                        className="absolute right-2 top-1.5 text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                                      >
                                        <X className="h-3 w-3" />
                                      </button>
                                    )}
                                  </div>
                                </div>

                                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                                  {monitoringData.defender_authority.defender.detections
                                    .filter((det: any) => {
                                      if (!defenderDetectionSearch.trim()) return true;
                                      const term = defenderDetectionSearch.toLowerCase();
                                      return (
                                        String(det.threatId).toLowerCase().includes(term) ||
                                        String(det.threatName || "").toLowerCase().includes(term) ||
                                        String(det.domainUser || "").toLowerCase().includes(term) ||
                                        String(det.processName || "").toLowerCase().includes(term) ||
                                        String(det.cleaningAction || "").toLowerCase().includes(term) ||
                                        (det.resources && det.resources.some((r: string) => r.toLowerCase().includes(term)))
                                      );
                                    })
                                    .map((det: any, idx: number) => (
                                      <div
                                        key={idx}
                                        className="p-3 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-[11px] space-y-1.5"
                                      >
                                        <div className="flex flex-wrap items-center justify-between gap-1.5">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <span className="font-semibold text-amber-300">
                                              {det.threatName || `Threat #${det.threatId}`}
                                            </span>
                                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30">
                                              ID: {det.threatId}
                                            </span>
                                            {det.cleaningAction && (
                                              <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold">
                                                {det.cleaningAction.toUpperCase()}
                                              </span>
                                            )}
                                          </div>
                                          <div className="flex items-center gap-3 text-[10px] text-[var(--sd-text-dim)]">
                                            {det.initialDetectionTime && (
                                              <span>Detected: {det.initialDetectionTime}</span>
                                            )}
                                            {det.remediationTime && (
                                              <span className="hidden sm:inline">Remediated: {det.remediationTime}</span>
                                            )}
                                          </div>
                                        </div>

                                        <div className="flex flex-wrap items-center gap-3 text-[10px] text-[var(--sd-text-dim)]">
                                          {det.domainUser && (
                                            <span>
                                              <span className="text-[var(--sd-text-muted)]">User: </span>
                                              <span className="text-[var(--sd-text)]">{det.domainUser}</span>
                                            </span>
                                          )}
                                          {det.processName && (
                                            <span>
                                              <span className="text-[var(--sd-text-muted)]">Process: </span>
                                              <span className="text-[var(--sd-text)]">{det.processName}</span>
                                            </span>
                                          )}
                                        </div>

                                        {det.resources && det.resources.length > 0 && (
                                          <div className="mt-1 space-y-1">
                                            <span className="text-[10px] text-red-400 font-semibold block">Targeted Infected Resources:</span>
                                            <div className="space-y-1 max-h-24 overflow-y-auto">
                                              {det.resources.map((res: string, rIdx: number) => (
                                                <div
                                                  key={rIdx}
                                                  className="p-1.5 rounded-lg bg-[var(--sd-bg)]/80 border border-[var(--sd-border)]/70 text-[10px] font-mono break-all text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] transition"
                                                >
                                                  {res}
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                </div>
                              </div>
                            )}

                          {/* Extended Defender Engine & Cloud Protection Telemetry */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 pt-2 border-t border-[var(--sd-border)]/40 text-[11px]">
                            <div className="p-2 rounded-lg bg-[var(--sd-panel)]/30 border border-[var(--sd-border)]/50">
                              <span className="text-[var(--sd-text-dim)] block text-[10px]">Product / Service Version</span>
                              <span className="text-[var(--sd-text)] font-semibold">
                                {monitoringData?.defender_authority?.defender?.productVersion || "4.18.26080.4"}
                              </span>
                            </div>
                            <div className="p-2 rounded-lg bg-[var(--sd-panel)]/30 border border-[var(--sd-border)]/50">
                              <span className="text-[var(--sd-text-dim)] block text-[10px]">Cloud Protection (MAPS)</span>
                              <span className="text-emerald-400 font-semibold">
                                {monitoringData?.defender_authority?.defender?.cloudProtection?.mapsReporting || "Advanced MAPS"}
                              </span>
                            </div>
                            <div className="p-2 rounded-lg bg-[var(--sd-panel)]/30 border border-[var(--sd-border)]/50">
                              <span className="text-[var(--sd-text-dim)] block text-[10px]">Sample Submission</span>
                              <span className="text-[var(--sd-text)] font-semibold">
                                {monitoringData?.defender_authority?.defender?.cloudProtection?.submitSamplesConsent || "Send Safe Samples Automatically"}
                              </span>
                            </div>
                            <div className="p-2 rounded-lg bg-[var(--sd-panel)]/30 border border-[var(--sd-border)]/50">
                              <span className="text-[var(--sd-text-dim)] block text-[10px]">Smart App / Device Ctrl</span>
                              <span className="text-[var(--sd-text)] font-semibold">
                                {monitoringData?.defender_authority?.defender?.smartAppControl || "Off"} &bull; {monitoringData?.defender_authority?.defender?.deviceControl || "Disabled"}
                              </span>
                            </div>
                          </div>

                          <div className="pt-1 text-[11px] text-[var(--sd-text-dim)] flex items-center justify-between">
                            <span>Audit: {monitoringData?.defender_authority?.defender?.lastAudit || "Baseline verified"}</span>
                            {monitoringData?.defender_authority?.defender?.computerId && (
                              <span className="hidden sm:inline text-[10px]">ID: {monitoringData.defender_authority.defender.computerId}</span>
                            )}
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] text-center text-[12px] font-mono text-[var(--sd-text-muted)] space-y-1">
                          <p className="text-amber-400 font-medium">🔒 Defender Authority Gated by Policy</p>
                          <p className="text-[11px] text-[var(--sd-text-dim)]">
                            Requires Tier 2 Authority Approval to inspect and manage endpoint Microsoft Defender EDR controls.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* ── Firewall Authority & Rule Manager Modal ── */}
      {showFwModal && selectedAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-3xl rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-[var(--sd-text)] shadow-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-4">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="h-5 w-5 text-[var(--sd-pine)]" />
                <div>
                  <h3 className="text-base font-semibold font-mono text-[var(--sd-text)]">
                    Endpoint Firewall Authority &amp; Rule Manager
                  </h3>
                  <p className="text-[12px] font-mono text-[var(--sd-text-dim)]">
                    Target: <span className="text-emerald-400 font-semibold">{selectedAgent.hostname}</span> &bull; {selectedAgent.ip_address}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowFwModal(false);
                  setFwFeedback(null);
                }}
                className="text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] p-1.5 rounded-lg hover:bg-[var(--sd-panel)] transition cursor-pointer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Failsafe Notice */}
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-[11px] font-mono text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
              <span>
                Failsafe Active: Every rule change takes a pre-flight snapshot. If control-plane connectivity is severed, the agent auto-reverts within 5s.
              </span>
            </div>

            {/* Feedback Alert */}
            {fwFeedback && (
              <div
                className={cn(
                  "p-3 rounded-xl text-[12px] font-mono flex items-center gap-2",
                  fwFeedback.type === "success"
                    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
                    : "bg-red-500/10 border border-red-500/30 text-red-400"
                )}
              >
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{fwFeedback.message}</span>
              </div>
            )}

            {/* Add Custom Rule Form */}
            <form onSubmit={handleCreateRuleSubmit} className="space-y-3 p-4 rounded-xl bg-[var(--sd-panel)] border border-[var(--sd-border)]">
              <h4 className="text-[12px] font-semibold font-mono uppercase tracking-wider text-[var(--sd-pine)] flex items-center gap-1.5">
                <Plus className="h-3.5 w-3.5" />
                <span>Enforce New Firewall Rule</span>
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-[12px] font-mono">
                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Rule Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Block-Port-8080"
                    value={fwRuleName}
                    onChange={(e) => setFwRuleName(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] focus:border-[var(--sd-pine)] outline-none"
                  />
                </div>

                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Direction &amp; Action</label>
                  <div className="grid grid-cols-2 gap-1.5">
                    <select
                      value={fwRuleDir}
                      onChange={(e) => setFwRuleDir(e.target.value as "in" | "out")}
                      className="px-2 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] text-[11px]"
                    >
                      <option value="in">Inbound</option>
                      <option value="out">Outbound</option>
                    </select>
                    <select
                      value={fwRuleAction}
                      onChange={(e) => setFwRuleAction(e.target.value as "block" | "allow")}
                      className="px-2 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] text-[11px]"
                    >
                      <option value="block">Block (Drop)</option>
                      <option value="allow">Allow</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Protocol</label>
                  <select
                    value={fwRuleProto}
                    onChange={(e) => setFwRuleProto(e.target.value as "TCP" | "UDP" | "ANY")}
                    className="w-full px-2 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] text-[11px]"
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ANY">Any Protocol</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Port (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. 445, 3389"
                    value={fwRulePort}
                    onChange={(e) => setFwRulePort(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] focus:border-[var(--sd-pine)] outline-none"
                  />
                </div>

                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Remote IP / CIDR (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.23"
                    value={fwRuleIp}
                    onChange={(e) => setFwRuleIp(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] focus:border-[var(--sd-pine)] outline-none"
                  />
                </div>

                <div>
                  <label className="block text-[var(--sd-text-dim)] text-[10px] uppercase mb-1">Authority Token</label>
                  <input
                    type="text"
                    placeholder="Auto-signed as SecOps Admin"
                    value={fwRuleTokenId}
                    onChange={(e) => setFwRuleTokenId(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] text-[11px] focus:border-[var(--sd-pine)] outline-none"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  disabled={fwActionLoading}
                  className="px-4 py-2 rounded-xl bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold text-[12px] font-mono hover:opacity-90 transition cursor-pointer disabled:opacity-50 flex items-center gap-2"
                >
                  {fwActionLoading && <RefreshCw className="h-3 w-3 animate-spin" />}
                  <span>Enforce &amp; Cryptographically Sign Rule</span>
                </button>
              </div>
            </form>

            {/* Current Active Rules Table */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-[12px] font-semibold font-mono uppercase tracking-wider text-[var(--sd-text)]">
                  Live Rules Inventory ({monitoringData?.firewall_baseline?.baseline?.rules?.length || 0})
                </h4>
                <button
                  type="button"
                  onClick={() => selectedAgent && fetchMonitoring(selectedAgent.id, true)}
                  disabled={fwActionLoading}
                  className="text-[11px] font-mono text-[var(--sd-pine)] hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <RefreshCw className={cn("h-3 w-3", fwActionLoading && "animate-spin")} />
                  <span>Refresh Rules</span>
                </button>
              </div>

              <div className="border border-[var(--sd-border)] rounded-xl overflow-hidden max-h-56 overflow-y-auto">
                <table className="w-full text-left text-[11px] font-mono">
                  <thead className="bg-[var(--sd-panel)] text-[var(--sd-text-dim)] border-b border-[var(--sd-border)] sticky top-0">
                    <tr>
                      <th className="p-2">Rule Name</th>
                      <th className="p-2">Direction</th>
                      <th className="p-2">Action</th>
                      <th className="p-2">Proto</th>
                      <th className="p-2">Port / Target</th>
                      <th className="p-2 text-right">Delete</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--sd-border)]/40">
                    {monitoringData?.firewall_baseline?.baseline?.rules && monitoringData.firewall_baseline.baseline.rules.length > 0 ? (
                      monitoringData.firewall_baseline.baseline.rules.map((r: any, idx: number) => (
                        <tr key={idx} className="hover:bg-[var(--sd-panel-raised)]/50">
                          <td className="p-2 text-[var(--sd-text)] font-medium truncate max-w-[180px]">{r.name}</td>
                          <td className="p-2 uppercase text-[var(--sd-text-dim)]">{r.direction}</td>
                          <td className="p-2">
                            <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-semibold", r.action === "block" ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400")}>
                              {r.action.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-2 text-[var(--sd-text-dim)]">{r.protocol || "TCP"}</td>
                          <td className="p-2 text-[var(--sd-text)]">
                            {r.localPort ? `Port:${r.localPort}` : ""} {r.remoteIp ? `IP:${r.remoteIp}` : ""}
                            {!r.localPort && !r.remoteIp ? "All Traffic" : ""}
                          </td>
                          <td className="p-2 text-right">
                            <button
                              type="button"
                              onClick={() => handleDeleteRule(r.name)}
                              disabled={fwActionLoading}
                              className="text-red-400 hover:text-red-300 p-1 cursor-pointer disabled:opacity-50"
                              title="Delete rule"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} className="p-6 text-center text-[var(--sd-text-muted)]">
                          No ShieldDesk dynamic firewall rules enforced on this endpoint.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Microsoft Defender EDR Authority Manager Modal ── */}
      {showDefenderModal && selectedAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[var(--sd-surface)] border border-[var(--sd-border)] rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 animate-in fade-in-50 zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-[var(--sd-border)]">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="h-5 w-5 text-[var(--sd-pine)]" />
                <div>
                  <h3 className="text-[15px] font-semibold text-[var(--sd-text)] font-mono">
                    Microsoft Defender EDR Authority Console
                  </h3>
                  <p className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                    Cryptographically Governed Endpoint Control &bull; Host: {selectedAgent.hostname}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowDefenderModal(false)}
                className="text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] p-1 rounded-lg hover:bg-[var(--sd-panel)] cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {defenderFeedback && (
              <div
                className={cn(
                  "p-3 rounded-xl border text-[12px] font-mono flex items-center justify-between",
                  defenderFeedback.type === "success"
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                    : "bg-red-500/10 border-red-500/30 text-red-300"
                )}
              >
                <span>{defenderFeedback.message}</span>
                <button
                  type="button"
                  onClick={() => setDefenderFeedback(null)}
                  className="text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] cursor-pointer"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            )}

            {/* Quick Action Matrix */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <button
                type="button"
                disabled={defenderActionLoading}
                onClick={() => handleDefenderAction({ action: "quick_scan" })}
                className="p-3 rounded-xl bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-left space-y-1 transition cursor-pointer disabled:opacity-50"
              >
                <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[12px] font-mono">
                  <Zap className="h-3.5 w-3.5" />
                  <span>Quick Scan</span>
                </div>
                <p className="text-[10px] text-[var(--sd-text-dim)] font-mono">
                  Scan common memory, boot sectors, &amp; startup directories
                </p>
              </button>

              <button
                type="button"
                disabled={defenderActionLoading}
                onClick={() => handleDefenderAction({ action: "full_scan" })}
                className="p-3 rounded-xl bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-left space-y-1 transition cursor-pointer disabled:opacity-50"
              >
                <div className="flex items-center gap-1.5 text-[var(--sd-pine)] font-semibold text-[12px] font-mono">
                  <Shield className="h-3.5 w-3.5" />
                  <span>Full System Scan</span>
                </div>
                <p className="text-[10px] text-[var(--sd-text-dim)] font-mono">
                  Inspect all storage drives, processes, and registries
                </p>
              </button>

              <button
                type="button"
                disabled={defenderActionLoading}
                onClick={() => handleDefenderAction({ action: "update_signatures" })}
                className="p-3 rounded-xl bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-left space-y-1 transition cursor-pointer disabled:opacity-50"
              >
                <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[12px] font-mono">
                  <RefreshCw className={cn("h-3.5 w-3.5", defenderActionLoading && "animate-spin")} />
                  <span>Update Intelligence</span>
                </div>
                <p className="text-[10px] text-[var(--sd-text-dim)] font-mono">
                  Pull latest signature definitions from Microsoft cloud
                </p>
              </button>
            </div>

            {/* Add Exclusion Form */}
            <div className="p-4 rounded-xl bg-[var(--sd-panel)]/50 border border-[var(--sd-border)] space-y-3">
              <h4 className="text-[12px] font-semibold font-mono text-[var(--sd-text)] uppercase">
                Configure Directory or Process Exclusion
              </h4>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  placeholder="e.g. C:\SecOps\Tools or process_name.exe"
                  value={defenderExclusionPath}
                  onChange={(e) => setDefenderExclusionPath(e.target.value)}
                  className="flex-1 px-3 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[12px] font-mono text-[var(--sd-text)] focus:border-[var(--sd-pine)] outline-none"
                />
                <button
                  type="button"
                  disabled={defenderActionLoading || !defenderExclusionPath.trim()}
                  onClick={async () => {
                    if (!defenderExclusionPath.trim()) return;
                    await handleDefenderAction({
                      action: "add_exclusion",
                      path: defenderExclusionPath.trim(),
                      approvalTokenId: defenderTokenId.trim() || undefined,
                    });
                    setDefenderExclusionPath("");
                  }}
                  className="px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold text-[11px] font-mono hover:opacity-90 transition cursor-pointer disabled:opacity-50"
                >
                  Add Exclusion
                </button>
              </div>
            </div>

            {/* Authority Token Input */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--sd-border)]/50 text-[11px] font-mono">
              <div className="flex items-center gap-2">
                <Key className="h-3.5 w-3.5 text-amber-400" />
                <span className="text-[var(--sd-text-dim)]">Tier 2 Approval Token:</span>
                <input
                  type="text"
                  placeholder="Auto-provisioned for SecOps Admin"
                  value={defenderTokenId}
                  onChange={(e) => setDefenderTokenId(e.target.value)}
                  className="px-2 py-1 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[11px] w-64 focus:border-[var(--sd-pine)] outline-none text-[var(--sd-text)]"
                />
              </div>
              <button
                type="button"
                onClick={() => setShowDefenderModal(false)}
                className="px-4 py-1.5 rounded-xl border border-[var(--sd-border)] hover:bg-[var(--sd-panel)] text-[var(--sd-text)] transition cursor-pointer"
              >
                Close Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Connect Endpoint Modal */}
      {showConnectModal && (
        <ConnectEndpointModal
          isOpen={showConnectModal}
          onClose={() => setShowConnectModal(false)}
          activeUserId={activeUserId}
          existingAgents={agents}
          onEndpointConnected={() => {
            fetchFleet(true);
            setShowConnectModal(false);
          }}
        />
      )}
    </div>
  );
}

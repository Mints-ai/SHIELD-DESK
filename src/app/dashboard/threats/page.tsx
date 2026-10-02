"use client";

import React, { useState, useEffect } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import {
  ShieldAlert,
  Activity,
  Flame,
  Binary,
  Radio,
  Send,
  EyeOff,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
  Server,
  Layers,
  Bot,
  Lock,
  Globe,
  Mail,
  UserCheck,
  Clock,
  Ban,
  Unlock,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface RuleItem {
  id: string;
  name?: string;
  title?: string;
  category?: string;
  severity: string;
  matches_today: number;
  status: string;
  target?: string;
  logsource?: string;
  description?: string;
  detection_logic?: string;
}

interface AnomalyMetric {
  metric: string;
  mean: number;
  stdDev: number;
  threshold_3sigma?: number;
  threshold_2sigma?: number;
  current_value: number;
  is_anomaly: boolean;
  unit: string;
}

export interface BlockedIpItem {
  ip: string;
  blockedAt: string;
  reason: string;
  attempts: number;
}

export interface ThreatSecurityAlert {
  id: string;
  type: string;
  severity: "medium" | "high" | "critical";
  title: string;
  description: string;
  targetUser: string;
  clientIp: string;
  failureReason: string;
  attemptsCount: number;
  isBlocked?: boolean;
  allowedRecipients: string[];
  status: string;
  createdAt: string;
}

import { useChat } from "@/lib/context/ChatContext";

export default function ThreatsDashboardPage() {
  const { activeUserId, activeUser, openChatWithPrompt } = useChat();
  const [activeTab, setActiveTab] = useState<"yara" | "sigma" | "anomaly" | "ingest" | "alerts">("anomaly");
  const [loading, setLoading] = useState(false);
  const [yaraRules, setYaraRules] = useState<RuleItem[]>([]);
  const [sigmaRules, setSigmaRules] = useState<RuleItem[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyMetric[]>([]);
  const [telemetry, setTelemetry] = useState<any>(null);
  const [securityAlerts, setSecurityAlerts] = useState<ThreatSecurityAlert[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIpItem[]>([]);
  const [canViewAuthAlerts, setCanViewAuthAlerts] = useState<boolean>(false);
  const [unblockFeedback, setUnblockFeedback] = useState<string | null>(null);

  // Strictly restricted: Only System Admin (dev-admin / system_admin) and Globex Analyst (dev-other / globex-tenant) can view alerts
  const isAuthorizedForAlerts =
    activeUserId === "dev-admin" ||
    activeUserId === "dev-other" ||
    activeUser?.role === "system_admin" ||
    activeUser?.tenantId === "globex-tenant" ||
    canViewAuthAlerts;

  // Auto-switch to anomaly tab if active persona is not authorized for alerts
  useEffect(() => {
    if (!isAuthorizedForAlerts && activeTab === "alerts") {
      setActiveTab("anomaly");
    }
  }, [isAuthorizedForAlerts, activeTab]);

  // Simulation Feedback
  const [simFeedback, setSimFeedback] = useState<string | null>(null);

  // Webhook Test State
  const [webhookLog, setWebhookLog] = useState<any>(null);

  const fetchThreatData = async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      const res = await fetch(`/api/threats?t=${Date.now()}`, {
        headers: {
          "X-ShieldDesk-User": activeUserId,
          "Cache-Control": "no-cache",
        },
      });
      const data = await res.json();
      if (data.yara_rules) setYaraRules(data.yara_rules);
      if (data.sigma_rules) setSigmaRules(data.sigma_rules);
      if (data.anomaly_baselines) setAnomalies(data.anomaly_baselines);
      if (data.ingest_telemetry) setTelemetry(data.ingest_telemetry);
      if (data.blocked_ips) setBlockedIps(data.blocked_ips);
      if (data.security_alerts && isAuthorizedForAlerts) {
        setSecurityAlerts(data.security_alerts);
      } else {
        setSecurityAlerts([]);
      }
      setCanViewAuthAlerts(Boolean(data.can_view_auth_alerts));
    } catch (err) {
      console.error("Failed to load threats:", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
    // Continuous real-time polling so alerts show immediately on the alerts tab
    const interval = setInterval(() => {
      fetchThreatData(true);
    }, 3000);
    return () => clearInterval(interval);
  }, [activeUserId]);

  const triggerAnomalySimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "simulate_burst" }),
      });
      const data = await res.json();
      setSimFeedback(
        `Anomaly Spike Triggered: ${data.simulated_value} attempts/min (${data.sigma_deviation})! Dispatched alert to ${data.alert_subject}`
      );
      // Fetch fresh live computed telemetry immediately
      await fetchThreatData(true);
    } catch {
      setSimFeedback("Anomaly simulation complete.");
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "acknowledge_alert", alert_id: alertId }),
      });
      setSecurityAlerts((prev) => prev.filter((a) => a.id !== alertId));
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "unblock_ip", ip }),
      });
      const data = await res.json();
      if (data.success) {
        setUnblockFeedback(`IP ${ip} successfully unblocked and containment restored.`);
        setTimeout(() => setUnblockFeedback(null), 4000);
        fetchThreatData(true);
      }
    } catch (err) {
      console.error("Failed to unblock IP:", err);
    }
  };

  const handleBlockIp = async (ip: string) => {
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "block_ip", ip, reason: "Manual SOC operator containment" }),
      });
      const data = await res.json();
      if (data.success) {
        setUnblockFeedback(`IP ${ip} manually blocked.`);
        setTimeout(() => setUnblockFeedback(null), 4000);
        fetchThreatData(true);
      }
    } catch (err) {
      console.error("Failed to block IP:", err);
    }
  };

  const handleInvestigateInChat = (alert: ThreatSecurityAlert) => {
    openChatWithPrompt(
      `Investigate suspicious authentication alert: ${alert.title}. Target account: ${alert.targetUser}, Source IP: ${alert.clientIp}, Condition: ${alert.failureReason} (${alert.attemptsCount} attempts). What immediate containment steps should we take?`
    );
  };

  const resetAnomaly = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "reset_anomalies" }),
      });
      const data = await res.json();
      if (data.anomaly_baselines) {
        setAnomalies(data.anomaly_baselines);
      } else {
        setAnomalies((prev) =>
          prev.map((a) => ({
            ...a,
            current_value: 0.0,
            is_anomaly: false,
          }))
        );
      }
      setSimFeedback(null);
      await fetchThreatData(true);
    } catch (err) {
      console.error("Failed to reset anomaly baselines:", err);
      setAnomalies((prev) =>
        prev.map((a) => ({
          ...a,
          current_value: 0.0,
          is_anomaly: false,
        }))
      );
      setSimFeedback(null);
    } finally {
      setLoading(false);
    }
  };

  const dispatchTestWebhook = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ endpoint_id: "wh-secops-slack" }),
      });
      const data = await res.json();
      setWebhookLog(data);
    } catch {
      setWebhookLog({ message: "Failed to dispatch test webhook" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-[var(--sd-pine)] text-[#f7f4ed]">
                <Flame className="h-5 w-5" />
              </div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--sd-text)]">
                Threat Detection &amp; Telemetry Engine
              </h1>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] mt-1">
              Go gRPC streaming ingestion, YARA/Sigma rule matching, 3-sigma statistical anomaly scoring, and HMAC webhooks.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)] border border-[var(--sd-pine-border)] flex items-center gap-1.5 font-mono">
              <Radio className="h-3 w-3 animate-pulse" />
              gRPC Ingest: 4,120 ev/min
            </span>

            <button
              onClick={() => fetchThreatData()}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-text)] transition cursor-pointer shadow-xs"
              title="Refresh threat alerts and telemetry"
            >
              <RotateCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>Refresh</span>
            </button>

            {activeUserId !== "dev-analyst" && (
              <div className="flex items-center gap-2">
                <button
                  onClick={triggerAnomalySimulation}
                  disabled={loading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-danger)] hover:bg-[var(--sd-danger)]/90 text-white text-xs font-semibold shadow-xs transition cursor-pointer disabled:opacity-50"
                  title="Simulate 3-sigma anomaly burst across telemetry streams"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  <span>Simulate Anomaly Burst</span>
                </button>

                {anomalies.some((a) => a.is_anomaly) && (
                  <button
                    onClick={resetAnomaly}
                    disabled={loading}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 text-xs font-semibold shadow-xs transition cursor-pointer disabled:opacity-50"
                    title="Stop anomaly simulation and restore nominal 3-sigma baseline"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>Reset Baseline</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Simulation Feedback Alert */}
        {simFeedback && (
          <div className="p-3 rounded-lg border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-xs text-[var(--sd-danger)] flex items-center gap-2 shadow-xs">
            <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--sd-danger)] animate-pulse" />
            <span className="font-semibold truncate">{simFeedback}</span>
          </div>
        )}

        {/* Stat Highlights */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">Active Threat Rules</span>
              <Binary className="h-4 w-4 text-[var(--sd-pine)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-text)] font-mono">
              {yaraRules.length + sigmaRules.length}
            </div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">YARA Malware + Sigma Behavioral</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">3σ Anomaly Baselines</span>
              <Activity className="h-4 w-4 text-[var(--sd-warning)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-text)] font-mono">
              {(() => {
                const count = anomalies.filter((a) => a.is_anomaly).length;
                return count > 0 ? (
                  <span className="text-[var(--sd-danger)]">
                    {count} ANOMAL{count > 1 ? "IES" : "Y"} ACTIVE
                  </span>
                ) : (
                  <span className="text-[var(--sd-pine-bright)]">NOMINAL</span>
                );
              })()}
            </div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">Rolling statistical bounds</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">PII Scrubbed Today</span>
              <EyeOff className="h-4 w-4 text-[var(--sd-pine-bright)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-text)] font-mono">
              {telemetry?.pii_redacted_today || 184}
            </div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">Zero plaintext tokens on bus</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-xs font-medium">NATS Throughput</span>
              <Radio className="h-4 w-4 text-[var(--sd-pine)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--sd-pine-bright)] font-mono">
              {telemetry?.events_per_minute || 4120} / 10k
            </div>
            <p className="text-[10.5px] text-[var(--sd-text-muted)] mt-1">Events/min capacity</p>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-2 border-b border-[var(--sd-border)]">
          <button
            onClick={() => setActiveTab("anomaly")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "anomaly"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>3-Sigma ML Anomaly Engine</span>
          </button>

          <button
            onClick={() => setActiveTab("yara")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "yara"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Binary className="h-3.5 w-3.5" />
            <span>YARA Malware Rules ({yaraRules.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("sigma")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "sigma"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>Sigma Behavioral Detection ({sigmaRules.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("ingest")}
            className={cn(
              "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
              activeTab === "ingest"
                ? "border-[var(--sd-pine)] text-[var(--sd-pine)]"
                : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
            )}
          >
            <Send className="h-3.5 w-3.5" />
            <span>gRPC Ingestion &amp; HMAC Webhooks</span>
          </button>

          {isAuthorizedForAlerts && (
            <button
              onClick={() => setActiveTab("alerts")}
              className={cn(
                "px-4 py-2.5 text-xs font-semibold border-b-2 transition cursor-pointer flex items-center gap-2",
                activeTab === "alerts"
                  ? "border-[var(--sd-danger)] text-[var(--sd-danger)]"
                  : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Alerts</span>
              {securityAlerts.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-[var(--sd-danger)] text-white font-mono animate-pulse">
                  {securityAlerts.length}
                </span>
              )}
            </button>
          )}
        </div>

        {/* Tab 1: 3-Sigma Anomaly Baselines */}
        {activeTab === "anomaly" && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-4 shadow-xs">
              <div>
                <h3 className="text-sm font-bold text-[var(--sd-text)]">
                  Statistical Anomaly Engine (3σ Autonomic Baselines)
                </h3>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1">
                  ShieldDesk models dynamic Gaussian distributions per tenant. If a live event rate exceeds $\mu + 3\sigma$, an immediate Tier 1 containment or Tier 2 approval workflow is initiated.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                {anomalies.map((anom, i) => {
                  const threshold = anom.threshold_3sigma || anom.threshold_2sigma || 10;
                  const ratio = Math.min((anom.current_value / threshold) * 100, 100);

                  return (
                    <div
                      key={i}
                      className={cn(
                        "p-4 rounded-xl border transition shadow-xs space-y-3",
                        anom.is_anomaly
                          ? "border-[var(--sd-danger)] bg-[var(--sd-danger-dim)]"
                          : "border-[var(--sd-border)] bg-[var(--sd-bg)]"
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-[var(--sd-text)]">{anom.metric}</span>
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono",
                            anom.is_anomaly
                              ? "bg-[var(--sd-danger)] text-white"
                              : "bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)]"
                          )}
                        >
                          {anom.is_anomaly ? "SPIKE ANOMALY" : "NORMAL"}
                        </span>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-baseline justify-between font-mono">
                          <span className="text-2xl font-bold text-[var(--sd-text)]">
                            {anom.current_value.toFixed(1)}
                          </span>
                          <span className="text-xs text-[var(--sd-text-muted)]">
                            Threshold: {threshold.toFixed(1)} {anom.unit}
                          </span>
                        </div>

                        {/* Progress Bar */}
                        <div className="h-2 w-full rounded-full bg-[var(--sd-border)] overflow-hidden">
                          <div
                            className={cn(
                              "h-full transition-all duration-300",
                              anom.is_anomaly ? "bg-[var(--sd-danger)]" : "bg-[var(--sd-pine)]"
                            )}
                            style={{ width: `${ratio}%` }}
                          />
                        </div>
                      </div>

                      <div className="text-[11px] text-[var(--sd-text-muted)] flex justify-between font-mono">
                        <span>μ: {anom.mean.toFixed(1)}</span>
                        <span>σ: {anom.stdDev.toFixed(1)}</span>
                        <span>Bound: {anom.threshold_3sigma ? "3σ" : "2σ"}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: YARA Rules */}
        {activeTab === "yara" && (
          <div className="space-y-3">
            {yaraRules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono">
                      {rule.severity}
                    </span>
                    <span className="font-mono text-xs font-bold text-[var(--sd-text)]">
                      {rule.name}
                    </span>
                    <span className="text-[11px] text-[var(--sd-text-muted)]">
                      Category: {rule.category}
                    </span>
                  </div>

                  <span className="text-xs font-mono text-[var(--sd-pine-bright)] font-semibold">
                    {rule.matches_today} matches today
                  </span>
                </div>

                <p className="text-xs text-[var(--sd-text-muted)]">{rule.description}</p>
                <div className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                  Target Inspection Zone: <code className="text-[var(--sd-text)]">{rule.target}</code>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: Sigma Rules */}
        {activeTab === "sigma" && (
          <div className="space-y-3">
            {sigmaRules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)] font-mono">
                      {rule.severity}
                    </span>
                    <span className="text-xs font-bold text-[var(--sd-text)]">{rule.title}</span>
                  </div>
                  <span className="text-xs font-mono text-[var(--sd-text)] font-semibold">
                    {rule.matches_today} matched
                  </span>
                </div>

                <p className="text-xs text-[var(--sd-text-muted)]">
                  Detection Logic: <code className="text-[var(--sd-text)] font-mono">{rule.detection_logic}</code>
                </p>
                <div className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                  Log Source: <code className="text-[var(--sd-text)]">{rule.logsource}</code>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 4: Ingestion & HMAC Webhooks */}
        {activeTab === "ingest" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Telemetry Card */}
              <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-3 shadow-xs">
                <h3 className="text-sm font-bold text-[var(--sd-text)] flex items-center gap-2">
                  <Radio className="h-4 w-4 text-[var(--sd-pine)]" />
                  gRPC Ingest Service &amp; PII Scrubbing
                </h3>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  In-flight regex tokenizer redacting sensitive credentials before events reach the NATS message bus.
                </p>

                <div className="space-y-2 pt-2">
                  <div className="flex justify-between text-xs py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Agent Handshake Protocol:</span>
                    <span className="font-mono text-[var(--sd-text)] font-semibold">mTLS v1.3 with X.509 cert</span>
                  </div>
                  <div className="flex justify-between text-xs py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Active Enrolled Endpoints:</span>
                    <span className="font-mono text-[var(--sd-text)] font-semibold">48 agents online</span>
                  </div>
                  <div className="flex justify-between text-xs py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Rate Limit Policy:</span>
                    <span className="font-mono text-[var(--sd-text)] font-semibold">10,000 ev/min per tenant</span>
                  </div>
                  <div className="flex justify-between text-xs py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">TimescaleDB Hypertable Events:</span>
                    <span className="font-mono text-[var(--sd-pine-bright)] font-semibold">148,290 records</span>
                  </div>
                </div>
              </div>

              {/* Webhook Dispatcher Card */}
              <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-3 shadow-xs">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-[var(--sd-text)] flex items-center gap-2">
                    <Send className="h-4 w-4 text-[var(--sd-pine)]" />
                    HMAC-SHA256 Webhook Dispatcher
                  </h3>
                  <button
                    onClick={dispatchTestWebhook}
                    disabled={loading}
                    className="px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-hover)] text-[#f7f4ed] text-xs font-semibold shadow-xs transition cursor-pointer"
                  >
                    Dispatch Test Webhook
                  </button>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  Dispatches signed webhook payloads with <code>X-ShieldDesk-Signature</code> and exponential backoff retry.
                </p>

                {webhookLog && (
                  <pre className="p-3 rounded-lg bg-[#121417] text-[#a9b7c6] font-mono text-[11px] overflow-x-auto max-h-48 whitespace-pre-wrap leading-relaxed">
                    {JSON.stringify(webhookLog, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 5: Alerts (Real-time Authentication Failures & Threats) */}
        {activeTab === "alerts" && (
          !isAuthorizedForAlerts ? (
            <div className="p-8 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] text-center space-y-3">
              <div className="inline-flex p-3 rounded-full bg-amber-500/10 text-amber-500">
                <Lock className="h-6 w-6" />
              </div>
              <h4 className="text-sm font-bold text-[var(--sd-text)]">
                Access Restricted: Security Alerts
              </h4>
              <p className="text-xs text-[var(--sd-text-muted)] max-w-md mx-auto">
                Real-time threat and authentication security alerts are strictly restricted to System Administrators and Globex SOC Analysts. Switch to System Admin or Globex Analyst persona to view real-time alert feeds.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Feedback toast */}
              {unblockFeedback && (
                <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                  <span>{unblockFeedback}</span>
                </div>
              )}

              {/* Autonomous IP Containment Active Banner */}
              {blockedIps.length > 0 && (
                <div className="p-4 rounded-xl border border-red-500/40 bg-red-500/10 space-y-3 shadow-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-[var(--sd-danger)] text-white">
                        <Ban className="h-4 w-4" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-[var(--sd-danger)] uppercase tracking-wider font-mono flex items-center gap-2">
                          <span>Autonomous IP Containment Active</span>
                          <span className="px-2 py-0.2 rounded-full bg-[var(--sd-danger)] text-white text-[10px]">
                            {blockedIps.length} Blocked
                          </span>
                        </h4>
                        <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                          IPs attempting login more than 5 times with invalid credentials are automatically blocked from authenticating.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap pt-1">
                    {blockedIps.map((b) => (
                      <div
                        key={b.ip}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--sd-panel)] border border-red-500/30 text-xs font-mono shadow-xs"
                      >
                        <span className="text-[var(--sd-danger)] font-bold">{b.ip}</span>
                        <span className="text-[10px] text-[var(--sd-text-muted)]">({b.attempts} attempts)</span>
                        <button
                          onClick={() => handleUnblockIp(b.ip)}
                          className="flex items-center gap-1 ml-1 px-2 py-0.5 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-[11px] font-sans font-semibold cursor-pointer transition"
                        >
                          <Unlock className="h-3 w-3" />
                          <span>Unblock</span>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] space-y-1 shadow-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-[var(--sd-text)] flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)]" />
                      <span>Authentication &amp; Threat Security Alerts</span>
                      {securityAlerts.length > 0 && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[var(--sd-danger)] text-white font-mono">
                          {securityAlerts.length} Active
                        </span>
                      )}
                    </h3>
                    <p className="text-xs text-[var(--sd-text-muted)] mt-1">
                      Continuous monitoring of unauthorized login attempts, credential brute-forcing, and anomalous access spikes with source IP &amp; target email attribution.
                    </p>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
                    <button
                      onClick={() => fetchThreatData()}
                      disabled={loading}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                    >
                      <RotateCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                      <span>Refresh</span>
                    </button>

                    {securityAlerts.length > 0 && (
                      <button
                        onClick={() => {
                          fetch("/api/threats", {
                            method: "POST",
                            headers: {
                              "Content-Type": "application/json",
                              "X-ShieldDesk-User": activeUserId,
                            },
                            body: JSON.stringify({ action: "reset_alerts" }),
                          }).then(() => {
                            setSecurityAlerts([]);
                            setBlockedIps([]);
                          });
                        }}
                        className="px-3 py-1.5 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs hover:bg-[var(--sd-panel-hover)] font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] cursor-pointer transition shadow-xs"
                      >
                        Clear All Alerts &amp; Reset Blocks
                      </button>
                    )}
                  </div>
                </div>
              </div>

            {securityAlerts.length > 0 ? (
              <div className="space-y-3">
                {securityAlerts.map((alert) => {
                  const isCritical = alert.severity === "critical";
                  const isHigh = alert.severity === "high";
                  const isIpCurrentlyBlocked =
                    alert.isBlocked || blockedIps.some((b) => b.ip === alert.clientIp);

                  return (
                    <div
                      key={alert.id}
                      className={cn(
                        "p-5 rounded-xl border shadow-xs space-y-4 animate-in fade-in duration-300",
                        isIpCurrentlyBlocked
                          ? "border-[var(--sd-danger)] bg-[var(--sd-danger-dim)]/80"
                          : isCritical
                          ? "border-[var(--sd-danger)] bg-[var(--sd-danger-dim)]"
                          : isHigh
                          ? "border-amber-500/50 bg-amber-500/10"
                          : "border-[var(--sd-border)] bg-[var(--sd-panel)]"
                      )}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[var(--sd-border)] pb-3">
                        <div className="flex items-center gap-2.5">
                          <div
                            className={cn(
                              "p-2 rounded-lg text-white",
                              isIpCurrentlyBlocked || isCritical
                                ? "bg-[var(--sd-danger)]"
                                : isHigh
                                ? "bg-amber-600"
                                : "bg-blue-600"
                            )}
                          >
                            <ShieldAlert className="h-5 w-5" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <h4 className="text-sm font-bold text-[var(--sd-text)]">
                                {alert.title}
                              </h4>
                              <span
                                className={cn(
                                  "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono",
                                  isIpCurrentlyBlocked || isCritical
                                    ? "bg-[var(--sd-danger)] text-white"
                                    : isHigh
                                    ? "bg-amber-600 text-white"
                                    : "bg-blue-600 text-white"
                                )}
                              >
                                {alert.severity} SEVERITY
                              </span>
                              {alert.attemptsCount > 1 && (
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
                                  {alert.attemptsCount} ATTEMPTS
                                </span>
                              )}
                              {isIpCurrentlyBlocked && (
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--sd-danger)] text-white border border-red-400 font-mono flex items-center gap-1 animate-pulse">
                                  <Ban className="h-3 w-3" />
                                  IP BLOCKED
                                </span>
                              )}
                            </div>
                            <span className="text-[11px] text-[var(--sd-text-muted)]">
                              Real-time authentication telemetry anomaly detection &amp; containment
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 self-start sm:self-center">
                          <span className="px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] font-mono flex items-center gap-1.5 shadow-xs">
                            <Lock className="h-3 w-3 text-[var(--sd-pine)]" />
                            SOC Verified Event
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                        <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                          <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                            <Mail className="h-3.5 w-3.5 text-blue-400" /> Target User Email
                          </span>
                          <p className="font-mono font-bold text-sm text-[var(--sd-text)] break-all" title={alert.targetUser}>
                            {alert.targetUser}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                          <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                            <Globe className="h-3.5 w-3.5 text-emerald-400" /> Source IP Address
                          </span>
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="font-mono font-bold text-sm text-emerald-400">
                              {alert.clientIp}
                            </p>
                            {isIpCurrentlyBlocked && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-[var(--sd-danger)] text-white font-mono flex items-center gap-1">
                                <Ban className="h-2.5 w-2.5" /> BLOCKED
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                          <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Failure Reason / Condition
                          </span>
                          <p className="font-semibold text-xs text-[var(--sd-danger)] line-clamp-2" title={alert.failureReason}>
                            {alert.failureReason}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                          <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                            <Clock className="h-3.5 w-3.5 text-purple-400" /> Detected Timestamp
                          </span>
                          <p className="font-mono text-xs text-[var(--sd-text)]">
                            {new Date(alert.createdAt).toLocaleTimeString()} ({alert.attemptsCount} attempt{alert.attemptsCount > 1 ? "s" : ""})
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center justify-end gap-2.5 pt-1 flex-wrap">
                        {isIpCurrentlyBlocked ? (
                          <button
                            onClick={() => handleUnblockIp(alert.clientIp)}
                            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-xs font-semibold transition cursor-pointer shadow-xs"
                          >
                            <Unlock className="h-3.5 w-3.5" />
                            <span>Unblock IP ({alert.clientIp})</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => handleBlockIp(alert.clientIp)}
                            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-danger)]/20 hover:text-[var(--sd-danger)] text-xs font-semibold text-[var(--sd-text-muted)] transition cursor-pointer shadow-xs"
                          >
                            <Ban className="h-3.5 w-3.5" />
                            <span>Block IP</span>
                          </button>
                        )}

                        <button
                          onClick={() => handleAcknowledgeAlert(alert.id)}
                          className="px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                        >
                          Acknowledge Alert
                        </button>

                        <button
                          onClick={() => handleInvestigateInChat(alert)}
                          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-bright)] text-white text-xs font-semibold transition cursor-pointer shadow-xs"
                        >
                          <Bot className="h-3.5 w-3.5" />
                          <span>Investigate in AI Chat</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] text-center space-y-3">
                <div className="inline-flex p-3 rounded-full bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)]">
                  <CheckCircle2 className="h-6 w-6" />
                </div>
                <h4 className="text-sm font-bold text-[var(--sd-text)]">
                  Zero Active Security Alerts
                </h4>
                <p className="text-xs text-[var(--sd-text-muted)] max-w-md mx-auto">
                  All authentication events and statistical baselines are nominal. Failed logins or anomaly bursts will appear here automatically with their source IP and target email.
                </p>
              </div>
            )}
          </div>
          )
        )}
      </main>
    </div>
  );
}

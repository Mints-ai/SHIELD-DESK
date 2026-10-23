"use client";

import React, { useState, useEffect, useCallback } from "react";
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
  RotateCcw,
  Sparkles,
  Layers,
  Bot,
  Lock,
  Globe,
  Mail,
  Clock,
  Ban,
  Unlock,
  Plus,
  Trash2,
  History,
  Terminal,
  Power,
  Code,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { YaraRuleTesterModal } from "@/components/threats/YaraRuleTesterModal";
import { YaraRuleCreatorModal } from "@/components/threats/YaraRuleCreatorModal";
import { YaraMatchHistoryModal } from "@/components/threats/YaraMatchHistoryModal";

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
  raw_content?: string;
  is_system?: boolean;
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

export interface IngestTelemetryInfo {
  agent_handshake_protocol?: string;
  active_agents_connected?: number;
  rate_limit_policy?: string;
  events_persisted_timescaledb?: number;
  pii_redacted_today?: number;
  bus_status?: string;
  events_per_minute?: number;
  pii_categories?: {
    jwt_tokens?: number;
    passwords_and_secrets?: number;
    credit_cards?: number;
    emails?: number;
  };
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

export interface WebhookEndpointItem {
  id: string;
  name: string;
  type: "discord" | "slack" | "teams" | "generic";
  destination: string;
  events: string[];
  min_severity?: string;
  is_custom?: boolean;
  enabled?: boolean;
  configured: boolean;
}

export interface WebhookDeliveryLogItem {
  id: string;
  delivery_id: string;
  tenant_id: string;
  endpoint_id: string;
  endpoint_name?: string;
  event_type: string;
  severity?: string;
  status_code?: number;
  latency_ms?: number;
  payload?: Record<string, unknown>;
  response_body?: string;
  success: boolean;
  attempts: number;
  is_dlq: boolean;
  status: "DELIVERED" | "DEAD_LETTER" | "RETRIED" | "PERMANENT_FAILURE";
  error_message?: string;
  destination?: string;
  last_attempt_at?: string;
  created_at: string;
}

export interface WebhookMetricsData {
  total_dispatches: number;
  delivered_count: number;
  dlq_pending_count: number;
  retried_count: number;
  success_rate: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  status_code_breakdown: {
    "2xx": number;
    "4xx": number;
    "5xx": number;
    timeout: number;
  };
}

function detectClientPlatform(urlStr: string): "discord" | "slack" | "teams" | null {
  try {
    const url = new URL(urlStr);
    const host = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    if (host.includes("discord.com") || host.includes("discordapp.com")) {
      if (pathname.includes("/api/webhooks")) return "discord";
    }
    if (host.includes("slack.com") || host.includes("hooks.slack.com")) {
      return "slack";
    }
    if (
      host.includes("office.com") ||
      host.includes("office365.com") ||
      host.includes("webhook.office.com") ||
      pathname.includes("incomingwebhook")
    ) {
      return "teams";
    }
    return null;
  } catch {
    return null;
  }
}

import { useChat } from "@/lib/context/ChatContext";

export default function ThreatsDashboardPage() {
  const { activeUserId, activeUser, openChatWithPrompt } = useChat();
  const [activeTab, setActiveTab] = useState<"yara" | "sigma" | "anomaly" | "ingest" | "alerts">("anomaly");
  const [loading, setLoading] = useState(false);
  const [yaraRules, setYaraRules] = useState<RuleItem[]>([]);
  const [sigmaRules, setSigmaRules] = useState<RuleItem[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyMetric[]>([]);
  const [telemetry, setTelemetry] = useState<IngestTelemetryInfo | null>(null);
  const [securityAlerts, setSecurityAlerts] = useState<ThreatSecurityAlert[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIpItem[]>([]);
  const [canViewAuthAlerts, setCanViewAuthAlerts] = useState<boolean>(false);
  const [unblockFeedback, setUnblockFeedback] = useState<string | null>(null);

  // YARA Sandbox, Creator & Match History State
  const [testerModalOpen, setTesterModalOpen] = useState(false);
  const [creatorModalOpen, setCreatorModalOpen] = useState(false);
  const [historyModalOpen, setHistoryModalOpen] = useState(false);
  const [testingRule, setTestingRule] = useState<{ id: string; name?: string; raw_content?: string } | null>(null);
  const [yaraFilter, setYaraFilter] = useState("");

  // Standardized operator roles for ShieldDesk SOC:
  // system_admin / super_admin: Admin privileges, baseline simulation & reset
  // responder: L3 containment operator (unblock/block IP, approve containment)
  // analyst: L1/L2 investigator (read-only containment, full observability)
  const isSystemAdmin =
    activeUserId === "dev-admin" ||
    activeUser?.role === "system_admin" ||
    activeUser?.role === "super_admin";

  const isResponder =
    activeUserId === "dev-responder" ||
    activeUser?.role === "responder";

  const isAnalyst =
    activeUserId === "dev-analyst" ||
    activeUser?.role === "analyst";

  const canManageContainment = isSystemAdmin || isResponder;
  const isAuthorizedForAlerts = isSystemAdmin || isResponder || isAnalyst || canViewAuthAlerts;

  // Auto-switch to anomaly tab if active persona is not authorized for alerts
  useEffect(() => {
    if (!isAuthorizedForAlerts && activeTab === "alerts") {
      void Promise.resolve().then(() => setActiveTab("anomaly"));
    }
  }, [isAuthorizedForAlerts, activeTab]);

  // Simulation Feedback
  const [simFeedback, setSimFeedback] = useState<string | null>(null);

  // Webhook State & Admin Management
  const [webhookLog, setWebhookLog] = useState<Record<string, unknown> | null>(null);
  const [webhookEndpoints, setWebhookEndpoints] = useState<WebhookEndpointItem[]>([]);
  const [canManageWebhooks, setCanManageWebhooks] = useState(false);
  const [addWebhookModalOpen, setAddWebhookModalOpen] = useState(false);
  const [newWebhookName, setNewWebhookName] = useState("");
  const [newWebhookType, setNewWebhookType] = useState<"slack" | "discord" | "teams" | "generic">("generic");
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [newWebhookSecret, setNewWebhookSecret] = useState("");
  const [newWebhookMinSeverity, setNewWebhookMinSeverity] = useState<"low" | "medium" | "high" | "critical">("medium");
  const [newWebhookEvents, setNewWebhookEvents] = useState<string[]>([
    "threat_detected",
    "approval_required",
    "incident_created",
    "lockdown.activated",
  ]);
  const [webhookCreating, setWebhookCreating] = useState(false);
  const [webhookFeedback, setWebhookFeedback] = useState<string | null>(null);
  const [selectedEndpointForTest, setSelectedEndpointForTest] = useState<string>("");
  const [webhookDeliveryLogs, setWebhookDeliveryLogs] = useState<WebhookDeliveryLogItem[]>([]);
  const [webhookMetrics, setWebhookMetrics] = useState<WebhookMetricsData | null>(null);
  const [webhookLogsFilter, setWebhookLogsFilter] = useState<"all" | "dlq" | "delivered">("all");
  const [retryingDeliveryId, setRetryingDeliveryId] = useState<string | null>(null);
  const [retryingAllDlq, setRetryingAllDlq] = useState<boolean>(false);
  const [inspectingLog, setInspectingLog] = useState<WebhookDeliveryLogItem | null>(null);
  const [autoDetectedPlatform, setAutoDetectedPlatform] = useState<"discord" | "slack" | "teams" | null>(null);

  const fetchThreatData = async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      const res = await fetch("/api/threats", {
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
      if (data.security_alerts) setSecurityAlerts(data.security_alerts);
      setCanViewAuthAlerts(Boolean(data.can_view_auth_alerts));

    } catch (err) {
      console.error("Failed to load threats:", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    let mounted = true;
    const pollData = async () => {
      try {
        const res = await fetch("/api/threats", {
          headers: {
            "X-ShieldDesk-User": activeUserId,
            "Cache-Control": "no-cache",
          },
        });
        const data = await res.json();
        if (!mounted) return;
        if (data.yara_rules) setYaraRules(data.yara_rules);
        if (data.sigma_rules) setSigmaRules(data.sigma_rules);
        if (data.anomaly_baselines) setAnomalies(data.anomaly_baselines);
        if (data.ingest_telemetry) setTelemetry(data.ingest_telemetry);
        if (data.blocked_ips) setBlockedIps(data.blocked_ips);
        if (data.security_alerts) setSecurityAlerts(data.security_alerts);
        setCanViewAuthAlerts(Boolean(data.can_view_auth_alerts));

      } catch (err) {
        console.error("Failed to load threats in polling:", err);
      }
    };

    void pollData();
    const interval = setInterval(() => {
      void pollData();
    }, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [activeUserId, isSystemAdmin, isResponder, isAnalyst, activeUser?.tenantId]);

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
        setBlockedIps((prev) => prev.filter((b) => b.ip !== ip));
        setSecurityAlerts((prev) =>
          prev.map((a) => (a.clientIp === ip ? { ...a, isBlocked: false } : a))
        );
        setUnblockFeedback(`IP ${ip} successfully unblocked and containment restored.`);
        setTimeout(() => setUnblockFeedback(null), 4000);
        await fetchThreatData(true);
      } else {
        setUnblockFeedback(`Failed to unblock IP ${ip}: ${data.error || "Permission denied"}`);
        setTimeout(() => setUnblockFeedback(null), 5000);
      }
    } catch (err) {
      console.error("Failed to unblock IP:", err);
      setUnblockFeedback(`Network error unblocking IP ${ip}`);
      setTimeout(() => setUnblockFeedback(null), 4000);
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

  const handleOpenTester = (rule?: RuleItem) => {
    if (rule) {
      setTestingRule({
        id: rule.id,
        name: rule.name || rule.id,
        raw_content: rule.raw_content,
      });
    } else {
      setTestingRule(null);
    }
    setTesterModalOpen(true);
  };

  const handleToggleYaraRule = async (rule: RuleItem) => {
    const nextStatus = rule.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
    setYaraRules((prev) =>
      prev.map((r) => (r.id === rule.id ? { ...r, status: nextStatus } : r))
    );

    try {
      await fetch(`/api/threats/yara/${rule.id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ enabled: nextStatus === "ACTIVE" }),
      });
      fetchThreatData(true);
    } catch (err) {
      console.error("Failed to toggle YARA rule:", err);
      fetchThreatData(true);
    }
  };

  const handleDeleteYaraRule = async (rule: RuleItem) => {
    if (rule.is_system) return;
    if (!confirm(`Delete custom YARA rule "${rule.name || rule.id}"?`)) return;

    try {
      const res = await fetch(`/api/threats/yara/${rule.id}`, {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      if (res.ok) {
        setYaraRules((prev) => prev.filter((r) => r.id !== rule.id));
      }
    } catch (err) {
      console.error("Failed to delete YARA rule:", err);
    }
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

  const fetchWebhookEndpoints = useCallback(async (filter = webhookLogsFilter) => {
    try {
      const res = await fetch(`/api/webhooks?status=${filter}&limit=50`, {
        headers: {
          "X-ShieldDesk-User": activeUserId,
        },
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.endpoints)) {
          setWebhookEndpoints(data.endpoints);
          if (data.endpoints.length > 0) {
            setSelectedEndpointForTest((prev) => prev || data.endpoints[0].id);
          }
        }
        if (Array.isArray(data.delivery_logs)) {
          setWebhookDeliveryLogs(data.delivery_logs);
        }
        if (data.metrics) {
          setWebhookMetrics(data.metrics);
        }
        setCanManageWebhooks(Boolean(data.can_manage_webhooks));
      }
    } catch (err) {
      console.error("Failed to load webhook endpoints:", err);
    }
  }, [activeUserId, webhookLogsFilter]);

  useEffect(() => {
    if (activeTab === "ingest") {
      void Promise.resolve().then(() => fetchWebhookEndpoints(webhookLogsFilter));
    }
  }, [activeTab, webhookLogsFilter, fetchWebhookEndpoints]);

  const dispatchTestWebhook = async (endpointId?: string) => {
    setLoading(true);
    try {
      const targetId = endpointId || selectedEndpointForTest;
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify(targetId ? { endpoint_id: targetId } : {}),
      });
      const data = await res.json();
      setWebhookLog(data);
      await fetchWebhookEndpoints();
    } catch {
      setWebhookLog({ message: "Failed to dispatch test webhook" });
    } finally {
      setLoading(false);
    }
  };

  const handleRetryDelivery = async (deliveryId: string) => {
    setRetryingDeliveryId(deliveryId);
    try {
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: "retry_delivery",
          delivery_id: deliveryId,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setWebhookFeedback(`Webhook delivery '${deliveryId}' replayed successfully (${data.log?.latency_ms ?? 0}ms).`);
      } else {
        setWebhookFeedback(`Retry failed: ${data.message || data.error || "Unknown error"}`);
      }
      setTimeout(() => setWebhookFeedback(null), 4000);
      await fetchWebhookEndpoints();
    } catch {
      setWebhookFeedback("Network error retrying webhook delivery.");
    } finally {
      setRetryingDeliveryId(null);
    }
  };

  const handleRetryAllDlq = async () => {
    setRetryingAllDlq(true);
    try {
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: "retry_all_dlq",
        }),
      });
      const data = await res.json();
      if (data.success) {
        setWebhookFeedback(data.message || `DLQ replay complete: ${data.succeeded_count} recovered.`);
      } else {
        setWebhookFeedback(`Batch retry error: ${data.error || "Failed to batch retry"}`);
      }
      setTimeout(() => setWebhookFeedback(null), 5000);
      await fetchWebhookEndpoints();
    } catch {
      setWebhookFeedback("Network error replaying DLQ batch.");
    } finally {
      setRetryingAllDlq(false);
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWebhookName.trim() || !newWebhookUrl.trim()) return;

    setWebhookCreating(true);
    setWebhookFeedback(null);
    try {
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          action: "create_endpoint",
          name: newWebhookName.trim(),
          type: newWebhookType,
          destination: newWebhookUrl.trim(),
          secret_key: newWebhookSecret.trim() || undefined,
          min_severity: newWebhookMinSeverity,
          events: newWebhookEvents,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setWebhookFeedback(`Webhook '${newWebhookName}' created successfully.`);
        setTimeout(() => setWebhookFeedback(null), 4000);
        setAddWebhookModalOpen(false);
        setNewWebhookName("");
        setNewWebhookUrl("");
        setNewWebhookSecret("");
        await fetchWebhookEndpoints();
      } else {
        setWebhookFeedback(`Error: ${data.error || "Failed to create webhook"}`);
      }
    } catch {
      setWebhookFeedback("Network error creating webhook endpoint.");
    } finally {
      setWebhookCreating(false);
    }
  };

  const handleToggleWebhook = async (endpoint: WebhookEndpointItem) => {
    try {
      const nextEnabled = !endpoint.enabled;
      const res = await fetch("/api/webhooks", {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          id: endpoint.id,
          enabled: nextEnabled,
        }),
      });
      if (res.ok) {
        setWebhookEndpoints((prev) =>
          prev.map((ep) => (ep.id === endpoint.id ? { ...ep, enabled: nextEnabled, configured: nextEnabled } : ep))
        );
        setWebhookFeedback(`Webhook '${endpoint.name}' ${nextEnabled ? "resumed" : "paused"}.`);
        setTimeout(() => setWebhookFeedback(null), 3000);
      }
    } catch (err) {
      console.error("Failed to toggle webhook:", err);
    }
  };

  const handleDeleteWebhook = async (id: string, name: string) => {
    if (!confirm(`Delete custom webhook endpoint "${name}"?`)) return;
    try {
      const res = await fetch(`/api/webhooks?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: {
          "X-ShieldDesk-User": activeUserId,
        },
      });
      if (res.ok) {
        setWebhookEndpoints((prev) => prev.filter((ep) => ep.id !== id));
        setWebhookFeedback(`Webhook '${name}' deleted successfully.`);
        setTimeout(() => setWebhookFeedback(null), 3000);
      }
    } catch (err) {
      console.error("Failed to delete webhook:", err);
    }
  };

  const [resettingPii, setResettingPii] = useState(false);

  const handleResetPIIMetrics = async () => {
    setResettingPii(true);
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({ action: "reset_pii" }),
      });
      if (res.ok) {
        await fetchThreatData(true);
      }
    } catch (e) {
      console.error("Failed to reset PII metrics:", e);
    } finally {
      setResettingPii(false);
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="p-2 shrink-0 rounded-xl sd-surface border border-[var(--sd-border)] text-[var(--sd-wheat)]">
                <Flame className="h-5 w-5" />
              </div>
              <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                Threat intelligence
              </h1>
            </div>
            <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
              Go gRPC streaming ingestion, YARA/Sigma rule matching, 3-sigma statistical anomaly scoring, and HMAC webhooks.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)] border border-[var(--sd-pine-border)] flex items-center gap-1.5 font-mono">
              <Radio className="h-3 w-3" />
              gRPC Ingest: 4,120 ev/min
            </span>

            <button
              onClick={() => fetchThreatData()}
              disabled={loading}
              className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
              title="Refresh threat alerts and telemetry"
            >
              <RotateCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>Refresh</span>
            </button>

            {isSystemAdmin && (
              <div className="flex items-center gap-2">
                <button
                  onClick={triggerAnomalySimulation}
                  disabled={loading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-danger)] hover:bg-[var(--sd-danger)]/90 text-[var(--sd-on-accent)] text-xs font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
                  title="Simulate 3-sigma anomaly burst across telemetry streams"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  <span>Simulate Anomaly Burst</span>
                </button>

                {anomalies.some((a) => a.is_anomaly) && (
                  <button
                    onClick={resetAnomaly}
                    disabled={loading}
                    className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] hover:bg-[var(--sd-success-border)] text-[var(--sd-success)] text-xs font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
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
            <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--sd-danger)]" />
            <span className="font-medium truncate">{simFeedback}</span>
          </div>
        )}


        {/* Stat Highlights */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">Active Threat Rules</span>
              <Binary className="h-4 w-4 text-[var(--sd-pine)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-text)] font-mono">
              {yaraRules.length + sigmaRules.length}
            </div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">YARA Malware + Sigma Behavioral</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">3σ Anomaly Baselines</span>
              <Activity className="h-4 w-4 text-[var(--sd-warning)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-text)] font-mono">
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
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">Rolling statistical bounds</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">PII Scrubbed Today</span>
              <EyeOff className="h-4 w-4 text-[var(--sd-pine-bright)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-text)] font-mono">
              {(telemetry?.pii_redacted_today ?? 0).toLocaleString()}
            </div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">Zero plaintext tokens on bus</p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
            <div className="flex items-center justify-between text-[var(--sd-text-muted)] mb-1">
              <span className="text-[13px] font-medium">Ingestion Throughput</span>
              <Radio className="h-4 w-4 text-[var(--sd-pine)]" />
            </div>
            <div className="text-2xl font-medium text-[var(--sd-pine-bright)] font-mono">
              {(telemetry?.events_per_minute ?? 0).toLocaleString()} / 10k
            </div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-1">Events/min capacity</p>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="sd-tabs" role="group" aria-label="Threats views">
          <button type="button" aria-pressed={activeTab === "anomaly"} onClick={() => setActiveTab("anomaly")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Activity className="h-3.5 w-3.5" />
            <span>Anomaly detection</span>
          </button>

          <button type="button" aria-pressed={activeTab === "yara"} onClick={() => setActiveTab("yara")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Binary className="h-3.5 w-3.5" />
            <span>YARA rules ({yaraRules.length})</span>
          </button>

          <button type="button" aria-pressed={activeTab === "sigma"} onClick={() => setActiveTab("sigma")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Layers className="h-3.5 w-3.5" />
            <span>Sigma rules ({sigmaRules.length})</span>
          </button>

          <button type="button" aria-pressed={activeTab === "ingest"} onClick={() => setActiveTab("ingest")} className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            <Send className="h-3.5 w-3.5" />
            <span>Ingestion &amp; webhooks</span>
          </button>

          {isAuthorizedForAlerts && (
            <button
              onClick={() => setActiveTab("alerts")}
              className={cn(
                "px-4 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-2",
                activeTab === "alerts"
                  ? "border-[var(--sd-danger)] text-[var(--sd-danger)]"
                  : "border-transparent text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
              )}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Alerts</span>
              {securityAlerts.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-medium bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono">
                  {securityAlerts.length}
                </span>
              )}
            </button>
          )}
        </div>

        {/* Tab 1: 3-Sigma Anomaly Baselines */}
        {activeTab === "anomaly" && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface space-y-4 shadow-xs">
              <div>
                <h3 className="text-sm font-medium text-[var(--sd-text)]">
                  Statistical Anomaly Engine (3σ Autonomic Baselines)
                </h3>
                <p className="text-[13px] text-[var(--sd-text-muted)] mt-1">
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
                        <span className="text-[13px] font-medium text-[var(--sd-text)]">{anom.metric}</span>
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider font-mono",
                            anom.is_anomaly
                              ? "bg-[var(--sd-danger)] text-[var(--sd-on-accent)]"
                              : "bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)]"
                          )}
                        >
                          {anom.is_anomaly ? "SPIKE ANOMALY" : "NORMAL"}
                        </span>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-baseline justify-between font-mono">
                          <span className="text-2xl font-medium text-[var(--sd-text)]">
                            {anom.current_value.toFixed(1)}
                          </span>
                          <span className="text-[13px] text-[var(--sd-text-muted)]">
                            Threshold: {threshold.toFixed(1)} {anom.unit}
                          </span>
                        </div>

                        {/* Progress Bar */}
                        <div className="h-2 w-full rounded-full bg-[var(--sd-border)] overflow-hidden">
                          <div
                            className={cn(
                              "h-full transition-all duration-200",
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
          <div className="space-y-4">
            {/* YARA Toolbar */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs">
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <input
                  type="text"
                  value={yaraFilter}
                  onChange={(e) => setYaraFilter(e.target.value)}
                  placeholder="Filter rules by name, ID, or category..."
                  className="w-full sm:w-64 bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
                />
                <span className="text-xs text-[var(--sd-text-muted)] whitespace-nowrap">
                  {yaraRules.filter((r) => r.status === "ACTIVE").length} active / {yaraRules.length} rules
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleOpenTester()}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-pine-border)] bg-[var(--sd-pine-dim)] hover:bg-[var(--sd-pine-border)] text-[var(--sd-pine-bright)] text-xs font-medium shadow-xs transition cursor-pointer"
                  title="Open YARA sandbox to scan arbitrary payloads"
                >
                  <Terminal className="h-3.5 w-3.5" />
                  <span>Rule Tester Sandbox</span>
                </button>

                <button
                  type="button"
                  onClick={() => setCreatorModalOpen(true)}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-bright)] text-black text-xs font-medium shadow-xs transition cursor-pointer"
                  title="Author a new custom YARA malware rule"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>New Custom Rule</span>
                </button>

                <button
                  type="button"
                  onClick={() => setHistoryModalOpen(true)}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] text-[var(--sd-text)] text-xs font-medium shadow-xs transition cursor-pointer"
                  title="View recent detections and linked incidents"
                >
                  <History className="h-3.5 w-3.5" />
                  <span>Match History</span>
                </button>
              </div>
            </div>

            {/* Live Rules List */}
            <div className="space-y-3">
              {yaraRules
                .filter((r) => {
                  if (!yaraFilter) return true;
                  const q = yaraFilter.toLowerCase();
                  return (
                    (r.name && r.name.toLowerCase().includes(q)) ||
                    r.id.toLowerCase().includes(q) ||
                    (r.category && r.category.toLowerCase().includes(q)) ||
                    (r.description && r.description.toLowerCase().includes(q))
                  );
                })
                .map((rule) => {
                  const isActive = rule.status === "ACTIVE";
                  const sevLower = (rule.severity || "medium").toLowerCase();
                  const sevColor =
                    sevLower === "critical"
                      ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border-[var(--sd-danger-border)]"
                      : sevLower === "high"
                      ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]"
                      : "bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)] border-[var(--sd-pine-border)]";

                  return (
                    <div
                      key={rule.id}
                      className={`p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-3 transition ${
                        !isActive ? "opacity-60 bg-[var(--sd-bg)]" : ""
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider border font-mono ${sevColor}`}
                          >
                            {rule.severity}
                          </span>
                          <span className="font-mono text-sm font-medium text-[var(--sd-text)]">
                            {rule.name || rule.id}
                          </span>
                          <span className="text-[11px] font-mono text-[var(--sd-text-muted)] bg-[var(--sd-surface-subtle)] px-2 py-0.5 rounded border border-[var(--sd-border)]">
                            {rule.id}
                          </span>
                          {rule.is_system ? (
                            <span className="text-[10px] font-mono text-[var(--sd-pine-bright)] bg-[var(--sd-pine-dim)] border border-[var(--sd-pine-border)] px-1.5 py-0.5 rounded">
                              SYSTEM
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono text-[var(--sd-warning)] bg-[var(--sd-warning-dim)] border border-[var(--sd-warning-border)] px-1.5 py-0.5 rounded">
                              CUSTOM
                            </span>
                          )}
                          <span className="text-[11px] text-[var(--sd-text-muted)]">
                            • {rule.category}
                          </span>
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="text-xs font-mono font-medium text-[var(--sd-pine-bright)]">
                            {rule.matches_today} matches today
                          </span>

                          {/* Toggle Active Switch */}
                          <button
                            type="button"
                            onClick={() => handleToggleYaraRule(rule)}
                            className={`px-2.5 py-1 rounded-md text-xs font-mono font-medium flex items-center gap-1 border transition cursor-pointer ${
                              isActive
                                ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]"
                                : "bg-[var(--sd-surface-subtle)] text-[var(--sd-text-muted)] border-[var(--sd-border)]"
                            }`}
                            title={isActive ? "Click to disable rule" : "Click to enable rule"}
                          >
                            <Power className="h-3 w-3" />
                            <span>{isActive ? "ACTIVE" : "DISABLED"}</span>
                          </button>
                        </div>
                      </div>

                      <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
                        {rule.description}
                      </p>

                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1 border-t border-[var(--sd-border)] text-xs">
                        <div className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                          Target Inspection Zone:{" "}
                          <code className="text-[var(--sd-text)] bg-[var(--sd-bg)] px-1.5 py-0.5 rounded border border-[var(--sd-border)]">
                            {rule.target || "endpoint telemetry"}
                          </code>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleOpenTester(rule)}
                            className="px-2.5 py-1 text-[11px] font-medium text-[var(--sd-pine-bright)] hover:bg-[var(--sd-pine-dim)] rounded-md border border-[var(--sd-pine-border)] flex items-center gap-1 transition cursor-pointer"
                          >
                            <Code className="h-3 w-3" />
                            <span>Test in Sandbox</span>
                          </button>

                          {!rule.is_system && (
                            <button
                              type="button"
                              onClick={() => handleDeleteYaraRule(rule)}
                              className="p-1 text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)] rounded-md transition cursor-pointer"
                              title="Delete custom rule"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        )}

        {/* Tab 3: Sigma Rules */}
        {activeTab === "sigma" && (
          <div className="space-y-3">
            {sigmaRules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)] font-mono">
                      {rule.severity}
                    </span>
                    <span className="text-[13px] font-medium text-[var(--sd-text)]">{rule.title}</span>
                  </div>
                  <span className="text-[13px] font-mono text-[var(--sd-text)] font-medium">
                    {rule.matches_today} matched
                  </span>
                </div>

                <p className="text-[13px] text-[var(--sd-text-muted)]">
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
            {/* KPI Performance Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-1">
                <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                  Total Deliveries
                </div>
                <div className="text-xl font-light text-[var(--sd-text)] font-mono">
                  {(webhookMetrics?.total_dispatches ?? 0).toLocaleString()}
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)]">All time audit events</div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-1">
                <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                  Success Rate
                </div>
                <div className="text-xl font-light text-emerald-400 font-mono">
                  {webhookMetrics?.success_rate ?? 100}%
                </div>
                <div className="text-[10px] text-emerald-400/80">
                  {webhookMetrics?.delivered_count ?? 0} delivered
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-1">
                <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                  Average Latency
                </div>
                <div className="text-xl font-light text-[var(--sd-pine-bright)] font-mono">
                  {webhookMetrics?.avg_latency_ms ?? 0}ms
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)]">Target response time</div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-1">
                <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                  P95 Latency
                </div>
                <div className="text-xl font-light text-[var(--sd-wheat)] font-mono">
                  {webhookMetrics?.p95_latency_ms ?? 0}ms
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)]">95th percentile SLA</div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-1 col-span-2 sm:col-span-1">
                <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                  DLQ Pending
                </div>
                <div
                  className={cn(
                    "text-xl font-mono font-medium",
                    (webhookMetrics?.dlq_pending_count ?? 0) > 0 ? "text-rose-400 font-bold" : "text-[var(--sd-text-muted)]"
                  )}
                >
                  {webhookMetrics?.dlq_pending_count ?? 0}
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)]">
                  {(webhookMetrics?.dlq_pending_count ?? 0) > 0 ? "Requires re-dispatch" : "Queue nominal"}
                </div>
              </div>
            </div>

            <div className="space-y-5">
              {/* Telemetry Card - Full Width Stacked */}
              <div className="p-5 rounded-xl border border-[var(--sd-border)] sd-surface space-y-4 shadow-xs">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                    <Radio className="h-4 w-4 text-[var(--sd-pine)]" />
                    <span>gRPC Ingest Service &amp; PII Scrubbing</span>
                  </h3>
                  <button
                    onClick={handleResetPIIMetrics}
                    disabled={resettingPii}
                    className="sd-button sd-button-secondary px-2.5 py-1 rounded-full text-xs font-medium cursor-pointer flex items-center gap-1.5"
                    title="Reset live PII redaction metrics"
                  >
                    <RotateCcw className="h-3 w-3 text-[var(--sd-pine-bright)]" />
                    {resettingPii ? "Resetting..." : "Reset"}
                  </button>
                </div>
                <p className="text-[13px] text-[var(--sd-text-muted)]">
                  In-flight regex tokenizer redacting sensitive credentials before events reach the NATS message bus.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5 pt-2">
                  <div className="flex justify-between text-[13px] py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Agent Handshake Protocol:</span>
                    <span className="font-mono text-[var(--sd-text)] font-medium">
                      {telemetry?.agent_handshake_protocol || "mTLS v1.3 with X.509 cert"}
                    </span>
                  </div>
                  <div className="flex justify-between text-[13px] py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Active Enrolled Endpoints:</span>
                    <span className="font-mono text-[var(--sd-text)] font-medium">
                      {telemetry?.active_agents_connected ?? 0} {telemetry?.active_agents_connected === 1 ? "agent" : "agents"} online
                    </span>
                  </div>
                  <div className="flex justify-between text-[13px] py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Rate Limit Policy:</span>
                    <span className="font-mono text-[var(--sd-text)] font-medium">
                      {telemetry?.rate_limit_policy || "10,000 ev/min per tenant"}
                    </span>
                  </div>
                  <div className="flex justify-between text-[13px] py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Telemetry Database Records:</span>
                    <span className="font-mono text-[var(--sd-pine-bright)] font-medium">
                      {(telemetry?.events_persisted_timescaledb ?? 0).toLocaleString()} records
                    </span>
                  </div>
                  <div className="flex justify-between text-[13px] py-1.5 border-b border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">PII Tokens Scrubbed Today:</span>
                    <span className="font-mono text-[var(--sd-pine-bright)] font-medium">
                      {(telemetry?.pii_redacted_today ?? 0).toLocaleString()} redacted
                    </span>
                  </div>
                  <div className="flex justify-between text-[13px] py-1.5 border-b md:border-b-0 border-[var(--sd-border)]">
                    <span className="text-[var(--sd-text-muted)]">Ingestion Message Bus:</span>
                    <span className="font-mono text-[var(--sd-text)] font-medium">
                      {telemetry?.bus_status || "Active Ingestion Loop"}
                    </span>
                  </div>
                </div>

                {/* Live PII Token Redaction Breakdown */}
                <div className="mt-2 pt-3 border-t border-[var(--sd-border)]">
                  <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider mb-2">
                    Live PII Redaction Breakdown
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
                    <div className="p-2.5 rounded-lg bg-[var(--sd-surface-subtle)] border border-[var(--sd-border)]">
                      <div className="text-[var(--sd-text-muted)] text-[11px]">JWT Tokens</div>
                      <div className="font-mono font-medium text-sm text-[var(--sd-text)] mt-0.5">
                        {(telemetry?.pii_categories?.jwt_tokens ?? 0).toLocaleString()}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[var(--sd-surface-subtle)] border border-[var(--sd-border)]">
                      <div className="text-[var(--sd-text-muted)] text-[11px]">Secrets / Keys</div>
                      <div className="font-mono font-medium text-sm text-[var(--sd-text)] mt-0.5">
                        {(telemetry?.pii_categories?.passwords_and_secrets ?? 0).toLocaleString()}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[var(--sd-surface-subtle)] border border-[var(--sd-border)]">
                      <div className="text-[var(--sd-text-muted)] text-[11px]">Credit Cards</div>
                      <div className="font-mono font-medium text-sm text-[var(--sd-text)] mt-0.5">
                        {(telemetry?.pii_categories?.credit_cards ?? 0).toLocaleString()}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[var(--sd-surface-subtle)] border border-[var(--sd-border)]">
                      <div className="text-[var(--sd-text-muted)] text-[11px]">User Emails</div>
                      <div className="font-mono font-medium text-sm text-[var(--sd-text)] mt-0.5">
                        {(telemetry?.pii_categories?.emails ?? 0).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Webhook Management & Dynamic Dispatcher */}
              <div className="p-5 rounded-xl border border-[var(--sd-border)] sd-surface space-y-5 shadow-xs">
                {webhookFeedback && (
                  <div className="p-3 rounded-lg border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] text-[var(--sd-success)] text-xs font-medium flex items-center justify-between gap-2 shadow-xs">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      <span>{webhookFeedback}</span>
                    </div>
                    <button
                      onClick={() => setWebhookFeedback(null)}
                      className="text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] text-xs font-mono"
                    >
                      ✕
                    </button>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--sd-border)] pb-4">
                  <div>
                    <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                      <Send className="h-4 w-4 text-[var(--sd-pine)]" />
                      <span>Registered Webhook Endpoints (Multi-Tenant)</span>
                      <span className="px-2 py-0.2 rounded-full text-[10px] font-mono bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]">
                        {webhookEndpoints.length} configured
                      </span>
                    </h3>
                    <p className="text-xs text-[var(--sd-text-muted)] mt-1">
                      Real-time HMAC-SHA256 authenticated alert dispatching across Slack, Teams, Discord, and external SIEM/SOAR platforms.
                    </p>
                  </div>

                  <div className="flex items-center gap-2 self-start sm:self-auto">
                    {isSystemAdmin || canManageWebhooks ? (
                      <button
                        onClick={() => setAddWebhookModalOpen(true)}
                        className="sd-button sd-button-primary flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-[var(--sd-on-accent)] transition cursor-pointer shadow-xs"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        <span>Add Webhook Endpoint</span>
                      </button>
                    ) : (
                      <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] text-xs font-medium shadow-xs">
                        <Lock className="h-3 w-3" />
                        <span>Admin Managed (Read-Only)</span>
                      </span>
                    )}

                    <button
                      onClick={() => fetchWebhookEndpoints()}
                      disabled={loading}
                      title="Refresh endpoints"
                      className="p-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                    >
                      <RotateCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                    </button>
                  </div>
                </div>

                {/* Webhooks Grid */}
                {webhookEndpoints.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                    {webhookEndpoints.map((ep) => {
                      const isDiscord = ep.type === "discord";
                      const isSlack = ep.type === "slack";
                      const isTeams = ep.type === "teams";

                      return (
                        <div
                          key={ep.id}
                          className={cn(
                            "p-4 rounded-xl border transition shadow-xs space-y-3",
                            ep.enabled !== false
                              ? "border-[var(--sd-border)] bg-[var(--sd-panel)]"
                              : "border-[var(--sd-border)] bg-[var(--sd-bg)] opacity-70"
                          )}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2 min-w-0">
                              <span
                                className={cn(
                                  "px-2 py-0.5 rounded text-[10px] font-mono font-medium uppercase tracking-wider",
                                  isDiscord
                                    ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                                    : isSlack
                                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                      : isTeams
                                        ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                                        : "bg-[var(--sd-wheat)]/10 text-[var(--sd-wheat)] border border-[var(--sd-wheat)]/20"
                                )}
                              >
                                {ep.type}
                              </span>
                              <h4 className="text-xs font-medium text-[var(--sd-text)] truncate" title={ep.name}>
                                {ep.name}
                              </h4>
                            </div>

                            <div className="flex items-center gap-1.5 shrink-0">
                              <span
                                className={cn(
                                  "px-2 py-0.5 rounded text-[10px] font-mono font-medium",
                                  ep.enabled !== false
                                    ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]"
                                    : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                                )}
                              >
                                {ep.enabled !== false ? "Active" : "Paused"}
                              </span>

                              {ep.is_custom ? (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                  Custom
                                </span>
                              ) : (
                                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]">
                                  System
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="space-y-1.5 text-xs">
                            <div className="flex items-center justify-between text-[11px] font-mono text-[var(--sd-text-muted)] bg-[var(--sd-bg)] p-2 rounded-lg border border-[var(--sd-border)]">
                              <span className="truncate" title={ep.destination}>
                                {ep.destination}
                              </span>
                              <span className="uppercase text-[9px] px-1.5 py-0.2 rounded bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] ml-2 shrink-0">
                                {ep.min_severity || "medium"} min
                              </span>
                            </div>

                            {ep.events && ep.events.length > 0 && (
                              <div className="flex items-center gap-1 flex-wrap pt-0.5">
                                {ep.events.slice(0, 3).map((ev) => (
                                  <span
                                    key={ev}
                                    className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                                  >
                                    {ev}
                                  </span>
                                ))}
                                {ep.events.length > 3 && (
                                  <span className="text-[9px] text-[var(--sd-text-muted)] font-mono">
                                    +{ep.events.length - 3} more
                                  </span>
                                )}
                              </div>
                            )}
                          </div>

                          <div className="flex items-center justify-between pt-2 border-t border-[var(--sd-border)]">
                            <button
                              onClick={() => dispatchTestWebhook(ep.id)}
                              disabled={loading}
                              className="sd-button flex items-center gap-1 px-2.5 py-1 rounded bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)] text-[11px] font-medium border border-[var(--sd-border)] transition cursor-pointer shadow-xs"
                            >
                              <Send className="h-3 w-3 text-[var(--sd-pine)]" />
                              <span>Test Dispatch</span>
                            </button>

                            <div className="flex items-center gap-1.5">
                              {ep.is_custom && (isSystemAdmin || canManageWebhooks) ? (
                                <>
                                  <button
                                    onClick={() => handleToggleWebhook(ep)}
                                    className="px-2 py-1 rounded text-[11px] font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] border border-[var(--sd-border)] transition cursor-pointer"
                                  >
                                    {ep.enabled !== false ? "Pause" : "Resume"}
                                  </button>
                                  <button
                                    onClick={() => handleDeleteWebhook(ep.id, ep.name)}
                                    title="Delete endpoint"
                                    className="p-1 rounded text-[var(--sd-text-muted)] hover:text-[var(--sd-danger)] hover:bg-[var(--sd-danger-dim)] transition cursor-pointer"
                                  >
                                    <Trash2 className="h-3.5 w-3.5" />
                                  </button>
                                </>
                              ) : (
                                <span className="text-[10px] text-[var(--sd-text-muted)] font-mono">
                                  Server Env Controlled
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="p-8 text-center rounded-xl border border-dashed border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2">
                    <Send className="h-8 w-8 text-[var(--sd-text-muted)] mx-auto opacity-50" />
                    <p className="text-xs text-[var(--sd-text-muted)]">
                      No webhook endpoints registered yet. Connect Slack, Discord, or your SIEM to stream live security alerts.
                    </p>
                    {(isSystemAdmin || canManageWebhooks) && (
                      <button
                        onClick={() => setAddWebhookModalOpen(true)}
                        className="sd-button sd-button-primary px-3 py-1.5 rounded-lg text-xs font-medium text-[var(--sd-on-accent)] inline-flex items-center gap-1.5 mt-2 cursor-pointer shadow-xs"
                      >
                        <Plus className="h-3.5 w-3.5" />
                        <span>Add First Webhook</span>
                      </button>
                    )}
                  </div>
                )}

                {/* Sandbox Dispatcher Card */}
                <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-3 shadow-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h4 className="text-xs font-medium text-[var(--sd-text)] flex items-center gap-1.5 font-mono uppercase tracking-wider">
                        <Terminal className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                        <span>Live HMAC Dispatch Sandbox</span>
                      </h4>
                      <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5">
                        Fires an authenticated verification payload signed with <code>X-ShieldDesk-Signature</code>.
                      </p>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      {webhookEndpoints.length > 0 && (
                        <select
                          value={selectedEndpointForTest}
                          onChange={(e) => setSelectedEndpointForTest(e.target.value)}
                          className="px-2.5 py-1.5 rounded-lg bg-[var(--sd-panel)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] font-mono cursor-pointer shadow-xs"
                        >
                          {webhookEndpoints.map((ep) => (
                            <option key={ep.id} value={ep.id}>
                              {ep.name} ({ep.type})
                            </option>
                          ))}
                        </select>
                      )}

                      <button
                        onClick={() => dispatchTestWebhook()}
                        disabled={loading || webhookEndpoints.length === 0}
                        className="sd-button sd-button-primary px-3 py-1.5 rounded-lg text-[var(--sd-on-accent)] text-xs font-medium shadow-xs transition cursor-pointer flex items-center gap-1.5"
                      >
                        <Send className={cn("h-3 w-3", loading && "animate-spin")} />
                        <span>Dispatch Test Webhook</span>
                      </button>
                    </div>
                  </div>

                  {webhookLog && (
                    <div className="space-y-2 pt-2 border-t border-[var(--sd-border)]">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-[var(--sd-text-muted)]">Dispatch Result:</span>
                        <span className={webhookLog.success ? "text-emerald-500 font-semibold" : "text-amber-500 font-semibold"}>
                          {webhookLog.message ? String(webhookLog.message) : (webhookLog.success ? "Success (200 OK)" : "Failed")}
                        </span>
                      </div>
                      <pre className="p-3 rounded-lg bg-[var(--sd-panel)] text-[var(--sd-text-muted)] font-mono text-[11px] overflow-x-auto max-h-48 whitespace-pre-wrap leading-relaxed border border-[var(--sd-border)]">
                        {JSON.stringify(webhookLog, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>

                {/* Subsection: Delivery History & DLQ Audit Ledger Table */}
                <div className="pt-6 border-t border-[var(--sd-border)] space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--sd-border)] pb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-[var(--sd-panel)] text-[var(--sd-pine-bright)] border border-[var(--sd-border)]">
                        <History className="h-4 w-4" />
                      </div>
                      <div>
                        <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                          <span>Delivery History &amp; Dead-Letter Queue (DLQ)</span>
                          <span className="px-2 py-0.2 rounded-full text-[10px] font-mono bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]">
                            {webhookDeliveryLogs.length} events
                          </span>
                        </h3>
                        <p className="text-xs text-[var(--sd-text-muted)]">
                          Millisecond-resolution audit trail of all outbound alert dispatches with replay recovery.
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Status filter tabs */}
                      <div className="inline-flex rounded-lg p-0.5 bg-[var(--sd-panel)] border border-[var(--sd-border)] text-xs">
                        <button
                          onClick={() => setWebhookLogsFilter("all")}
                          className={cn(
                            "px-2.5 py-1 rounded-md text-[11px] font-medium transition cursor-pointer",
                            webhookLogsFilter === "all"
                              ? "bg-[var(--sd-panel-raised)] text-[var(--sd-text)] shadow-xs"
                              : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                          )}
                        >
                          All
                        </button>
                        <button
                          onClick={() => setWebhookLogsFilter("dlq")}
                          className={cn(
                            "px-2.5 py-1 rounded-md text-[11px] font-medium transition cursor-pointer flex items-center gap-1",
                            webhookLogsFilter === "dlq"
                              ? "bg-rose-500/20 text-rose-300 shadow-xs border border-rose-500/30"
                              : "text-[var(--sd-text-muted)] hover:text-rose-400"
                          )}
                        >
                          <span>Dead-Letter (DLQ)</span>
                          {(webhookMetrics?.dlq_pending_count ?? 0) > 0 && (
                            <span className="px-1.5 py-0.2 rounded-full bg-rose-500 text-white text-[9px] font-bold">
                              {webhookMetrics?.dlq_pending_count}
                            </span>
                          )}
                        </button>
                        <button
                          onClick={() => setWebhookLogsFilter("delivered")}
                          className={cn(
                            "px-2.5 py-1 rounded-md text-[11px] font-medium transition cursor-pointer",
                            webhookLogsFilter === "delivered"
                              ? "bg-emerald-500/20 text-emerald-300 shadow-xs border border-emerald-500/30"
                              : "text-[var(--sd-text-muted)] hover:text-emerald-400"
                          )}
                        >
                          Delivered (2xx)
                        </button>
                      </div>

                      {/* Replay All DLQ Button */}
                      {(webhookMetrics?.dlq_pending_count ?? 0) > 0 && (
                        <button
                          onClick={handleRetryAllDlq}
                          disabled={retryingAllDlq}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
                          title="Replay all failed DLQ deliveries"
                        >
                          <RotateCcw className={cn("h-3 w-3", retryingAllDlq && "animate-spin")} />
                          <span>{retryingAllDlq ? "Replaying..." : "Replay All DLQ"}</span>
                        </button>
                      )}

                      <button
                        onClick={() => fetchWebhookEndpoints()}
                        title="Refresh logs"
                        className="p-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Table */}
                  <div className="overflow-x-auto rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)]">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-[var(--sd-border)] text-[var(--sd-text-muted)] text-[11px] uppercase font-mono tracking-wider bg-[var(--sd-panel)]">
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3">Timestamp</th>
                          <th className="py-2.5 px-3">Event</th>
                          <th className="py-2.5 px-3">Target Endpoint</th>
                          <th className="py-2.5 px-3">Latency</th>
                          <th className="py-2.5 px-3">Attempts</th>
                          <th className="py-2.5 px-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--sd-border)]">
                        {webhookDeliveryLogs.length > 0 ? (
                          webhookDeliveryLogs.map((log) => {
                            const isDelivered = log.status === "DELIVERED";
                            const isRetried = log.status === "RETRIED";
                            const isDlq = log.is_dlq || log.status === "DEAD_LETTER";
                            const latency = log.latency_ms ?? 0;

                            return (
                              <tr key={log.id} className="hover:bg-[var(--sd-panel-hover)]/40 transition">
                                <td className="py-2.5 px-3">
                                  <span
                                    className={cn(
                                      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium",
                                      isDelivered
                                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                        : isRetried
                                          ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                                          : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                                    )}
                                  >
                                    {isDelivered ? "200 OK" : isRetried ? "RETRIED" : `${log.status_code || 500} DLQ`}
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--sd-text-muted)]">
                                  {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--sd-text)]">
                                  {log.event_type}
                                </td>
                                <td className="py-2.5 px-3 text-[11px] text-[var(--sd-text-muted)] truncate max-w-xs" title={log.destination || log.endpoint_name}>
                                  {log.endpoint_name || log.endpoint_id}
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px]">
                                  <span
                                    className={cn(
                                      latency < 100
                                        ? "text-emerald-400"
                                        : latency < 500
                                          ? "text-amber-400"
                                          : "text-rose-400"
                                    )}
                                  >
                                    {latency}ms
                                  </span>
                                </td>
                                <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--sd-text-muted)]">
                                  {log.attempts || 1}
                                </td>
                                <td className="py-2.5 px-3 text-right">
                                  <div className="flex items-center justify-end gap-1.5">
                                    {isDlq && (
                                      <button
                                        onClick={() => handleRetryDelivery(log.delivery_id)}
                                        disabled={retryingDeliveryId === log.delivery_id}
                                        className="px-2 py-1 rounded text-[11px] font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/20 transition cursor-pointer flex items-center gap-1 disabled:opacity-50"
                                        title="Retry dead-letter dispatch"
                                      >
                                        <RotateCcw className={cn("h-3 w-3", retryingDeliveryId === log.delivery_id && "animate-spin")} />
                                        <span>Retry</span>
                                      </button>
                                    )}
                                    <button
                                      onClick={() => setInspectingLog(log)}
                                      className="px-2 py-1 rounded text-[11px] font-medium bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)] border border-[var(--sd-border)] transition cursor-pointer"
                                    >
                                      Inspect
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })
                        ) : (
                          <tr>
                            <td colSpan={7} className="py-8 text-center text-xs text-[var(--sd-text-muted)] font-mono">
                              No webhook delivery logs found for this filter.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Add Webhook Endpoint Modal */}
              {addWebhookModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
                  <div className="relative w-full max-w-lg rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] p-6 shadow-xl space-y-4">
                    <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
                      <div className="flex items-center gap-2">
                        <div className="p-2 rounded-lg bg-[var(--sd-pine)]/10 text-[var(--sd-pine)] border border-[var(--sd-pine)]/20">
                          <Send className="h-4 w-4" />
                        </div>
                        <div>
                          <h3 className="text-sm font-medium text-[var(--sd-text)]">
                            Add Webhook Endpoint
                          </h3>
                          <p className="text-[11px] text-[var(--sd-text-muted)]">
                            Configure real-time alert routing for your SOC team.
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => setAddWebhookModalOpen(false)}
                        className="text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] p-1 rounded-lg text-sm"
                      >
                        ✕
                      </button>
                    </div>

                    <form onSubmit={handleCreateWebhook} className="space-y-3.5 text-xs">
                      <div className="space-y-1">
                        <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                          Endpoint Name
                        </label>
                        <input
                          type="text"
                          required
                          value={newWebhookName}
                          onChange={(e) => setNewWebhookName(e.target.value)}
                          placeholder="e.g. Incident Response Slack Channel"
                          className="w-full px-3 py-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] transition"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                            Webhook Platform
                          </label>
                          <select
                            value={newWebhookType}
                            onChange={(e) => setNewWebhookType(e.target.value as "slack" | "discord" | "teams" | "generic")}
                            className="w-full px-3 py-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] transition cursor-pointer"
                          >
                            <option value="slack">Slack</option>
                            <option value="discord">Discord</option>
                            <option value="teams">Microsoft Teams</option>
                            <option value="generic">Generic SIEM / SOAR</option>
                          </select>
                        </div>

                        <div className="space-y-1">
                          <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                            Minimum Severity
                          </label>
                          <select
                            value={newWebhookMinSeverity}
                            onChange={(e) => setNewWebhookMinSeverity(e.target.value as "low" | "medium" | "high" | "critical")}
                            className="w-full px-3 py-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] transition cursor-pointer"
                          >
                            <option value="low">Low (All Events)</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="critical">Critical Only</option>
                          </select>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                            Destination URL
                          </label>
                          {autoDetectedPlatform && (
                            <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              <Zap className="h-3 w-3" />
                              Auto-detected: {autoDetectedPlatform.toUpperCase()}
                            </span>
                          )}
                        </div>
                        <input
                          type="url"
                          required
                          value={newWebhookUrl}
                          onChange={(e) => {
                            const val = e.target.value;
                            setNewWebhookUrl(val);
                            const detected = detectClientPlatform(val);
                            if (detected) {
                              setAutoDetectedPlatform(detected);
                              setNewWebhookType(detected);
                            } else {
                              setAutoDetectedPlatform(null);
                            }
                          }}
                          placeholder="https://hooks.slack.com/services/... or https://siem.corp/webhook"
                          className="w-full px-3 py-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] font-mono focus:outline-hidden focus:border-[var(--sd-pine)] transition"
                        />
                        <p className="text-[10px] text-[var(--sd-text-muted)]">
                          Must be a valid HTTPS webhook URL. SSRF protection blocks cloud metadata and loopback destinations.
                        </p>
                      </div>

                      <div className="space-y-1">
                        <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                          HMAC Secret Key (Optional)
                        </label>
                        <input
                          type="password"
                          value={newWebhookSecret}
                          onChange={(e) => setNewWebhookSecret(e.target.value)}
                          placeholder="Shared secret for X-ShieldDesk-Signature validation"
                          className="w-full px-3 py-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs text-[var(--sd-text)] font-mono focus:outline-hidden focus:border-[var(--sd-pine)] transition"
                        />
                      </div>

                      <div className="space-y-1.5 pt-1">
                        <label className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                          Subscribed Events
                        </label>
                        <div className="grid grid-cols-2 gap-2">
                          {[
                            { id: "threat_detected", label: "Threat Detections (YARA/Sigma)" },
                            { id: "approval_required", label: "Human Approval Requests" },
                            { id: "incident_created", label: "Incident Creation" },
                            { id: "lockdown.activated", label: "Emergency Containment / Lockdown" },
                          ].map((ev) => (
                            <label
                              key={ev.id}
                              className="flex items-center gap-2 p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] cursor-pointer text-[11px]"
                            >
                              <input
                                type="checkbox"
                                checked={newWebhookEvents.includes(ev.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setNewWebhookEvents((prev) => [...prev, ev.id]);
                                  } else {
                                    setNewWebhookEvents((prev) => prev.filter((x) => x !== ev.id));
                                  }
                                }}
                                className="rounded text-[var(--sd-pine)] focus:ring-0"
                              />
                              <span className="text-[var(--sd-text)]">{ev.label}</span>
                            </label>
                          ))}
                        </div>
                      </div>

                      <div className="flex items-center justify-end gap-2 pt-3 border-t border-[var(--sd-border)]">
                        <button
                          type="button"
                          onClick={() => setAddWebhookModalOpen(false)}
                          className="px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] text-xs font-medium text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={webhookCreating}
                          className="sd-button sd-button-primary flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium text-[var(--sd-on-accent)] transition cursor-pointer shadow-xs"
                        >
                          {webhookCreating && <RotateCcw className="h-3 w-3 animate-spin" />}
                          <span>Save Webhook</span>
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}
            </div>

            {/* Inspector Modal */}
            {inspectingLog && (
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-150">
                <div className="relative w-full max-w-2xl rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
                  <div className="flex items-center justify-between border-b border-[var(--sd-border)] pb-3">
                    <div className="flex items-center gap-2">
                      <div className="p-2 rounded-lg bg-[var(--sd-pine)]/10 text-[var(--sd-pine)] border border-[var(--sd-pine)]/20">
                        <Terminal className="h-4 w-4" />
                      </div>
                      <div>
                        <h3 className="text-sm font-medium text-[var(--sd-text)]">
                          Webhook Delivery Inspector
                        </h3>
                        <p className="text-[11px] text-[var(--sd-text-muted)] font-mono">
                          ID: {inspectingLog.delivery_id}
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => setInspectingLog(null)}
                      className="text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] p-1 rounded-lg text-sm cursor-pointer"
                    >
                      ✕
                    </button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                    <div className="p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)]">
                      <div className="text-[10px] text-[var(--sd-text-muted)] uppercase">Status</div>
                      <div className="font-medium mt-0.5 text-[var(--sd-text)]">{inspectingLog.status} ({inspectingLog.status_code || 0})</div>
                    </div>
                    <div className="p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)]">
                      <div className="text-[10px] text-[var(--sd-text-muted)] uppercase">Latency</div>
                      <div className="font-medium mt-0.5 text-[var(--sd-text)]">{inspectingLog.latency_ms ?? 0}ms</div>
                    </div>
                    <div className="p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)]">
                      <div className="text-[10px] text-[var(--sd-text-muted)] uppercase">Attempts</div>
                      <div className="font-medium mt-0.5 text-[var(--sd-text)]">{inspectingLog.attempts}</div>
                    </div>
                    <div className="p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)]">
                      <div className="text-[10px] text-[var(--sd-text-muted)] uppercase">DLQ Flag</div>
                      <div className="font-medium mt-0.5 text-[var(--sd-text)]">{inspectingLog.is_dlq ? "YES" : "NO"}</div>
                    </div>
                  </div>

                  {inspectingLog.error_message && (
                    <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-mono space-y-1">
                      <div className="font-semibold uppercase text-[10px] tracking-wider">Error Message</div>
                      <div>{inspectingLog.error_message}</div>
                    </div>
                  )}

                  <div className="space-y-1">
                    <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider font-mono">
                      Dispatched Payload (JSON)
                    </div>
                    <pre className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text)] overflow-x-auto max-h-52">
                      {JSON.stringify(inspectingLog.payload || {}, null, 2)}
                    </pre>
                  </div>

                  {inspectingLog.response_body && (
                    <div className="space-y-1">
                      <div className="text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider font-mono">
                        Destination Response Body
                      </div>
                      <pre className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text-muted)] overflow-x-auto max-h-36">
                        {inspectingLog.response_body}
                      </pre>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-3 border-t border-[var(--sd-border)]">
                    <span className="text-[10px] text-[var(--sd-text-muted)] font-mono">
                      Timestamp: {new Date(inspectingLog.created_at).toISOString()}
                    </span>
                    <button
                      onClick={() => setInspectingLog(null)}
                      className="px-4 py-1.5 rounded-lg bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] border border-[var(--sd-border)] transition cursor-pointer"
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Alerts (Real-time Authentication Failures & Threats) */}
        {activeTab === "alerts" && (
          <div className="space-y-4">
            {/* Feedback toast */}
            {unblockFeedback && (
              <div className="p-3 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] text-[var(--sd-success)] text-xs font-medium flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{unblockFeedback}</span>
              </div>
            )}

            {/* Autonomous IP Containment Active Banner */}
            {blockedIps.length > 0 && (
              <div className="p-4 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] space-y-3 shadow-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]">
                      <Ban className="h-4 w-4" />
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-[var(--sd-danger)] uppercase tracking-wider font-mono flex items-center gap-2">
                        <span>Autonomous IP Containment Active</span>
                        <span className="px-2 py-0.2 rounded-full bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] text-[10px]">
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
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--sd-panel)] border border-[var(--sd-danger-border)] text-xs font-mono shadow-xs"
                    >
                      <span className="text-[var(--sd-danger)] font-medium">{b.ip}</span>
                      <span className="text-[10px] text-[var(--sd-text-muted)]">({b.attempts} attempts)</span>
                      {canManageContainment ? (
                        <button
                          onClick={() => handleUnblockIp(b.ip)}
                          className="flex items-center gap-1 ml-1 px-2 py-0.5 rounded bg-[var(--sd-success-dim)] hover:bg-[var(--sd-success-border)] text-[var(--sd-success)] text-[11px] font-sans font-medium cursor-pointer transition"
                        >
                          <Unlock className="h-3 w-3" />
                          <span>Unblock</span>
                        </button>
                      ) : (
                        <span className="flex items-center gap-1 ml-1 px-2 py-0.5 rounded bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] text-[10px] font-sans">
                          <Lock className="h-2.5 w-2.5" />
                          <span>View Only</span>
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

              <div className="p-4 rounded-xl border border-[var(--sd-border)] sd-surface space-y-1 shadow-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-medium text-[var(--sd-text)] flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-[var(--sd-danger)]" />
                      <span>Authentication &amp; Threat Security Alerts</span>
                      {securityAlerts.length > 0 && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono">
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
                      className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                    >
                      <RotateCcw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
                      <span>Refresh</span>
                    </button>

                    {canManageContainment && securityAlerts.length > 0 && (
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
                          "sd-surface p-5 rounded-xl border space-y-4 transition-colors duration-200",
                          isIpCurrentlyBlocked
                            ? "border-[var(--sd-danger)] bg-[var(--sd-danger-dim)]/80"
                            : isCritical
                              ? "border-[var(--sd-danger)] bg-[var(--sd-danger-dim)]"
                              : isHigh
                                ? "border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)]"
                                : "border-[var(--sd-border)] bg-[var(--sd-panel)]"
                        )}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[var(--sd-border)] pb-3">
                          <div className="flex items-center gap-2.5">
                            <div
                              className={cn(
                                "p-2 rounded-lg text-[var(--sd-on-accent)]",
                                isIpCurrentlyBlocked || isCritical
                                  ? "bg-[var(--sd-danger)]"
                                  : isHigh
                                    ? "bg-[var(--sd-warning)]"
                                    : "bg-[var(--sd-wheat)]"
                              )}
                            >
                              <ShieldAlert className="h-5 w-5" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="text-sm font-medium text-[var(--sd-text)]">
                                  {alert.title}
                                </h4>
                                <span
                                  className={cn(
                                    "px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider font-mono",
                                    isIpCurrentlyBlocked || isCritical
                                      ? "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]"
                                      : isHigh
                                        ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                                        : "bg-[var(--sd-panel-raised)] text-[var(--sd-wheat)] border border-[var(--sd-border)]"
                                  )}
                                >
                                  {alert.severity} SEVERITY
                                </span>
                                {alert.attemptsCount > 1 && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] font-mono">
                                    {alert.attemptsCount} ATTEMPTS
                                  </span>
                                )}
                                {isIpCurrentlyBlocked && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] border border-[var(--sd-danger-border)] font-mono flex items-center gap-1">
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
                            <span className="px-2.5 py-1 rounded-full text-[10px] font-medium uppercase tracking-wider bg-[var(--sd-panel)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] font-mono flex items-center gap-1.5 shadow-xs">
                              <Lock className="h-3 w-3 text-[var(--sd-pine)]" />
                              SOC Verified Event
                            </span>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                          <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                            <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                              <Mail className="h-3.5 w-3.5 text-[var(--sd-wheat)]" /> Target User Email
                            </span>
                            <p className="font-mono font-medium text-sm text-[var(--sd-text)] break-all" title={alert.targetUser}>
                              {alert.targetUser}
                            </p>
                          </div>

                          <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                            <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                              <Globe className="h-3.5 w-3.5 text-[var(--sd-success)]" /> Source IP Address
                            </span>
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className="font-mono font-medium text-sm text-[var(--sd-success)]">
                                {alert.clientIp}
                              </p>
                              {isIpCurrentlyBlocked && (
                                <span className="px-1.5 py-0.2 rounded text-[9px] font-medium bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono flex items-center gap-1">
                                  <Ban className="h-2.5 w-2.5" /> BLOCKED
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                            <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                              <AlertTriangle className="h-3.5 w-3.5 text-[var(--sd-warning)]" /> Failure Reason / Condition
                            </span>
                            <p className="font-medium text-xs text-[var(--sd-danger)] line-clamp-2" title={alert.failureReason}>
                              {alert.failureReason}
                            </p>
                          </div>

                          <div className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] space-y-1 shadow-xs">
                            <span className="text-[11px] text-[var(--sd-text-muted)] flex items-center gap-1.5 font-medium">
                              <Clock className="h-3.5 w-3.5 text-[var(--sd-text-muted)]" /> Detected Timestamp
                            </span>
                            <p className="font-mono text-xs text-[var(--sd-text)]">
                              {new Date(alert.createdAt).toLocaleTimeString()} ({alert.attemptsCount} attempt{alert.attemptsCount > 1 ? "s" : ""})
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center justify-end gap-2.5 pt-1 flex-wrap">
                          {canManageContainment ? (
                            isIpCurrentlyBlocked ? (
                              <button
                                onClick={() => handleUnblockIp(alert.clientIp)}
                                className="sd-button flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] hover:bg-[var(--sd-success-dim)] text-[var(--sd-success)] text-xs font-medium transition cursor-pointer shadow-xs"
                              >
                                <Unlock className="h-3.5 w-3.5" />
                                <span>Unblock IP ({alert.clientIp})</span>
                              </button>
                            ) : (
                              <button
                                onClick={() => handleBlockIp(alert.clientIp)}
                                className="sd-button flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-danger)]/20 hover:text-[var(--sd-danger)] text-xs font-medium text-[var(--sd-text-muted)] transition cursor-pointer shadow-xs"
                              >
                                <Ban className="h-3.5 w-3.5" />
                                <span>Block IP</span>
                              </button>
                            )
                          ) : (
                            <span className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] text-[var(--sd-text-muted)] text-xs font-medium shadow-xs">
                              <Lock className="h-3.5 w-3.5" />
                              <span>View Only · Requires Responder to Unblock</span>
                            </span>
                          )}

                          {canManageContainment && (
                            <button
                              onClick={() => handleAcknowledgeAlert(alert.id)}
                              className="px-3.5 py-1.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                            >
                              Acknowledge Alert
                            </button>
                          )}

                          <button
                            onClick={() => handleInvestigateInChat(alert)}
                            className="sd-button sd-button-primary flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[var(--sd-on-accent)] text-xs font-medium transition cursor-pointer shadow-xs"
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
                <div className="p-8 rounded-xl border border-[var(--sd-border)] sd-surface text-center space-y-3">
                  <div className="inline-flex p-3 rounded-full bg-[var(--sd-pine-dim)] text-[var(--sd-pine-bright)]">
                    <CheckCircle2 className="h-6 w-6" />
                  </div>
                  <h4 className="text-sm font-medium text-[var(--sd-text)]">
                    Zero Active Security Alerts
                  </h4>
                  <p className="text-xs text-[var(--sd-text-muted)] max-w-md mx-auto">
                    All authentication events and statistical baselines are nominal. Failed logins or anomaly bursts will appear here automatically with their source IP and target email.
                  </p>
                </div>
              )}
            </div>
        )}

        {/* YARA Interactive Modals */}
        <YaraRuleTesterModal
          isOpen={testerModalOpen}
          onClose={() => setTesterModalOpen(false)}
          initialRuleContent={testingRule?.raw_content}
          initialRuleId={testingRule?.id}
          availableRules={yaraRules}
        />

        <YaraRuleCreatorModal
          isOpen={creatorModalOpen}
          onClose={() => setCreatorModalOpen(false)}
          onRuleCreated={() => fetchThreatData(true)}
        />

        <YaraMatchHistoryModal
          isOpen={historyModalOpen}
          onClose={() => setHistoryModalOpen(false)}
        />
      </main>
    </div>
  );
}

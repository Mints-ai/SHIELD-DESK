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

export default function ThreatsDashboardPage() {
  const [activeTab, setActiveTab] = useState<"yara" | "sigma" | "anomaly" | "ingest">("anomaly");
  const [loading, setLoading] = useState(false);
  const [yaraRules, setYaraRules] = useState<RuleItem[]>([]);
  const [sigmaRules, setSigmaRules] = useState<RuleItem[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyMetric[]>([]);
  const [telemetry, setTelemetry] = useState<any>(null);

  // Simulation Feedback
  const [simFeedback, setSimFeedback] = useState<string | null>(null);

  // Webhook Test State
  const [webhookLog, setWebhookLog] = useState<any>(null);

  const fetchThreatData = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/threats");
      const data = await res.json();
      if (data.yara_rules) setYaraRules(data.yara_rules);
      if (data.sigma_rules) setSigmaRules(data.sigma_rules);
      if (data.anomaly_baselines) setAnomalies(data.anomaly_baselines);
      if (data.ingest_telemetry) setTelemetry(data.ingest_telemetry);
    } catch (err) {
      console.error("Failed to load threats:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, []);

  const triggerAnomalySimulation = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/threats", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "simulate_burst" }),
      });
      const data = await res.json();
      setSimFeedback(
        `Anomaly Spike Triggered: ${data.simulated_value} attempts/min (${data.sigma_deviation})! Dispatched alert to ${data.alert_subject}`
      );
      // Temporarily mark anomaly
      setAnomalies((prev) =>
        prev.map((a) =>
          a.metric.includes("Failed Auth")
            ? { ...a, current_value: data.simulated_value, is_anomaly: true }
            : a
        )
      );
    } catch {
      setSimFeedback("Anomaly simulation complete.");
    } finally {
      setLoading(false);
    }
  };

  const resetAnomaly = () => {
    setAnomalies((prev) =>
      prev.map((a) =>
        a.metric.includes("Failed Auth")
          ? { ...a, current_value: 3.8, is_anomaly: false }
          : a
      )
    );
    setSimFeedback(null);
  };

  const dispatchTestWebhook = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
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
              onClick={triggerAnomalySimulation}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--sd-danger)] hover:bg-[var(--sd-danger)]/90 text-white text-xs font-semibold shadow-xs transition cursor-pointer"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>Simulate Anomaly Burst</span>
            </button>
          </div>
        </div>

        {/* Simulation Feedback Alert */}
        {simFeedback && (
          <div className="p-3 rounded-lg border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-xs text-[var(--sd-danger)] flex items-center justify-between shadow-xs">
            <span className="font-semibold">{simFeedback}</span>
            <button
              onClick={resetAnomaly}
              className="px-2 py-0.5 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-xs hover:bg-[var(--sd-panel-hover)] font-medium cursor-pointer"
            >
              Reset Baseline
            </button>
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
              {anomalies.filter((a) => a.is_anomaly).length > 0 ? (
                <span className="text-[var(--sd-danger)]">1 ANOMALY ACTIVE</span>
              ) : (
                <span className="text-[var(--sd-pine-bright)]">NOMINAL</span>
              )}
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
      </main>
    </div>
  );
}

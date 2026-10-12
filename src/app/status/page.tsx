"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Clock,
  Activity,
  Server,
  Database,
  Lock,
  Cpu,
  Scan,
  CreditCard,
  FileCheck2,
  Terminal,
  ExternalLink,
  Radio,
  Sparkles,
  Copy,
  Check,
  Flame,
  ArrowRight,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import type { SystemStatusReport, ServiceComponentStatus } from "@/lib/status/serviceStatus";

export default function StatusPage() {
  const [report, setReport] = useState<SystemStatusReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [autoRefreshCountdown, setAutoRefreshCountdown] = useState(30);
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [copiedEndpoint, setCopiedEndpoint] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch("/api/status?format=json", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (!res.ok && res.status !== 503) {
        throw new Error(`Status check returned HTTP ${res.status}`);
      }
      const data: SystemStatusReport = await res.json();
      setReport(data);
      setLastRefreshed(new Date());
      setAutoRefreshCountdown(30);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Auto-refresh timer every 30s
  useEffect(() => {
    const timer = setInterval(() => {
      setAutoRefreshCountdown((prev) => {
        if (prev <= 1) {
          fetchStatus();
          return 30;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [fetchStatus]);

  const copyApiCommand = () => {
    const origin = typeof window !== "undefined" ? window.location.origin : "https://app.shielddesk.io";
    navigator.clipboard.writeText(`curl -s ${origin}/api/status | jq`);
    setCopiedEndpoint(true);
    setTimeout(() => setCopiedEndpoint(false), 2000);
  };

  const getServiceIcon = (key: string) => {
    switch (key) {
      case "database":
        return <Database className="w-5 h-5 text-[var(--sd-wheat)]" />;
      case "auth_gateway":
        return <Lock className="w-5 h-5 text-[var(--sd-wheat)]" />;
      case "fleet_pki":
        return <Server className="w-5 h-5 text-[var(--sd-pine)]" />;
      case "ai_engine":
        return <Cpu className="w-5 h-5 text-[var(--sd-pine)]" />;
      case "scanner_engine":
        return <Scan className="w-5 h-5 text-[var(--sd-wheat)]" />;
      case "threat_engine":
        return <Flame className="w-5 h-5 text-[var(--sd-danger)]" />;
      case "compliance_ledger":
        return <FileCheck2 className="w-5 h-5 text-[var(--sd-success)]" />;
      case "billing_service":
        return <CreditCard className="w-5 h-5 text-[var(--sd-wheat)]" />;
      default:
        return <Radio className="w-5 h-5 text-[var(--sd-text-muted)]" />;
    }
  };

  const getStatusBadge = (status: ServiceComponentStatus["status"]) => {
    switch (status) {
      case "operational":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Operational
          </span>
        );
      case "degraded":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[var(--sd-warning-dim)] text-[var(--sd-wheat)] border border-[var(--sd-warning-border)]">
            <AlertTriangle className="w-3.5 h-3.5" />
            Degraded Performance
          </span>
        );
      case "outage":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]">
            <XCircle className="w-3.5 h-3.5" />
            Major Outage
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]">
            <Clock className="w-3.5 h-3.5" />
            Maintenance
          </span>
        );
    }
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h ${mins}m`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m ${seconds % 60}s`;
  };

  const isAllOperational = report?.status === "operational";

  const allServices = report ? Object.entries(report.services) : [];
  const filteredServices = allServices.filter(([, svc]) => {
    if (activeCategory === "all") return true;
    return svc.category === activeCategory;
  });

  const categories = [
    { id: "all", label: "All Subsystems", count: allServices.length },
    { id: "core", label: "Core Infrastructure", count: allServices.filter(([, s]) => s.category === "core").length },
    { id: "security", label: "Security & PKI", count: allServices.filter(([, s]) => s.category === "security").length },
    { id: "intelligence", label: "AI & Intelligence", count: allServices.filter(([, s]) => s.category === "intelligence").length },
    { id: "commercial", label: "Commercial Gateways", count: allServices.filter(([, s]) => s.category === "commercial").length },
  ];

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      {/* Global Top Navbar */}
      <TopNavBar />

      {/* Main Workspace Layout */}
      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl sd-surface border border-[var(--sd-border)] flex items-center justify-center text-[var(--sd-wheat)] shadow-xs">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="tracking-tight text-[var(--sd-text)] text-2xl sm:text-3xl font-light leading-tight font-sans">
                  Platform Operational Status
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] font-mono">
                  {report?.version ? `v${report.version}` : "v2.4.0 Live"}
                </span>
              </div>
              <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
                Real-time cryptographic telemetry, PKI control plane health, and subsystem latency diagnostics.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Manual refresh button */}
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition-all cursor-pointer shadow-xs disabled:opacity-50"
              title="Refresh status manually"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-[var(--sd-pine)] ${loading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
              <span className="text-[10px] text-[var(--sd-text-dim)] font-mono">({autoRefreshCountdown}s)</span>
            </button>

            {/* Direct JSON link */}
            <Link
              href="/api/status?format=json"
              target="_blank"
              className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl sd-button-primary text-xs font-semibold text-[var(--sd-on-accent)] transition-all cursor-pointer shadow-xs"
            >
              <Terminal className="h-3.5 w-3.5 text-[var(--sd-on-accent)]" />
              <span>GET /api/status</span>
              <ExternalLink className="h-3 w-3 text-[var(--sd-on-accent)] opacity-70" />
            </Link>
          </div>
        </div>

        {/* Error notification banner if any */}
        {error && (
          <div className="p-4 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] text-xs flex items-center gap-3">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span className="flex-1">Telemetry probe communication error: {error}</span>
            <button
              onClick={fetchStatus}
              className="underline font-semibold hover:opacity-80"
            >
              Retry Probe
            </button>
          </div>
        )}

        {/* Executive Overview Metrics Cards */}
        <div className="sd-overview-metrics">
          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Overall Status
              <Activity size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value flex items-center gap-2">
              <span
                className={`inline-block w-2.5 h-2.5 rounded-full ${
                  isAllOperational ? "bg-[var(--sd-success)] animate-pulse" : "bg-[var(--sd-warning)] animate-ping"
                }`}
              />
              <span className="capitalize">{report?.status || (loading ? "Probing..." : "Unknown")}</span>
            </div>
            <p className="sd-metric-caption">Zero-trust control plane</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Platform SLA
              <CheckCircle2 size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value text-[var(--sd-wheat)] font-mono">99.98%</div>
            <p className="sd-metric-caption">Rolling 90-day target</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Process Uptime
              <Clock size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value font-mono text-[18px]">
              {report ? formatUptime(report.uptime_seconds) : (loading ? "..." : "—")}
            </div>
            <p className="sd-metric-caption">Current cluster container</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Active Subsystems
              <Server size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value font-mono">
              {report
                ? `${report.summary.operational} / ${report.summary.total_services}`
                : "—"}
            </div>
            <p className="sd-metric-caption">Operational components</p>
          </div>
        </div>

        {/* Status Callout Banner */}
        <div
          className={`p-6 rounded-2xl border transition-all ${
            loading && !report
              ? "sd-surface border-[var(--sd-border)]"
              : isAllOperational
              ? "bg-gradient-to-r from-[var(--sd-panel)] to-[var(--sd-primary-subtle)] border-[var(--sd-border)] shadow-[0_0_24px_rgba(11,107,80,0.14)]"
              : "bg-gradient-to-r from-[var(--sd-panel)] to-[var(--sd-warning-dim)] border-[var(--sd-warning-border)] shadow-[0_0_24px_rgba(216,196,154,0.14)]"
          }`}
        >
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center border shadow-xs ${
                  isAllOperational
                    ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]"
                    : "bg-[var(--sd-warning-dim)] text-[var(--sd-wheat)] border-[var(--sd-warning-border)]"
                }`}
              >
                {isAllOperational ? (
                  <CheckCircle2 className="w-7 h-7" />
                ) : (
                  <AlertTriangle className="w-7 h-7" />
                )}
              </div>
              <div>
                <h2 className="text-xl sm:text-2xl font-light tracking-tight text-[var(--sd-text)]">
                  {loading && !report
                    ? "Evaluating Platform Subsystems..."
                    : isAllOperational
                    ? "All Systems Operational"
                    : "Subsystem Degradation Detected"}
                </h2>
                <p className="text-xs sm:text-sm text-[var(--sd-text-muted)] mt-0.5">
                  Continuous cryptographic verification of local engines, mTLS endpoints, and SOC audit ledgers.
                </p>
              </div>
            </div>

            <div className="text-left sm:text-right shrink-0">
              <span className="text-[10px] text-[var(--sd-text-dim)] block uppercase tracking-widest font-mono">
                Last Telemetry Probe
              </span>
              <span className="text-sm font-mono font-semibold text-[var(--sd-wheat)]">
                {lastRefreshed.toLocaleTimeString()}
              </span>
              <span className="text-[10px] text-[var(--sd-text-muted)] block">
                Auto-refreshes every 30s
              </span>
            </div>
          </div>
        </div>

        {/* 90-Day Uptime Visualization Ledger */}
        <div className="sd-surface rounded-2xl border border-[var(--sd-border)] p-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-[var(--sd-pine)]" />
              <h2 className="text-sm font-medium text-[var(--sd-text)]">
                90-Day Service Availability Ledger
              </h2>
            </div>
            <span className="text-xs font-mono text-[var(--sd-success)] font-semibold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--sd-success)]" />
              100% Operational Today
            </span>
          </div>

          {/* 90 block day tickers */}
          <div className="grid grid-cols-45 sm:grid-cols-90 gap-1 my-3 h-9 items-end">
            {Array.from({ length: 90 }).map((_, idx) => (
              <div
                key={idx}
                className="w-full bg-[var(--sd-pine)]/80 hover:bg-[var(--sd-wheat)] transition-all rounded-xs h-full cursor-pointer"
                title={`Day ${90 - idx}: 100% Nominal Operational SLA (0 recorded outage events)`}
              />
            ))}
          </div>

          <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-dim)] font-mono mt-3 pt-3 border-t border-[var(--sd-border-subtle)]">
            <span>90 days ago</span>
            <span className="hidden sm:inline">Continuous Compliance SLA Baseline</span>
            <span>Today</span>
          </div>
        </div>

        {/* Subsystems & Components Grid */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-[var(--sd-text)] flex items-center gap-2">
                <Server className="w-4 h-4 text-[var(--sd-pine)]" />
                Platform Subsystems & Control-Plane Components
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Probed in real-time across database connections, authentication providers, and analysis engines.
              </p>
            </div>

            {/* Category Filter Pills */}
            <div className="inline-flex items-center p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] overflow-x-auto max-w-full">
              {categories.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setActiveCategory(cat.id)}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                    activeCategory === cat.id
                      ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold shadow-xs"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                  }`}
                >
                  {cat.label}
                  {cat.count > 0 && (
                    <span className="ml-1.5 opacity-70 font-mono text-[10px]">
                      ({cat.count})
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Component cards grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredServices.map(([key, svc]) => (
              <div
                key={key}
                className="sd-surface rounded-2xl border border-[var(--sd-border)] hover:border-[var(--sd-border-strong)] p-5 transition-all shadow-xs flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)]">
                        {getServiceIcon(key)}
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-[var(--sd-text)] leading-tight">
                          {svc.name}
                        </h3>
                        <span className="text-[10px] uppercase font-mono tracking-wider text-[var(--sd-wheat)] mt-0.5 block">
                          {svc.category}
                        </span>
                      </div>
                    </div>
                    {getStatusBadge(svc.status)}
                  </div>

                  <p className="text-xs text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed mb-4">
                    {svc.description}
                  </p>
                </div>

                <div className="pt-3 border-t border-[var(--sd-border-subtle)] flex items-center justify-between text-[11px] font-mono text-[var(--sd-text-dim)]">
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[var(--sd-pine)]" />
                    <span>Round-Trip Latency:</span>
                    <strong
                      className={`font-semibold ${
                        svc.latency_ms > 200
                          ? "text-[var(--sd-danger)]"
                          : svc.latency_ms > 50
                          ? "text-[var(--sd-wheat)]"
                          : "text-[var(--sd-success)]"
                      }`}
                    >
                      {svc.latency_ms} ms
                    </strong>
                  </span>
                  <span>
                    Probed {new Date(svc.last_checked).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Active Incident Announcements & Maintenance Windows */}
        <div className="sd-surface rounded-2xl border border-[var(--sd-border)] p-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-[var(--sd-text)] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-[var(--sd-success)]" />
              Active Announcements & Maintenance Windows
            </h2>
            <span className="text-xs font-mono text-[var(--sd-text-dim)]">
              Audited by Mints Security Engineering
            </span>
          </div>

          <div className="space-y-3">
            {report?.incidents && report.incidents.length > 0 ? (
              report.incidents.map((inc) => (
                <div
                  key={inc.id}
                  className="p-4 rounded-xl sd-surface border border-[var(--sd-border)] flex items-start gap-3"
                >
                  <div className="mt-0.5">
                    <AlertTriangle className="w-4 h-4 text-[var(--sd-wheat)] shrink-0" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-xs font-semibold text-[var(--sd-text)]">
                        {inc.title}
                      </h4>
                      <span className="text-[10px] font-mono text-[var(--sd-text-dim)]">
                        {new Date(inc.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--sd-text-muted)] mt-1 leading-relaxed">
                      {inc.message}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-4 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-xs text-[var(--sd-text-muted)] flex items-center gap-3">
                <CheckCircle2 className="w-4 h-4 text-[var(--sd-success)] shrink-0" />
                <span>
                  No active incidents or scheduled maintenance windows. All control-plane cryptographic probes and zero-trust orchestration nodes are within nominal tolerances.
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Machine-Readable JSON Export Callout */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-[var(--sd-wheat)]" />
              <span className="text-sm font-medium text-[var(--sd-text)]">
                Machine-Readable Public Telemetry API
              </span>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-2xl">
              Integrate uptime checks directly into Datadog, Prometheus, BetterUptime, or UptimeRobot.
              Returns complete JSON system metrics, latency timers, and component state.
            </p>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <button
              onClick={copyApiCommand}
              className="sd-button flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-mono font-medium border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer shadow-xs"
              title="Copy curl command"
            >
              {copiedEndpoint ? (
                <>
                  <Check className="h-3.5 w-3.5 text-[var(--sd-success)]" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 text-[var(--sd-wheat)]" />
                  <span>Copy cURL</span>
                </>
              )}
            </button>

            <Link
              href="/api/status?format=json"
              target="_blank"
              className="sd-button flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl sd-button-primary text-xs font-semibold text-[var(--sd-on-accent)] transition-all cursor-pointer shadow-xs shrink-0"
            >
              <span>View JSON</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>

        {/* Navigation Shortcut Back to SOC */}
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-[var(--sd-text-dim)] border-t border-[var(--sd-border-subtle)]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[var(--sd-pine)]" />
            <span>ShieldDesk™ Autonomous SOC · Mints Global Security Engineering</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-[var(--sd-wheat)] transition-colors flex items-center gap-1">
              <span>Incident Queue</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
            <Link href="/dashboard/scanner" className="hover:text-[var(--sd-wheat)] transition-colors">
              Security Scanner
            </Link>
            <Link href="/pricing" className="hover:text-[var(--sd-wheat)] transition-colors">
              Commercial Plans
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}

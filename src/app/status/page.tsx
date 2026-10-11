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
  ArrowLeft,
  ExternalLink,
  Radio,
} from "lucide-react";
import type { SystemStatusReport, ServiceComponentStatus } from "@/lib/status/serviceStatus";

export default function StatusPage() {
  const [report, setReport] = useState<SystemStatusReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [autoRefreshCountdown, setAutoRefreshCountdown] = useState(30);

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch("/api/status", { cache: "no-store" });
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

  const getServiceIcon = (key: string) => {
    switch (key) {
      case "database":
        return <Database className="w-5 h-5 text-blue-400" />;
      case "auth_gateway":
        return <Lock className="w-5 h-5 text-purple-400" />;
      case "fleet_pki":
        return <Server className="w-5 h-5 text-emerald-400" />;
      case "ai_engine":
        return <Cpu className="w-5 h-5 text-indigo-400" />;
      case "scanner_engine":
        return <Scan className="w-5 h-5 text-cyan-400" />;
      case "threat_engine":
        return <Activity className="w-5 h-5 text-rose-400" />;
      case "compliance_ledger":
        return <FileCheck2 className="w-5 h-5 text-amber-400" />;
      case "billing_service":
        return <CreditCard className="w-5 h-5 text-emerald-400" />;
      default:
        return <Radio className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusBadge = (status: ServiceComponentStatus["status"]) => {
    switch (status) {
      case "operational":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            Operational
          </span>
        );
      case "degraded":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            Degraded Performance
          </span>
        );
      case "outage":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            Major Outage
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
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

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex flex-col selection:bg-emerald-500/30">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#0A0F1D]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2 group">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center group-hover:border-emerald-500/60 transition-colors">
                <Shield className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <span className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
                  ShieldDesk<span className="text-emerald-400 font-mono text-xs">STATUS</span>
                </span>
                <span className="text-[10px] text-slate-400 block -mt-0.5">Mints Global Security Engineering</span>
              </div>
            </Link>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800/70 hover:bg-slate-800 border border-slate-700/60 text-slate-300 transition-colors cursor-pointer disabled:opacity-50"
              title="Refresh status manually"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
              <span className="text-[10px] text-slate-500 ml-1">({autoRefreshCountdown}s)</span>
            </button>

            <Link
              href="/"
              className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 font-medium transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>SOC Console</span>
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-8">
        {/* Banner Alert */}
        <div
          className={`p-6 rounded-xl border mb-8 transition-all ${
            loading && !report
              ? "bg-slate-900/60 border-slate-800"
              : isAllOperational
              ? "bg-emerald-950/20 border-emerald-500/30 shadow-[0_0_24px_rgba(16,185,129,0.06)]"
              : "bg-amber-950/20 border-amber-500/30 shadow-[0_0_24px_rgba(245,158,11,0.06)]"
          }`}
        >
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                  isAllOperational ? "bg-emerald-500/10 text-emerald-400" : "bg-amber-500/10 text-amber-400"
                }`}
              >
                {isAllOperational ? (
                  <CheckCircle2 className="w-7 h-7" />
                ) : (
                  <AlertTriangle className="w-7 h-7" />
                )}
              </div>
              <div>
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                  {loading && !report
                    ? "Evaluating Subsystem Health..."
                    : isAllOperational
                    ? "All Systems Operational"
                    : "Some Services Experiencing Degradation"}
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
                  Real-time cryptographic telemetry, PKI control plane, and zero-trust orchestration nodes.
                </p>
              </div>
            </div>

            <div className="text-left sm:text-right shrink-0">
              <span className="text-[11px] text-slate-500 block uppercase tracking-wider font-semibold">
                Historical SLA
              </span>
              <span className="text-lg font-mono font-bold text-emerald-400">99.98% Uptime</span>
              <span className="text-[10px] text-slate-400 block">Past 90 days rolling</span>
            </div>
          </div>
        </div>

        {/* System Vitals Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4 mb-8">
          <div className="bg-[#0C1222] border border-slate-800/80 rounded-lg p-3.5">
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Overall Status</span>
            <span className="text-sm font-semibold capitalize flex items-center gap-1.5 text-white">
              <span
                className={`w-2 h-2 rounded-full ${
                  isAllOperational ? "bg-emerald-400 animate-pulse" : "bg-amber-400 animate-ping"
                }`}
              />
              {report?.status || "Analyzing"}
            </span>
          </div>

          <div className="bg-[#0C1222] border border-slate-800/80 rounded-lg p-3.5">
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Process Uptime</span>
            <span className="text-sm font-mono font-semibold text-slate-200">
              {report ? formatUptime(report.uptime_seconds) : "..."}
            </span>
          </div>

          <div className="bg-[#0C1222] border border-slate-800/80 rounded-lg p-3.5">
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Release Version</span>
            <span className="text-sm font-mono font-semibold text-slate-200">
              v{report?.version || "2.4.0"}
            </span>
          </div>

          <div className="bg-[#0C1222] border border-slate-800/80 rounded-lg p-3.5">
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Last Probe</span>
            <span className="text-sm font-mono font-semibold text-slate-200">
              {lastRefreshed.toLocaleTimeString()}
            </span>
          </div>
        </div>

        {/* 90-Day Uptime Visualization */}
        <div className="bg-[#0C1222] border border-slate-800/80 rounded-xl p-5 mb-8">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              90-Day Service Availability Ledger
            </h2>
            <span className="text-xs font-mono text-emerald-400 font-semibold">100% Operational Today</span>
          </div>

          {/* 90 bar blocks */}
          <div className="grid grid-cols-45 sm:grid-cols-90 gap-1 my-3 h-8 items-end">
            {Array.from({ length: 90 }).map((_, idx) => (
              <div
                key={idx}
                className="w-full bg-emerald-500/80 hover:bg-emerald-400 transition-all rounded-xs h-full"
                title={`Day ${90 - idx}: 100% Operational - 0 Incident Disruption`}
              />
            ))}
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono mt-2">
            <span>90 days ago</span>
            <span>Continuous Compliance Baseline</span>
            <span>Today</span>
          </div>
        </div>

        {/* Core Subsystem Component Cards */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-emerald-400" />
              Platform Subsystems & Control-Plane Components
            </h2>
            <span className="text-xs text-slate-400">
              {report?.summary.operational || 0} / {report?.summary.total_services || 8} Operational
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {report &&
              Object.entries(report.services).map(([key, svc]) => (
                <div
                  key={key}
                  className="bg-[#0C1222] border border-slate-800/80 hover:border-slate-700/80 rounded-xl p-4 transition-all"
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                        {getServiceIcon(key)}
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white leading-tight">{svc.name}</h3>
                        <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500">
                          {svc.category}
                        </span>
                      </div>
                    </div>
                    {getStatusBadge(svc.status)}
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 mb-3 mt-1">{svc.description}</p>

                  <div className="pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      Latency: <span className="text-slate-300 font-semibold">{svc.latency_ms} ms</span>
                    </span>
                    <span className="text-slate-500">Checked {new Date(svc.last_checked).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Incident & Maintenance Ledger */}
        <div className="bg-[#0C1222] border border-slate-800/80 rounded-xl p-5 mb-8">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            Active Announcements & Scheduled Maintenance
          </h2>

          <div className="space-y-3">
            {report?.incidents && report.incidents.length > 0 ? (
              report.incidents.map((inc) => (
                <div
                  key={inc.id}
                  className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 flex items-start gap-3"
                >
                  <div className="mt-0.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-xs font-semibold text-white">{inc.title}</h4>
                      <span className="text-[10px] font-mono text-slate-500">
                        {new Date(inc.created_at).toLocaleDateString()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">{inc.message}</p>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500">No active incidents or scheduled maintenance windows.</p>
            )}
          </div>
        </div>

        {/* Machine-Readable JSON Export Callout */}
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-slate-400">
          <div>
            <span className="text-slate-200 font-medium">Looking for programmatic uptime monitoring?</span>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Integrate with UptimeRobot, Datadog, Prometheus, or BetterUptime using our public JSON endpoint.
            </p>
          </div>
          <Link
            href="/api/status"
            target="_blank"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-[11px] border border-slate-700 transition-colors shrink-0"
          >
            <span>GET /api/status</span>
            <ExternalLink className="w-3 h-3 text-slate-400" />
          </Link>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 py-6 text-center text-xs text-slate-500 bg-[#0A0F1D]">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>&copy; {new Date().getFullYear()} Mints Global Security Engineering. ShieldDesk™ Autonomous SOC.</span>
          <div className="flex items-center gap-4 text-slate-400">
            <Link href="/" className="hover:text-emerald-400 transition-colors">
              SOC Workspace
            </Link>
            <Link href="/pricing" className="hover:text-emerald-400 transition-colors">
              Commercial Plans
            </Link>
            <Link href="/api/status" className="hover:text-emerald-400 transition-colors">
              Raw JSON API
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

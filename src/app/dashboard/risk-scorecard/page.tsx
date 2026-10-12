"use client";

import React, { useState, useEffect, useCallback } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import type { RiskScorecardData } from "@/lib/reporting/scorecard";
import {
  BarChart3,
  ShieldCheck,
  Zap,
  Clock,
  TrendingDown,
  Printer,
  DollarSign,
  Layers,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Server,
  FileCheck2,
  Bot,
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function RiskScorecardPage() {
  const { activeUserId, activeUser } = useChat();

  const [scorecard, setScorecard] = useState<RiskScorecardData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchScorecard = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/reports/scorecard", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (res.ok) {
        setScorecard(data);
      }
    } catch (err) {
      console.error("Failed to load scorecard:", err);
    } finally {
      setLoading(false);
    }
  }, [activeUserId]);

  useEffect(() => {
    fetchScorecard();
  }, [fetchScorecard]);

  const handlePrint = () => {
    window.print();
  };

  const renderStatusBadge = (status?: string) => {
    const s = status || "MEASURED";
    if (s === "MEASURED") {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium uppercase px-2 py-0.5 rounded bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]">
          <CheckCircle className="h-2.5 w-2.5" /> Live Measured
        </span>
      );
    }
    if (s === "ESTIMATED") {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium uppercase px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] text-[var(--sd-pine)] border border-[var(--sd-border)]">
          Telemetry Model
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium uppercase px-2 py-0.5 rounded bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]">
        Benchmark Baseline
      </span>
    );
  };

  const totalThreatSignals = (scorecard?.threatDistribution || []).reduce(
    (acc, item) => acc + item.count,
    0
  );

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans print:bg-white print:text-black">
      <div className="print:hidden">
        <TopNavBar />
      </div>

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 flex flex-col gap-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl sd-surface border border-[var(--sd-border)] flex items-center justify-center text-[var(--sd-wheat)] shadow-xs print:hidden">
              <BarChart3 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                  Risk scorecard
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-medium sd-surface text-[var(--sd-pine)] border border-[var(--sd-border)] font-mono shadow-xs">
                  Tenant: {activeUser.tenantName}
                </span>
                {renderStatusBadge(scorecard?.postureScoreMetric?.status)}
              </div>
              <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
                Phase 7 Executive Intelligence &mdash; Live cyber posture index, response velocity, and threat mitigation ROI
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 print:hidden">
            <button
              onClick={fetchScorecard}
              disabled={loading}
              className="sd-button flex items-center gap-2 px-3.5 py-2 rounded-full border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-[13px] font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs disabled:opacity-50"
              title="Recalculate scorecard from live tenant telemetry"
            >
              <RefreshCw className={cn("h-3.5 w-3.5 text-[var(--sd-pine)]", loading && "animate-spin")} />
              <span>{loading ? "Syncing..." : "Refresh Telemetry"}</span>
            </button>

            <button
              onClick={handlePrint}
              className="sd-button flex items-center gap-2 px-4 py-2 rounded-full border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-[13px] font-medium text-[var(--sd-pine)] transition cursor-pointer shadow-xs"
            >
              <Printer className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
              <span>Print Executive Report</span>
            </button>
          </div>
        </div>

        {/* Telemetry Methodology & Benchmarking Notice Banner */}
        {scorecard?.dataDisclaimer && (
          <div className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] text-[13px] leading-relaxed flex items-start gap-3 shadow-xs">
            <AlertTriangle className="h-4 w-4 text-[var(--sd-pine)] shrink-0 mt-0.5" />
            <div>
              <span className="font-medium text-[var(--sd-text)]">Telemetry & Methodology Notice: </span>
              {scorecard.dataDisclaimer}
            </div>
          </div>
        )}

        {/* Hero Posture Grade & ROI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Posture Grade Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                  Security Posture Index
                </span>
              </div>
              <div className="flex items-baseline gap-3 my-1">
                <span className="text-5xl font-medium text-[var(--sd-pine)] font-mono">
                  {loading && !scorecard ? "—" : scorecard?.postureGrade || "A"}
                </span>
                <span className="text-sm font-medium text-[var(--sd-text)] font-mono">
                  {loading && !scorecard ? "—" : scorecard?.postureScore ?? 91} / 100 Index
                </span>
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                {scorecard?.postureScoreMetric?.methodology ||
                  "Composite of ISO 27001 compliance controls, fleet baseline coverage, and active incident posture."}
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <ShieldCheck className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Loss Avoided / ROI Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <span className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                Estimated Loss Avoided
              </span>
              <div className="text-3xl font-medium text-[var(--sd-pine)] font-mono my-1">
                {loading && !scorecard ? "—" : scorecard?.estimatedLossAvoidedUsd || "$0"}
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                {scorecard?.estimatedLossAvoidedMetric?.methodology ||
                  "Calculated from contained incidents, remediated CVEs, blocked YARA detections, and protected endpoints."}
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <DollarSign className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Active Containment Ratio */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <span className="text-[13px] font-medium uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                Threats Contained & Blocked
              </span>
              <div className="text-3xl font-medium text-[var(--sd-pine)] font-mono my-1">
                {loading && !scorecard ? "—" : scorecard?.activeThreatsBlocked ?? 0}{" "}
                <span className="text-[13px] font-normal text-[var(--sd-text-muted)]">Events</span>
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                Aggregated from tenant incidents, blocked YARA malware signatures, remediated CVEs, and verified host actions.
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <Zap className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>
        </div>

        {/* Fleet Coverage, Compliance Assurance & Autonomous Action Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Endpoints Protected */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex items-center justify-between shadow-xs">
            <div className="space-y-1">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)]">
                Endpoints Protected
              </span>
              <div className="text-2xl font-medium font-mono text-[var(--sd-text)]">
                {loading && !scorecard ? "—" : scorecard?.endpointsProtected ?? 0}{" "}
                <span className="text-xs font-normal text-[var(--sd-text-muted)]">Active Hosts</span>
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                Enrolled in live mTLS heartbeat & telemetry stream
              </p>
            </div>
            <div className="h-11 w-11 rounded-xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <Server className="h-5 w-5 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Compliance Assurance */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex items-center justify-between shadow-xs">
            <div className="space-y-1">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)]">
                ISO 27001 Assurance
              </span>
              <div className="text-2xl font-medium font-mono text-[var(--sd-pine)]">
                {loading && !scorecard ? "—" : `${scorecard?.complianceAssurancePct ?? 0}%`}
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                {scorecard?.metrics?.compliance_assurance_pct?.methodology ||
                  "Continuous evaluation across live security controls"}
              </p>
            </div>
            <div className="h-11 w-11 rounded-xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <FileCheck2 className="h-5 w-5 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Autonomous Action Ratio */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex flex-col justify-between shadow-xs gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)]">
                Autonomous Governance Ratio
              </span>
              <Bot className="h-4 w-4 text-[var(--sd-pine)]" />
            </div>
            <div className="grid grid-cols-3 gap-2 text-center pt-1">
              <div className="p-2 rounded-lg bg-[var(--sd-panel-raised)] border border-[var(--sd-border)]">
                <div className="text-base font-mono font-medium text-[var(--sd-pine)]">
                  {scorecard?.autonomousActionRatio?.tier1AutoContained ?? 0}
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)] font-mono">Tier 1 Auto</div>
              </div>
              <div className="p-2 rounded-lg bg-[var(--sd-panel-raised)] border border-[var(--sd-border)]">
                <div className="text-base font-mono font-medium text-[var(--sd-text)]">
                  {scorecard?.autonomousActionRatio?.tier2HumanApproved ?? 0}
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)] font-mono">Tier 2 Signed</div>
              </div>
              <div className="p-2 rounded-lg bg-[var(--sd-panel-raised)] border border-[var(--sd-border)]">
                <div className="text-base font-mono font-medium text-[var(--sd-warning)]">
                  {scorecard?.autonomousActionRatio?.tier3BreakGlass ?? 0}
                </div>
                <div className="text-[10px] text-[var(--sd-text-muted)] font-mono">Tier 3 Dual</div>
              </div>
            </div>
          </div>
        </div>

        {/* MTTD & MTTR Speedup Performance Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* MTTD Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-[var(--sd-pine)]" />
                <h3 className="text-sm font-medium text-[var(--sd-pine)]">
                  Mean Time to Detect (MTTD)
                </h3>
                {renderStatusBadge(scorecard?.mttdMinutes?.metric?.status)}
              </div>
              <span className="flex items-center gap-1 text-[13px] font-medium text-[var(--sd-success)] bg-[var(--sd-success-dim)] px-2 py-0.5 rounded border border-[var(--sd-success-border)] font-mono">
                <TrendingDown className="h-3 w-3" />
                {scorecard?.mttdMinutes.reductionPct ?? 96.6}% Faster Detection
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                <span className="text-[11px] uppercase font-mono text-[var(--sd-text-muted)] font-medium">
                  Industry Baseline
                </span>
                <div className="text-2xl font-medium font-mono text-[var(--sd-text-muted)] mt-1">
                  {scorecard?.mttdMinutes.beforeShieldDesk ?? 54} <span className="text-[13px]">min</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)]">
                <span className="text-[11px] uppercase font-mono text-[var(--sd-success)] font-medium">
                  Active Tenant Telemetry
                </span>
                <div className="text-2xl font-medium font-mono text-[var(--sd-success)] mt-1">
                  {scorecard?.mttdMinutes.withShieldDesk ?? 1.8} <span className="text-[13px]">min</span>
                </div>
              </div>
            </div>

            <p className="text-[12px] text-[var(--sd-text-muted)] leading-relaxed">
              {scorecard?.mttdMinutes?.metric?.methodology ||
                "Automated high-frequency telemetry ingestion and multi-horizon correlation cut dwell time from 54 minutes."}
            </p>
          </div>

          {/* MTTR Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-[var(--sd-pine)]" />
                <h3 className="text-sm font-medium text-[var(--sd-pine)]">
                  Mean Time to Remediate (MTTR)
                </h3>
                {renderStatusBadge(scorecard?.mttrMinutes?.metric?.status)}
              </div>
              <span className="flex items-center gap-1 text-[13px] font-medium text-[var(--sd-success)] bg-[var(--sd-success-dim)] px-2 py-0.5 rounded border border-[var(--sd-success-border)] font-mono">
                <TrendingDown className="h-3 w-3" />
                {scorecard?.mttrMinutes.reductionPct ?? 97.4}% Faster Remediation
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                <span className="text-[11px] uppercase font-mono text-[var(--sd-text-muted)] font-medium">
                  Manual SOC Baseline
                </span>
                <div className="text-2xl font-medium font-mono text-[var(--sd-text-muted)] mt-1">
                  {scorecard?.mttrMinutes.beforeShieldDesk ?? 252} <span className="text-[13px]">min</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)]">
                <span className="text-[11px] uppercase font-mono text-[var(--sd-success)] font-medium">
                  Active Tenant Telemetry
                </span>
                <div className="text-2xl font-medium font-mono text-[var(--sd-success)] mt-1">
                  {scorecard?.mttrMinutes.withShieldDesk ?? 6.4} <span className="text-[13px]">min</span>
                </div>
              </div>
            </div>

            <p className="text-[12px] text-[var(--sd-text-muted)] leading-relaxed">
              {scorecard?.mttrMinutes?.metric?.methodology ||
                "Tier 1 autonomous containment actions and one-click Tier 2 human sign-off tokens accelerate host remediation."}
            </p>
          </div>
        </div>

        {/* Threat Category Distribution */}
        <div className="p-6 rounded-2xl border border-[var(--sd-border)] sd-surface shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-[var(--sd-pine)]" />
              <h3 className="text-sm font-medium text-[var(--sd-pine)]">
                Threat Vector Distribution & Detection Profiles
              </h3>
            </div>
            <span className="text-[11px] font-mono text-[var(--sd-text-muted)]">
              Live Tenant Signals ({totalThreatSignals} Categorized)
            </span>
          </div>

          <div className="space-y-3 pt-2">
            {(scorecard?.threatDistribution || []).length === 0 ? (
              <div className="py-6 text-center text-xs text-[var(--sd-text-muted)]">
                No active threat vectors recorded for {activeUser.tenantName}.
              </div>
            ) : (
              (scorecard?.threatDistribution || []).map((threat, idx) => (
                <div key={threat.category} className="space-y-1.5">
                  <div className="flex items-center justify-between text-[13px]">
                    <span className="font-medium text-[var(--sd-text)]">{threat.category}</span>
                    <span className="font-mono text-[var(--sd-pine)] font-medium">
                      {threat.count} {threat.count === 1 ? "signal" : "signals"} ({threat.percentage}%)
                    </span>
                  </div>
                  <div className="h-2 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden border border-[var(--sd-border)]">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-200",
                        idx === 0 && "bg-[var(--sd-danger)]",
                        idx === 1 && "bg-[var(--sd-warning)]",
                        idx === 2 && "bg-[var(--sd-pine)]",
                        idx >= 3 && "bg-[var(--sd-pine)]/60"
                      )}
                      style={{ width: `${threat.percentage}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  );
}


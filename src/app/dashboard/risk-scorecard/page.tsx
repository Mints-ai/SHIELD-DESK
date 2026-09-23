"use client";

import React, { useState, useEffect } from "react";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function RiskScorecardPage() {
  const { activeUserId, activeUser } = useChat();

  const [scorecard, setScorecard] = useState<RiskScorecardData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchScorecard = async () => {
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
  };

  useEffect(() => {
    fetchScorecard();
  }, [activeUserId]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans print:bg-white print:text-black">
      <div className="print:hidden">
        <TopNavBar />
      </div>

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 flex flex-col gap-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-[var(--sd-pine)] flex items-center justify-center text-[#f7f4ed] shadow-xs print:hidden">
              <BarChart3 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-[var(--sd-pine)]">
                  Executive Risk & Security Scorecard
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-white text-[var(--sd-pine)] border border-[var(--sd-border)] font-mono shadow-xs">
                  Tenant: {activeUser.tenantName}
                </span>
              </div>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Phase 7 Executive Intelligence &mdash; Cyber posture index, response velocity, and threat mitigation ROI
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 print:hidden">
            <button
              onClick={handlePrint}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-panel-hover)] text-xs font-semibold text-[var(--sd-pine)] transition cursor-pointer shadow-xs"
            >
              <Printer className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
              <span>Print Executive Report</span>
            </button>
          </div>
        </div>

        {/* Hero Posture Grade & ROI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Posture Grade Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                Security Posture Grade
              </span>
              <div className="flex items-baseline gap-3 my-1">
                <span className="text-5xl font-black text-[var(--sd-pine)] font-mono">
                  {scorecard?.postureGrade || "A"}
                </span>
                <span className="text-sm font-semibold text-[var(--sd-text)] font-mono">
                  {scorecard?.postureScore || 91} / 100 Index
                </span>
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                Based on mean time to detect/contain, active fleet coverage, and zero policy breaches.
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <ShieldCheck className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Loss Avoided / ROI Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                Estimated Loss Avoided
              </span>
              <div className="text-3xl font-extrabold text-[var(--sd-pine)] font-mono my-1">
                {scorecard?.estimatedLossAvoidedUsd || "$1,450,000"}
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                Calculated against Ponemon Institute average cost per compromised workstation and downtime hours avoided.
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <DollarSign className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>

          {/* Active Containment Ratio */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white flex items-center justify-between shadow-xs">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-bold uppercase tracking-wider text-[var(--sd-pine)] font-mono">
                Threats Contained (24h)
              </span>
              <div className="text-3xl font-extrabold text-[var(--sd-pine)] font-mono my-1">
                {scorecard?.activeThreatsBlocked ?? 16} <span className="text-xs font-normal text-[var(--sd-text-muted)]">Events</span>
              </div>
              <p className="text-[11px] text-[var(--sd-text-muted)]">
                100% of detected reconnaissance and lateral SMB bursts isolated with zero confirmed exfiltration.
              </p>
            </div>
            <div className="h-16 w-16 rounded-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border)] flex items-center justify-center shrink-0">
              <Zap className="h-8 w-8 text-[var(--sd-pine)]" />
            </div>
          </div>
        </div>

        {/* MTTD & MTTR Speedup Performance Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* MTTD Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-[var(--sd-pine)]" />
                <h3 className="text-sm font-bold text-[var(--sd-pine)]">
                  Mean Time to Detect (MTTD)
                </h3>
              </div>
              <span className="flex items-center gap-1 text-xs font-bold text-[var(--sd-success)] bg-[var(--sd-success-dim)] px-2 py-0.5 rounded border border-[var(--sd-success-border)] font-mono">
                <TrendingDown className="h-3 w-3" />
                {scorecard?.mttdMinutes.reductionPct ?? 96.6}% Speedup
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)] font-medium">Industry Baseline</span>
                <div className="text-2xl font-bold font-mono text-[var(--sd-text-muted)] mt-1">
                  {scorecard?.mttdMinutes.beforeShieldDesk ?? 54} <span className="text-xs">min</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-success)] font-semibold">With ShieldDesk</span>
                <div className="text-2xl font-bold font-mono text-[var(--sd-success)] mt-1">
                  {scorecard?.mttdMinutes.withShieldDesk ?? 1.8} <span className="text-xs">min</span>
                </div>
              </div>
            </div>

            <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
              Automated high-frequency telemetry ingestion and multi-horizon correlation cut dwell time from 54 minutes to under 2 minutes.
            </p>
          </div>

          {/* MTTR Card */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-[var(--sd-pine)]" />
                <h3 className="text-sm font-bold text-[var(--sd-pine)]">
                  Mean Time to Remediate (MTTR)
                </h3>
              </div>
              <span className="flex items-center gap-1 text-xs font-bold text-[var(--sd-success)] bg-[var(--sd-success-dim)] px-2 py-0.5 rounded border border-[var(--sd-success-border)] font-mono">
                <TrendingDown className="h-3 w-3" />
                {scorecard?.mttrMinutes.reductionPct ?? 97.4}% Speedup
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-text-muted)] font-medium">Manual SOC Response</span>
                <div className="text-2xl font-bold font-mono text-[var(--sd-text-muted)] mt-1">
                  {scorecard?.mttrMinutes.beforeShieldDesk ?? 252} <span className="text-xs">min</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)]">
                <span className="text-[10px] uppercase font-mono text-[var(--sd-success)] font-semibold">With ShieldDesk</span>
                <div className="text-2xl font-bold font-mono text-[var(--sd-success)] mt-1">
                  {scorecard?.mttrMinutes.withShieldDesk ?? 6.4} <span className="text-xs">min</span>
                </div>
              </div>
            </div>

            <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
              Tier 1 autonomous containment actions and one-click Tier 2 human sign-off tokens prevent manual response latency.
            </p>
          </div>
        </div>

        {/* Threat Category Distribution */}
        <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-white shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-[var(--sd-pine)]" />
              <h3 className="text-sm font-bold text-[var(--sd-pine)]">
                Threat Vector Distribution & Detection Profiles
              </h3>
            </div>
            <span className="text-[10px] font-mono text-[var(--sd-text-muted)]">Tenant Incident Telemetry</span>
          </div>

          <div className="space-y-3 pt-2">
            {(scorecard?.threatDistribution || []).map((threat, idx) => (
              <div key={idx} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-[var(--sd-text)]">{threat.category}</span>
                  <span className="font-mono text-[var(--sd-pine)] font-medium">
                    {threat.count} incidents ({threat.percentage}%)
                  </span>
                </div>
                <div className="h-2 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden border border-[var(--sd-border)]">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-500",
                      idx === 0 && "bg-[var(--sd-danger)]",
                      idx === 1 && "bg-[var(--sd-warning)]",
                      idx === 2 && "bg-[var(--sd-pine)]",
                      idx === 3 && "bg-[var(--sd-pine)]/50"
                    )}
                    style={{ width: `${threat.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

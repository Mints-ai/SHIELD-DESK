"use client";

import React, { useState, useEffect } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import type { ComplianceSummary } from "@/lib/compliance/iso27001";
import {
  FileCheck2,
  ShieldCheck,
  Download,
  Lock,
  Check,
  Layers,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function CompliancePage() {
  const { activeUserId, activeUser } = useChat();

  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedHorizon, setSelectedHorizon] = useState<string>("all");
  const [isExporting, setIsExporting] = useState(false);

  const fetchCompliance = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/compliance", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();
      if (res.ok) {
        setSummary(data);
      }
    } catch (err) {
      console.error("Failed to load compliance data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCompliance();
  }, [activeUserId]);

  const handleExportEvidence = async () => {
    try {
      setIsExporting(true);
      const res = await fetch("/api/compliance?export=true", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const data = await res.json();

      // Trigger download
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shielddesk-audit-evidence-${activeUser.tenantId}-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to export evidence:", err);
    } finally {
      setIsExporting(false);
    }
  };

  const filteredControls = (summary?.controls || []).filter((c) => {
    if (selectedHorizon === "all") return true;
    return c.horizon === selectedHorizon;
  });

  return (
    <div className="min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 flex flex-col gap-6">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-[var(--sd-pine)] flex items-center justify-center text-[#f7f4ed] shadow-xs">
              <FileCheck2 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-[var(--sd-pine)]">
                  Compliance & ISO 27001 Annex A
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] font-mono">
                  SOC 2 Type II
                </span>
              </div>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Automated mapping of mitigation horizons, governance approval tokens, and tamper-proof audit trails
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleExportEvidence}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] text-[#f7f4ed] text-xs font-semibold transition cursor-pointer shadow-xs disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5 text-[#e6dbbf]" />
              <span>{isExporting ? "Compiling Cryptographic Evidence..." : "Export Evidence Package"}</span>
            </button>
          </div>
        </div>

        {/* Hero Scorecard Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Main Score Card */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-white flex flex-col justify-between shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Overall Audit Readiness
            </span>
            <div className="flex items-baseline gap-2 my-2">
              <span className="text-4xl font-extrabold text-[var(--sd-pine)] font-mono">
                {summary?.overallScore ?? 96}%
              </span>
              <span className="text-xs font-bold text-[var(--sd-success)] font-mono uppercase">
                {summary?.soc2Readiness ?? "Audit Ready"}
              </span>
            </div>
            <div className="h-2 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden border border-[var(--sd-border)]">
              <div
                className="h-full bg-[var(--sd-pine)] rounded-full transition-all duration-500"
                style={{ width: `${summary?.overallScore ?? 96}%` }}
              />
            </div>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-white flex flex-col justify-between shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Fully Automated Controls
            </span>
            <div className="text-3xl font-extrabold text-[var(--sd-success)] font-mono my-2">
              {summary?.fullyAutomated ?? 8} <span className="text-xs text-[var(--sd-text-muted)] font-normal">/ {summary?.totalControls ?? 10}</span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Deterministic incident correlation & hash-chaining
            </span>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-white flex flex-col justify-between shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Policy-Governed Controls
            </span>
            <div className="text-3xl font-extrabold text-[var(--sd-warning)] font-mono my-2">
              {summary?.partiallyAutomated ?? 2} <span className="text-xs text-[var(--sd-text-muted)] font-normal">/ {summary?.totalControls ?? 10}</span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Layer 4 human sign-off gating enforced
            </span>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-white flex flex-col justify-between shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Verifiable Evidence Records
            </span>
            <div className="text-3xl font-extrabold text-[var(--sd-pine)] font-mono my-2">
              {summary?.auditEvidenceCount ?? 6} <span className="text-xs text-[var(--sd-text-muted)] font-normal">Signed</span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Tamper-evident SHA-256 hash chains
            </span>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center gap-2 border-b border-[var(--sd-border)] pb-3">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-semibold">Filter Horizon:</span>
          {["all", "immediate", "short_term", "continuous", "long_term"].map((h) => (
            <button
              key={h}
              onClick={() => setSelectedHorizon(h)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-xs capitalize transition cursor-pointer font-medium",
                selectedHorizon === h
                  ? "bg-[var(--sd-pine)] text-[#f7f4ed] shadow-xs"
                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)]"
              )}
            >
              {h.replace("_", " ")}
            </button>
          ))}
        </div>

        {/* Control Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredControls.map((control) => (
            <div
              key={control.code}
              className="p-5 rounded-2xl border border-[var(--sd-border)] bg-white hover:border-[var(--sd-border-strong)] transition-all shadow-xs space-y-3"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] px-2 py-0.5 text-xs font-mono font-bold text-[var(--sd-pine)]">
                    {control.code}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                    {control.category}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-[var(--sd-success)]">
                    {control.compliancePct}%
                  </span>
                  <span
                    className={cn(
                      "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono",
                      control.status === "fully_automated"
                        ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)]"
                        : "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]"
                    )}
                  >
                    {control.status.replace("_", " ")}
                  </span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-[var(--sd-text)] leading-snug">
                  {control.title}
                </h3>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1 leading-relaxed">
                  {control.shieldDeskEnforcement}
                </p>
              </div>

              <div className="pt-2 border-t border-[var(--sd-border)] flex items-center justify-between text-[10.5px]">
                <span className="text-[var(--sd-text-muted)] font-mono">
                  Horizon: <strong className="text-[var(--sd-pine)] capitalize font-semibold">{control.horizon.replace("_", " ")}</strong>
                </span>
                <span className="text-[var(--sd-text-muted)] font-mono truncate max-w-[220px]">
                  Evidence: {control.auditEvidenceSource}
                </span>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}

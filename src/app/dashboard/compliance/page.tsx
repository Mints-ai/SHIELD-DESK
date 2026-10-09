"use client";

import React, { useState, useEffect } from "react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import { useChat } from "@/lib/context/ChatContext";
import type { FrameworkId, FrameworkControl } from "@/lib/compliance/frameworks";
import { FrameworkSelector } from "@/components/compliance/FrameworkSelector";
import { ControlEvidenceModal } from "@/components/compliance/ControlEvidenceModal";
import { HashChainVerifierModal } from "@/components/compliance/HashChainVerifierModal";
import { ExecutiveReportModal } from "@/components/compliance/ExecutiveReportModal";
import { ComplianceScanBanner } from "@/components/compliance/ComplianceScanBanner";
import { PolicyVaultModal } from "@/components/compliance/PolicyVaultModal";
import {
  FileCheck2,
  Download,
  Printer,
  FileSpreadsheet,
  FileCode,
  Hash,
  FileText,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ComplianceDashboardData {
  id: string;
  name: string;
  badge: string;
  title: string;
  overallScore: number;
  readinessRating: string;
  totalControls: number;
  fullyAutomated: number;
  partiallyAutomated: number;
  policyGoverned: number;
  auditEvidenceCount: number;
  controls: FrameworkControl[];
}

export default function CompliancePage() {
  const { activeUserId, activeUser } = useChat();

  const [selectedFramework, setSelectedFramework] = useState<FrameworkId>("iso27001");
  const [data, setData] = useState<ComplianceDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedHorizon, setSelectedHorizon] = useState<string>("all");
  const [isExporting, setIsExporting] = useState(false);
  const [exportDropdownOpen, setExportDropdownOpen] = useState(false);

  // Modals
  const [inspectingControlCode, setInspectingControlCode] = useState<string | null>(null);
  const [isVerifierOpen, setIsVerifierOpen] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isPolicyVaultOpen, setIsPolicyVaultOpen] = useState(false);

  const handleFrameworkChange = (fw: FrameworkId) => {
    setLoading(true);
    setSelectedFramework(fw);
  };

  useEffect(() => {
    let ignore = false;
    fetch(`/api/compliance?framework=${selectedFramework}`, {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then((res) => res.json())
      .then((json) => {
        if (!ignore) {
          setData(json);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!ignore) {
          console.error("Failed to load compliance data:", err);
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [selectedFramework, activeUserId]);

  const handleExport = async (format: "json" | "csv") => {
    try {
      setIsExporting(true);
      setExportDropdownOpen(false);

      const res = await fetch(`/api/compliance?export=true&format=${format}`, {
        headers: { "X-ShieldDesk-User": activeUserId },
      });

      if (format === "json") {
        const json = await res.json();
        const blob = new Blob([JSON.stringify(json, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `shielddesk-audit-evidence-${activeUser.tenantId}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const text = await res.text();
        const blob = new Blob([text], { type: "text/csv; charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `shielddesk-audit-trail-${activeUser.tenantId}-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error("Failed to export evidence:", err);
    } finally {
      setIsExporting(false);
    }
  };

  const filteredControls = (data?.controls || []).filter((c: FrameworkControl) => {
    if (selectedHorizon === "all") return true;
    return c.horizon === selectedHorizon;
  });

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      <TopNavBar />

      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 flex flex-col gap-6">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl sd-surface border border-[var(--sd-border)] flex items-center justify-center text-[var(--sd-wheat)] shadow-xs">
              <FileCheck2 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="tracking-tight text-[var(--sd-text)] text-3xl font-light leading-tight">
                  Enterprise Compliance & Audit Operations
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] font-mono">
                  {data?.badge || "Live Verified SOC"}
                </span>
              </div>
              <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
                Real-time evaluation of live telemetry, cryptographic SHA-256 hash chains, and dual-custody governance tokens
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 relative">
            {/* Verify Ledger Integrity */}
            <button
              onClick={() => setIsVerifierOpen(true)}
              className="sd-button px-3.5 py-2 rounded-xl text-xs font-medium border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <Hash className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
              <span>Verify Ledger Integrity</span>
            </button>

            {/* Policy Vault */}
            <button
              onClick={() => setIsPolicyVaultOpen(true)}
              className="sd-button px-3.5 py-2 rounded-xl text-xs font-medium border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <FileText className="h-3.5 w-3.5 text-[var(--sd-wheat)]" />
              <span>Policy Vault</span>
            </button>

            {/* Export Evidence Dropdown */}
            <div className="relative">
              <button
                onClick={() => setExportDropdownOpen(!exportDropdownOpen)}
                disabled={isExporting}
                className="sd-button sd-button-primary flex items-center gap-2 px-4 py-2 rounded-xl text-[var(--sd-on-accent)] text-xs font-medium transition cursor-pointer shadow-xs disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5 text-[var(--sd-on-accent)]" />
                <span>{isExporting ? "Compiling Bundle..." : "Export Evidence"}</span>
                <ChevronDown className="h-3.5 w-3.5 ml-0.5 opacity-80" />
              </button>

              {exportDropdownOpen && (
                <div className="absolute right-0 top-full mt-2 w-64 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] p-2 shadow-2xl z-40 space-y-1">
                  <button
                    onClick={() => handleExport("json")}
                    className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-[var(--sd-panel-raised)] transition flex items-center gap-2.5 text-xs text-[var(--sd-text)] cursor-pointer"
                  >
                    <FileCode className="h-4 w-4 text-[var(--sd-pine)] shrink-0" />
                    <div>
                      <div className="font-medium">Signed Evidence Package (JSON)</div>
                      <div className="text-[10px] text-[var(--sd-text-muted)]">
                        Merkle proofs, events & Python verifier
                      </div>
                    </div>
                  </button>

                  <button
                    onClick={() => handleExport("csv")}
                    className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-[var(--sd-panel-raised)] transition flex items-center gap-2.5 text-xs text-[var(--sd-text)] cursor-pointer"
                  >
                    <FileSpreadsheet className="h-4 w-4 text-[var(--sd-wheat)] shrink-0" />
                    <div>
                      <div className="font-medium">Audit Trail Log (CSV)</div>
                      <div className="text-[10px] text-[var(--sd-text-muted)]">
                        Chronological tabular spreadsheet
                      </div>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setExportDropdownOpen(false);
                      setIsReportOpen(true);
                    }}
                    className="w-full text-left px-3 py-2.5 rounded-xl hover:bg-[var(--sd-panel-raised)] transition flex items-center gap-2.5 text-xs text-[var(--sd-text)] cursor-pointer border-t border-[var(--sd-border)]"
                  >
                    <Printer className="h-4 w-4 text-emerald-500 shrink-0" />
                    <div>
                      <div className="font-medium">Executive Auditor Report</div>
                      <div className="text-[10px] text-[var(--sd-text-muted)]">
                        Printable formal compliance package
                      </div>
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Framework Selector Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-[var(--sd-text-muted)]">
            <span>REGULATORY COMPLIANCE FRAMEWORK</span>
            <span>STANDARD: {data?.name || "ISO/IEC 27001:2022"}</span>
          </div>
          <FrameworkSelector
            selectedFramework={selectedFramework}
            onSelectFramework={handleFrameworkChange}
            isLoading={loading}
          />
        </div>

        {/* Live Automated Scan Banner */}
        <ComplianceScanBanner
          activeUserId={activeUserId}
          onScanComplete={() => {
            fetch(`/api/compliance?framework=${selectedFramework}`, {
              headers: { "X-ShieldDesk-User": activeUserId },
            })
              .then((res) => res.json())
              .then((json) => setData(json))
              .catch((err) => console.error("Scan reload failed:", err));
          }}
        />

        {/* Hero Scorecard Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Main Score Card */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex flex-col justify-between shadow-xs">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Live Audit Readiness
            </span>
            <div className="flex items-baseline gap-2 my-2">
              <span className="text-4xl font-medium text-[var(--sd-pine)] font-mono">
                {data?.overallScore ?? 96}%
              </span>
              <span className="text-[13px] font-medium text-[var(--sd-success)] font-mono uppercase">
                {data?.readinessRating?.replace("_", " ") ?? "Audit Ready"}
              </span>
            </div>
            <div className="h-2 w-full bg-[var(--sd-bg-alt)] rounded-full overflow-hidden border border-[var(--sd-border)]">
              <div
                className="h-full bg-[var(--sd-pine)] rounded-full transition-all duration-300"
                style={{ width: `${data?.overallScore ?? 96}%` }}
              />
            </div>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex flex-col justify-between shadow-xs">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Fully Automated Controls
            </span>
            <div className="text-3xl font-medium text-[var(--sd-success)] font-mono my-2">
              {data?.fullyAutomated ?? 8}{" "}
              <span className="text-[13px] text-[var(--sd-text-muted)] font-normal">
                / {data?.totalControls ?? 10}
              </span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Deterministic correlation & continuous telemetry
            </span>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex flex-col justify-between shadow-xs">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Policy-Governed Controls
            </span>
            <div className="text-3xl font-medium text-[var(--sd-warning)] font-mono my-2">
              {data?.partiallyAutomated ?? 2}{" "}
              <span className="text-[13px] text-[var(--sd-text-muted)] font-normal">
                / {data?.totalControls ?? 10}
              </span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Dual-custody approval gating enforced
            </span>
          </div>

          <div className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface flex flex-col justify-between shadow-xs">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--sd-text-muted)] font-mono">
              Verifiable Evidence Records
            </span>
            <div className="text-3xl font-medium text-[var(--sd-pine)] font-mono my-2">
              {data?.auditEvidenceCount ?? 15}{" "}
              <span className="text-[13px] text-[var(--sd-text-muted)] font-normal">Signed</span>
            </div>
            <span className="text-[11px] text-[var(--sd-text-muted)]">
              Tamper-evident SHA-256 hash chains
            </span>
          </div>
        </div>

        {/* Horizon Filter Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="text-[13px] text-[var(--sd-text-muted)] font-mono">Horizon:</span>
            <div className="sd-tabs" role="group" aria-label="Filter controls by horizon">
              {["all", "immediate", "short_term", "continuous", "long_term"].map((h) => (
                <button
                  key={h}
                  onClick={() => setSelectedHorizon(h)}
                  aria-pressed={selectedHorizon === h}
                  className="capitalize font-mono text-xs"
                >
                  {h.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>

          <span className="text-xs text-[var(--sd-text-muted)] font-mono">
            Click any control card to inspect live evidence records & policies
          </span>
        </div>

        {/* Control Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredControls.map((control: FrameworkControl) => (
            <div
              key={control.code}
              onClick={() => setInspectingControlCode(control.code)}
              className="p-5 rounded-2xl border border-[var(--sd-border)] sd-surface hover:border-[var(--sd-pine)] hover:shadow-md transition-all shadow-xs space-y-3 cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] px-2 py-0.5 text-[13px] font-mono font-medium text-[var(--sd-pine)] group-hover:border-[var(--sd-pine)]/50 transition-colors">
                    {control.code}
                  </span>
                  <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--sd-text-muted)] font-medium">
                    {control.category}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[13px] font-mono font-medium text-[var(--sd-success)]">
                    {control.compliancePct}%
                  </span>
                  <span
                    className={cn(
                      "px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider font-mono",
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
                <h3 className="text-sm font-medium text-[var(--sd-text)] leading-snug group-hover:text-[var(--sd-pine)] transition-colors">
                  {control.title}
                </h3>
                <p className="text-[13px] text-[var(--sd-text-muted)] mt-1 leading-relaxed">
                  {control.shieldDeskEnforcement}
                </p>
              </div>

              <div className="pt-2 border-t border-[var(--sd-border)] flex items-center justify-between text-[11px]">
                <span className="text-[var(--sd-text-muted)] font-mono">
                  Horizon:{" "}
                  <strong className="text-[var(--sd-pine)] capitalize font-medium">
                    {control.horizon.replace("_", " ")}
                  </strong>
                </span>
                <span className="text-[var(--sd-text-muted)] font-mono truncate max-w-[220px]">
                  Evidence: {control.auditEvidenceSource}
                </span>
              </div>
            </div>
          ))}
        </div>
      </main>

      {/* Control Evidence Modal */}
      <ControlEvidenceModal
        controlCode={inspectingControlCode}
        frameworkId={selectedFramework}
        onClose={() => setInspectingControlCode(null)}
        activeUserId={activeUserId}
      />

      {/* Hash Chain Verifier Modal */}
      <HashChainVerifierModal
        isOpen={isVerifierOpen}
        onClose={() => setIsVerifierOpen(false)}
        activeUserId={activeUserId}
      />

      {/* Executive Report Modal */}
      <ExecutiveReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        frameworkId={selectedFramework}
        activeUserId={activeUserId}
      />

      {/* Policy Vault Modal */}
      <PolicyVaultModal
        isOpen={isPolicyVaultOpen}
        onClose={() => setIsPolicyVaultOpen(false)}
        activeUserId={activeUserId}
      />
    </div>
  );
}

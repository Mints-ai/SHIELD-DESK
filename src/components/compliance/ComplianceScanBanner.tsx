"use client";

import React, { useState } from "react";
import {
  Play,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { ComplianceScanResult, ScanFinding } from "@/lib/compliance/scanner";

interface ComplianceScanBannerProps {
  activeUserId: string;
  onScanComplete?: () => void;
}

export function ComplianceScanBanner({
  activeUserId,
  onScanComplete,
}: ComplianceScanBannerProps) {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ComplianceScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const handleRunScan = async () => {
    try {
      setScanning(true);
      setError(null);
      const res = await fetch("/api/compliance/scan", {
        method: "POST",
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const json = await res.json();
      if (res.ok && json.scan) {
        setScanResult(json.scan);
        setIsOpen(true);
        if (onScanComplete) {
          onScanComplete();
        }
      } else {
        setError(json.error || "Failed to execute compliance audit scan.");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="w-full rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] p-4 shadow-xs space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)] flex items-center justify-center shrink-0">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-semibold text-[var(--sd-text)] tracking-tight">
                Automated Operational Compliance Audit
              </h3>
              {scanResult && (
                <span
                  className={cn(
                    "text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-medium",
                    scanResult.overallStatus === "PASSED"
                      ? "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]"
                      : scanResult.overallStatus === "WARNING"
                      ? "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)]"
                      : "bg-red-500/10 text-red-400 border-red-500/20"
                  )}
                >
                  {scanResult.overallStatus} ({scanResult.readinessScore}%)
                </span>
              )}
            </div>
            <p className="text-[11px] text-[var(--sd-text-muted)] mt-0.5">
              Live automated health checks: agent heartbeats, vulnerability SLAs, separation of duties, & tamper ledgers.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {scanResult && (
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="px-2.5 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition flex items-center gap-1 cursor-pointer font-mono"
            >
              <span>{isOpen ? "Hide Findings" : "View Findings"}</span>
              {isOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
          )}

          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="px-3.5 py-1.5 rounded-xl bg-[var(--sd-pine)] text-white text-xs font-medium hover:bg-[var(--sd-pine)]/90 transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-xs"
          >
            {scanning ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5 fill-current" />
            )}
            <span>{scanning ? "Evaluating Telemetry..." : "Run Compliance Scan"}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-red-500/20 bg-red-500/10 text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Findings Drawer */}
      {isOpen && scanResult && (
        <div className="pt-3 border-t border-[var(--sd-border)] space-y-2.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-[var(--sd-text-muted)]">
            <span>
              AUDIT RESULTS: {scanResult.checksPassed} PASSED / {scanResult.checksFailed} FAILED
            </span>
            <span>SCAN ID: {scanResult.scanId}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {scanResult.findings?.map((f: ScanFinding) => {
              const isPass = f.status === "PASS";
              return (
                <div
                  key={f.id}
                  className={cn(
                    "p-3 rounded-xl border transition-all text-xs flex flex-col justify-between gap-2",
                    isPass
                      ? "border-[var(--sd-border)] bg-[var(--sd-panel-raised)]/30"
                      : "border-red-500/30 bg-red-500/5"
                  )}
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        {isPass ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-[var(--sd-success)] shrink-0" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                        )}
                        <span className="font-medium text-[var(--sd-text)]">
                          {f.title}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-[var(--sd-pine)]">
                        {f.controlCode}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--sd-text-muted)] leading-relaxed">
                      {f.description}
                    </p>
                  </div>

                  <div className="pt-1.5 border-t border-[var(--sd-border)]/50 flex items-center justify-between text-[10px]">
                    <span className="font-mono text-[var(--sd-text-muted)] truncate max-w-[200px]">
                      {f.evidenceSnippet}
                    </span>
                    {f.remediationAction && (
                      <a
                        href={f.remediationUrl || "#"}
                        className="text-[var(--sd-pine)] hover:underline font-medium flex items-center gap-1 shrink-0"
                      >
                        <span>{f.remediationAction}</span>
                        <ExternalLink className="h-2.5 w-2.5" />
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

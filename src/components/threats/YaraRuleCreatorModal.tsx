"use client";

import React, { useState } from "react";
import {
  X,
  CheckCircle2,
  AlertTriangle,
  Save,
  Check,
  FileCode2,
} from "lucide-react";

interface YaraRuleCreatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRuleCreated: () => void;
}

export function YaraRuleCreatorModal({
  isOpen,
  onClose,
  onRuleCreated,
}: YaraRuleCreatorModalProps) {
  const [name, setName] = useState("");
  const [category, setCategory] = useState("Malware / Custom");
  const [severity, setSeverity] = useState<"critical" | "high" | "medium" | "low">("high");
  const [target, setTarget] = useState("filesystem / process memory");
  const [description, setDescription] = useState("");
  const [rawContent, setRawContent] = useState(`rule Custom_Threat_Signature {
    meta:
        description = "Detects suspicious threat indicator"
        severity = "high"
        category = "Custom"
    strings:
        $s1 = "suspicious_payload_string" nocase
    condition:
        any of them
}`);

  const [validating, setValidating] = useState(false);
  const [validationSuccess, setValidationSuccess] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!isOpen) return null;

  const handleValidate = async () => {
    setValidating(true);
    setValidationSuccess(null);
    setValidationError(null);

    try {
      const res = await fetch("/api/threats/yara/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          raw_content: rawContent,
          sample_payload: "test",
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setValidationError(
          `Syntax error at Line ${data.line || 1}, Col ${data.column || 1}: ${data.message || data.error}`
        );
      } else {
        setValidationSuccess(`Valid YARA AST syntax (Rule: ${data.ruleName || "OK"})`);
      }
    } catch (err: unknown) {
      setValidationError(err instanceof Error ? err.message : "Failed to validate rule syntax");
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setValidationError(null);

    try {
      const res = await fetch("/api/threats/yara", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim() || undefined,
          category,
          severity,
          target,
          description,
          raw_content: rawContent,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setValidationError(
          data.error + (data.line ? ` (Line ${data.line}, Col ${data.column}): ${data.message || ""}` : "")
        );
      } else {
        onRuleCreated();
        onClose();
      }
    } catch (err: unknown) {
      setValidationError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="relative w-full max-w-3xl bg-[var(--sd-surface)] border border-[var(--sd-border)] rounded-2xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[var(--sd-border)] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-[var(--sd-pine-dim)] text-[var(--sd-pine)] border border-[var(--sd-pine-border)]">
              <FileCode2 className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-[var(--sd-text)]">
                Create Custom YARA Malware Rule
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Author and deploy new tenant-isolated threat detection signatures
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

        {/* Form Body */}
        <form onSubmit={handleSave} className="p-6 overflow-y-auto space-y-4 flex-1">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[var(--sd-text-muted)] mb-1">
                Rule Name (optional override)
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Backdoor_ShadowBypass_V2"
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[var(--sd-text-muted)] mb-1">
                Category
              </label>
              <input
                type="text"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                placeholder="e.g. Ransomware, C2 / Beacon, Webshell"
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[var(--sd-text-muted)] mb-1">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as "critical" | "high" | "medium" | "low")}
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[var(--sd-text-muted)] mb-1">
                Target Inspection Zone
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. filesystem / webroot, process memory"
                className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[var(--sd-text-muted)] mb-1">
              Description / Analyst Notes
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief explanation of threat behavior and mitigation steps"
              className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)]"
            />
          </div>

          {/* Raw .yar Editor */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-xs font-medium text-[var(--sd-text-muted)]">
                YARA Rule Syntax (.yar)
              </label>
              <button
                type="button"
                onClick={handleValidate}
                disabled={validating || !rawContent.trim()}
                className="text-xs text-[var(--sd-pine)] hover:text-[var(--sd-pine-bright)] flex items-center gap-1 cursor-pointer disabled:opacity-50"
              >
                <Check className="h-3 w-3" />
                <span>{validating ? "Validating..." : "Validate Syntax"}</span>
              </button>
            </div>
            <textarea
              value={rawContent}
              onChange={(e) => {
                setRawContent(e.target.value);
                setValidationSuccess(null);
                setValidationError(null);
              }}
              rows={11}
              required
              className="w-full bg-[var(--sd-bg)] text-[var(--sd-text)] border border-[var(--sd-border)] rounded-xl p-3 text-xs font-mono leading-relaxed focus:outline-none focus:ring-1 focus:ring-[var(--sd-pine)] resize-none"
            />
          </div>

          {/* Feedback Banners */}
          {validationSuccess && (
            <div className="p-3 rounded-lg border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] text-xs text-[var(--sd-success)] flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{validationSuccess}</span>
            </div>
          )}

          {validationError && (
            <div className="p-3 rounded-lg border border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-xs text-[var(--sd-danger)] flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{validationError}</span>
            </div>
          )}

          {/* Actions */}
          <div className="pt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg border border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface-subtle)] transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !rawContent.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-bright)] text-black text-xs font-medium shadow-xs transition cursor-pointer disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              <span>{saving ? "Deploying..." : "Save & Deploy Rule"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

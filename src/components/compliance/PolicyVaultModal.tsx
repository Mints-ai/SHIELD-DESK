"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  FileText,
  Plus,
  Search,
} from "lucide-react";
import type { CompliancePolicy } from "@/lib/compliance/policyStore";

interface PolicyVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeUserId: string;
}

export function PolicyVaultModal({
  isOpen,
  onClose,
  activeUserId,
}: PolicyVaultModalProps) {
  const [policies, setPolicies] = useState<CompliancePolicy[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [isAdding, setIsAdding] = useState(false);

  // New policy form state
  const [newCode, setNewCode] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState("Information Security");
  const [newDescription, setNewDescription] = useState("");
  const [newVersion, setNewVersion] = useState("1.0");
  const [newControls, setNewControls] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let ignore = false;
    if (isOpen) {
      fetch("/api/compliance/policies", {
        headers: { "X-ShieldDesk-User": activeUserId },
      })
        .then((res) => res.json())
        .then((json) => {
          if (!ignore) {
            if (json.policies) {
              setPolicies(json.policies);
            } else {
              setError(json.error || "Failed to load compliance policies.");
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
    }
    return () => {
      ignore = true;
    };
  }, [isOpen, activeUserId]);

  if (!isOpen) return null;

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCode || !newTitle) return;

    try {
      setSubmitting(true);
      const mappings = newControls
        .split(",")
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean);

      const res = await fetch("/api/compliance/policies", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": activeUserId,
        },
        body: JSON.stringify({
          policyCode: newCode,
          title: newTitle,
          category: newCategory,
          description: newDescription,
          version: newVersion,
          controlMappings: mappings,
        }),
      });

      const json = await res.json();
      if (res.ok && json.policy) {
        setPolicies((prev) => [json.policy, ...prev]);
        setIsAdding(false);
        // Reset form
        setNewCode("");
        setNewTitle("");
        setNewDescription("");
        setNewControls("");
      } else {
        setError(json.error || "Failed to save policy.");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setSubmitting(false);
    }
  };

  const filtered = policies.filter((p) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      p.policyCode.toLowerCase().includes(q) ||
      p.title.toLowerCase().includes(q) ||
      p.category.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      (p.controlMappings || []).some((m: string) => m.toLowerCase().includes(q))
    );
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      <div className="sd-surface border border-[var(--sd-border)] rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden bg-[var(--sd-surface)] text-[var(--sd-text)]">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)] bg-[var(--sd-bg)]">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30 text-[var(--sd-pine)] flex items-center justify-center">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)] tracking-tight">
                Governance Policy & Document Attachment Vault
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Organizational security policies mapped directly to ISO/IEC 27001, SOC 2, NIST, & HIPAA clauses
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsAdding(!isAdding)}
              className="px-3 py-1.5 rounded-xl bg-[var(--sd-pine)] text-white text-xs font-medium hover:bg-[var(--sd-pine)]/90 transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>{isAdding ? "Cancel" : "Attach New Policy"}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {error && (
            <div className="p-3 rounded-xl border border-red-500/20 bg-red-500/10 text-red-400 text-xs">
              {error}
            </div>
          )}

          {/* New Policy Form */}
          {isAdding && (
            <form
              onSubmit={handleCreatePolicy}
              className="p-4 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-4"
            >
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--sd-text)]">
                Attach New Organizational Policy
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Policy Code *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. POL-SEC-06"
                    value={newCode}
                    onChange={(e) => setNewCode(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] font-mono"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Policy Title *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Cryptographic Key Management & Data Encryption Policy"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)]"
                  />
                </div>

                <div>
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Category
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Cryptography & Data Protection"
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)]"
                  />
                </div>

                <div>
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Version
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 1.0"
                    value={newVersion}
                    onChange={(e) => setNewVersion(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] font-mono"
                  />
                </div>

                <div>
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Mapped Control Codes (comma separated)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. A.8.24, CC6.2, PR.DS-01"
                    value={newControls}
                    onChange={(e) => setNewControls(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)] font-mono"
                  />
                </div>

                <div className="sm:col-span-3">
                  <label className="text-[11px] font-mono text-[var(--sd-text-muted)] block mb-1">
                    Policy Scope & Executive Description
                  </label>
                  <textarea
                    rows={2}
                    placeholder="Describe the governance mandate, compliance scope, and enforcement requirements..."
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] focus:outline-hidden focus:border-[var(--sd-pine)]"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAdding(false)}
                  className="px-3 py-1.5 rounded-xl border border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)] hover:bg-[var(--sd-panel-raised)] cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-xl bg-[var(--sd-pine)] text-white text-xs font-medium hover:bg-[var(--sd-pine)]/90 cursor-pointer disabled:opacity-50"
                >
                  {submitting ? "Saving..." : "Save Policy Attachment"}
                </button>
              </div>
            </form>
          )}

          {/* Search Bar */}
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--sd-text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter policies by code, title, category, or linked control clauses..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-hidden focus:border-[var(--sd-pine)]"
            />
          </div>

          {/* Policies Grid */}
          <div className="space-y-3">
            {loading ? (
              <div className="py-12 text-center text-xs text-[var(--sd-text-muted)]">
                Loading compliance policy documents...
              </div>
            ) : filtered.length === 0 ? (
              <div className="p-8 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-center text-xs text-[var(--sd-text-muted)]">
                No policy documents match your filter.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {filtered.map((pol) => (
                  <div
                    key={pol.id}
                    className="p-4 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] hover:border-[var(--sd-border-strong)] transition-all shadow-xs flex flex-col justify-between gap-3"
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)]">
                            {pol.policyCode}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] uppercase">
                            {pol.status}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                          v{pol.version}
                        </span>
                      </div>

                      <h3 className="text-sm font-medium text-[var(--sd-text)] leading-snug">
                        {pol.title}
                      </h3>
                      <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed">
                        {pol.description}
                      </p>
                    </div>

                    <div className="space-y-2 pt-2 border-t border-[var(--sd-border)]">
                      <div className="flex flex-wrap items-center gap-1">
                        <span className="text-[10px] font-mono text-[var(--sd-text-muted)] mr-1">
                          Mapped:
                        </span>
                        {(pol.controlMappings || []).map((code: string) => (
                          <span
                            key={code}
                            className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-pine)]"
                          >
                            {code}
                          </span>
                        ))}
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-[var(--sd-text-muted)] font-mono">
                        <span>Category: {pol.category}</span>
                        <span>Review: {pol.reviewDate?.slice(0, 10)}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[var(--sd-border)] bg-[var(--sd-bg)] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition cursor-pointer"
          >
            Close Vault
          </button>
        </div>
      </div>
    </div>
  );
}

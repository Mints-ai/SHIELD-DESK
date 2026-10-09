"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  X,
  CheckCircle2,
  AlertTriangle,
  Search,
  Copy,
  Check,
  RefreshCw,
  Hash,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { DetailedVerificationReport, VerifiedBlockDetail } from "@/lib/compliance/verifier";

interface HashChainVerifierModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeUserId: string;
}

export function HashChainVerifierModal({
  isOpen,
  onClose,
  activeUserId,
}: HashChainVerifierModalProps) {
  const [data, setData] = useState<DetailedVerificationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedBlocks, setExpandedBlocks] = useState<Record<number, boolean>>({});
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const runVerification = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch("/api/compliance/verify", {
        headers: { "X-ShieldDesk-User": activeUserId },
      });
      const json = await res.json();
      if (res.ok && json.verification) {
        setData(json.verification);
      } else {
        setError(json.error || "Failed to verify ledger integrity.");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setLoading(false);
    }
  }, [activeUserId]);

  useEffect(() => {
    let ignore = false;
    if (isOpen) {
      fetch("/api/compliance/verify", {
        headers: { "X-ShieldDesk-User": activeUserId },
      })
        .then((res) => res.json())
        .then((json) => {
          if (!ignore) {
            if (json.verification) {
              setData(json.verification);
            } else {
              setError(json.error || "Failed to verify ledger integrity.");
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

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const toggleExpand = (idx: number) => {
    setExpandedBlocks((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const filteredBlocks = (data?.blocks || []).filter((b: VerifiedBlockDetail) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const hash = (b.currentHash || "").toLowerCase();
    const prev = (b.prevHash || "").toLowerCase();
    const id = (b.id || "").toLowerCase();
    const actor = (b.actorId || "").toLowerCase();
    const eventType = (b.eventType || "").toLowerCase();
    const payloadStr = JSON.stringify(b.payload || {}).toLowerCase();
    return (
      hash.includes(q) ||
      prev.includes(q) ||
      id.includes(q) ||
      actor.includes(q) ||
      eventType.includes(q) ||
      payloadStr.includes(q)
    );
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      <div className="sd-surface border border-[var(--sd-border)] rounded-2xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden bg-[var(--sd-surface)] text-[var(--sd-text)]">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[var(--sd-border)] bg-[var(--sd-bg)]">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-[var(--sd-pine)]/15 border border-[var(--sd-pine)]/30 text-[var(--sd-pine)] flex items-center justify-center">
              <Hash className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-medium text-[var(--sd-text)] tracking-tight">
                Cryptographic Hash-Chain Ledger Verifier
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)] mt-0.5">
                Deterministic SHA-256 block recalculation, sequence link validation, and Merkle tree audit
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={runVerification}
              disabled={loading}
              className="px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs font-mono font-medium hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>{loading ? "Recalculating Hashes..." : "Re-Verify Ledger"}</span>
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
          {/* Status Banner */}
          {loading ? (
            <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-center text-sm text-[var(--sd-text-muted)] flex flex-col items-center gap-2">
              <div className="h-6 w-6 border-2 border-[var(--sd-pine)] border-t-transparent rounded-full animate-spin" />
              <span>Recalculating SHA-256 hashes from Genesis to Head...</span>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl border border-red-500/20 bg-red-500/10 text-red-400 text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          ) : data?.valid ? (
            <div className="p-4 rounded-2xl border border-[var(--sd-success-border)] bg-[var(--sd-success-dim)] text-[var(--sd-success)] flex items-center justify-between gap-3 shadow-xs">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="h-5 w-5 shrink-0" />
                <div>
                  <h3 className="text-sm font-semibold tracking-tight">
                    100% Mathematically Validated — Zero Tampering Detected
                  </h3>
                  <p className="text-xs opacity-90 mt-0.5">
                    All {data.totalBlocks} blocks sequentially link from Genesis to Head. Computed Merkle Root and SHA-256 hashes match cryptographic proofs.
                  </p>
                </div>
              </div>
              <span className="font-mono text-xs px-2 py-0.5 rounded-md bg-[var(--sd-bg)] text-[var(--sd-success)] border border-[var(--sd-success-border)] shrink-0">
                CHAIN HEAD: {data.chainHeadHash?.slice(0, 10)}...
              </span>
            </div>
          ) : (
            <div className="p-4 rounded-2xl border border-red-500/30 bg-red-500/10 text-red-400 flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 shrink-0" />
              <div>
                <h3 className="text-sm font-semibold tracking-tight">
                  Cryptographic Integrity Alert: Chain Tampering or Link Failure
                </h3>
                <p className="text-xs opacity-90 mt-0.5">
                  {data?.failureReason || "Hash calculation mismatch detected."}
                </p>
              </div>
            </div>
          )}

          {/* Cryptographic KPIs */}
          {data && (
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)]">
                <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase">
                  Verified Blocks
                </span>
                <div className="text-2xl font-mono font-medium text-[var(--sd-text)] mt-1">
                  {data.totalBlocks}
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] flex flex-col justify-between">
                <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase">
                  Genesis Block
                </span>
                <div className="flex items-center justify-between gap-1 mt-1">
                  <span className="font-mono text-xs text-[var(--sd-pine)] truncate max-w-[140px]">
                    {data.genesisHash?.slice(0, 16)}...
                  </span>
                  <button
                    onClick={() => handleCopy(data.genesisHash)}
                    className="p-1 rounded hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] cursor-pointer"
                    title="Copy Genesis Hash"
                  >
                    {copiedHash === data.genesisHash ? <Check className="h-3 w-3 text-[var(--sd-success)]" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] flex flex-col justify-between">
                <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase">
                  Chain Head Hash
                </span>
                <div className="flex items-center justify-between gap-1 mt-1">
                  <span className="font-mono text-xs text-[var(--sd-pine)] truncate max-w-[140px]">
                    {data.chainHeadHash?.slice(0, 16)}...
                  </span>
                  <button
                    onClick={() => handleCopy(data.chainHeadHash)}
                    className="p-1 rounded hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] cursor-pointer"
                    title="Copy Chain Head Hash"
                  >
                    {copiedHash === data.chainHeadHash ? <Check className="h-3 w-3 text-[var(--sd-success)]" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              </div>

              <div className="p-3.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] flex flex-col justify-between">
                <span className="text-[11px] font-mono text-[var(--sd-text-muted)] uppercase">
                  Merkle Tree Root
                </span>
                <div className="flex items-center justify-between gap-1 mt-1">
                  <span className="font-mono text-xs text-[var(--sd-wheat)] truncate max-w-[140px]">
                    {data.merkleRoot?.slice(0, 16)}...
                  </span>
                  <button
                    onClick={() => handleCopy(data.merkleRoot)}
                    className="p-1 rounded hover:bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] cursor-pointer"
                    title="Copy Merkle Root"
                  >
                    {copiedHash === data.merkleRoot ? <Check className="h-3 w-3 text-[var(--sd-success)]" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Search Bar */}
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--sd-text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search blocks by SHA-256 transaction hash, event type, actor ID, or payload content..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus:outline-hidden focus:border-[var(--sd-pine)] font-mono"
            />
          </div>

          {/* Block Sequence Explorer */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-[var(--sd-text-muted)] px-1">
              <span>BLOCK SEQUENCE ({filteredBlocks.length} OF {data?.totalBlocks || 0})</span>
              <span>SHA-256 CONTINUITY</span>
            </div>

            <div className="space-y-2">
              {filteredBlocks.map((block: VerifiedBlockDetail) => {
                const isExpanded = !!expandedBlocks[block.blockIndex];
                const isGenesis = block.eventType === "GENESIS";
                const isTampered = block.status === "TAMPERED" || block.status === "BROKEN_LINK";

                return (
                  <div
                    key={block.blockIndex}
                    className={cn(
                      "rounded-xl border transition-all duration-150 overflow-hidden bg-[var(--sd-bg)]",
                      isTampered
                        ? "border-red-500/40 bg-red-500/5"
                        : "border-[var(--sd-border)] hover:border-[var(--sd-border-strong)]"
                    )}
                  >
                    <div
                      onClick={() => toggleExpand(block.blockIndex)}
                      className="p-3.5 flex items-center justify-between gap-3 cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-3">
                        <button className="text-[var(--sd-text-muted)]">
                          {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        </button>
                        <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)]">
                          #{block.blockIndex}
                        </span>
                        <span
                          className={cn(
                            "font-mono text-[10px] font-medium px-2 py-0.5 rounded border uppercase",
                            isGenesis
                              ? "bg-[var(--sd-pine)]/15 text-[var(--sd-pine)] border-[var(--sd-pine)]/30"
                              : isTampered
                              ? "bg-red-500/20 text-red-400 border-red-500/30"
                              : "bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border-[var(--sd-border)]"
                          )}
                        >
                          {block.eventType}
                        </span>
                        <span className="text-xs text-[var(--sd-text)] truncate max-w-[160px]">
                          {block.actorId}
                        </span>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[11px] text-[var(--sd-pine)] hidden md:inline truncate max-w-[200px]">
                          {block.currentHash.slice(0, 16)}...
                        </span>
                        <span
                          className={cn(
                            "text-[10px] font-mono px-2 py-0.5 rounded border font-medium uppercase",
                            isTampered
                              ? "bg-red-500/20 text-red-400 border-red-500/30"
                              : "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]"
                          )}
                        >
                          {block.status}
                        </span>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="p-4 border-t border-[var(--sd-border)] bg-[var(--sd-panel-raised)]/40 space-y-3 text-xs">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
                          <div>
                            <span className="text-[var(--sd-text-muted)]">Current SHA-256 Hash:</span>
                            <div className="p-1.5 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-pine)] break-all mt-0.5">
                              {block.currentHash}
                            </div>
                          </div>
                          <div>
                            <span className="text-[var(--sd-text-muted)]">Previous Link Hash:</span>
                            <div className="p-1.5 rounded bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[var(--sd-text-muted)] break-all mt-0.5">
                              {block.prevHash}
                            </div>
                          </div>
                        </div>

                        <div>
                          <span className="text-[11px] font-mono text-[var(--sd-text-muted)]">
                            Event Payload JSON:
                          </span>
                          <pre className="p-3 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border)] text-[11px] font-mono text-[var(--sd-text)] overflow-x-auto mt-1 max-h-[160px]">
                            {JSON.stringify(block.payload, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[var(--sd-border)] bg-[var(--sd-bg)] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-text)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))] transition cursor-pointer"
          >
            Close Verifier
          </button>
        </div>
      </div>
    </div>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  X,
  History,
  ExternalLink,
  RefreshCw,
  Clock,
  Terminal,
} from "lucide-react";
import type { YaraMatchRecord, YaraStringMatch } from "@/lib/detection/yara/types";

interface YaraMatchHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function YaraMatchHistoryModal({
  isOpen,
  onClose,
}: YaraMatchHistoryModalProps) {
  const [matches, setMatches] = useState<YaraMatchRecord[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let active = true;
    if (isOpen) {
      fetch("/api/threats/yara/matches?limit=50")
        .then((res) => res.json())
        .then((data) => {
          if (active && data.matches) {
            setMatches(data.matches);
          }
        })
        .catch(() => {})
        .finally(() => {
          if (active) setLoading(false);
        });
    }
    return () => {
      active = false;
    };
  }, [isOpen]);

  const handleManualRefresh = () => {
    setLoading(true);
    fetch("/api/threats/yara/matches?limit=50")
      .then((res) => res.json())
      .then((data) => {
        if (data.matches) {
          setMatches(data.matches);
        }
      })
      .catch(() => {})
      .finally(() => {
        setLoading(false);
      });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-[var(--sd-surface)] border border-[var(--sd-border)] rounded-2xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[var(--sd-border)] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)]">
              <History className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-medium text-[var(--sd-text)]">
                YARA Malware Match History
              </h2>
              <p className="text-xs text-[var(--sd-text-muted)]">
                Audit trail of endpoint pattern detections and auto-correlated SOC incidents
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleManualRefresh}
              disabled={loading}
              className="p-1.5 rounded-lg text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface-subtle)] transition cursor-pointer"
              title="Refresh match log"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface-subtle)] transition cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Matches Table / List */}
        <div className="p-6 overflow-y-auto space-y-3 flex-1">
          {matches.length === 0 ? (
            <div className="py-12 text-center text-xs text-[var(--sd-text-muted)]">
              No recent YARA malware matches recorded for this tenant.
            </div>
          ) : (
            matches.map((m) => (
              <div
                key={m.id}
                className="p-4 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] space-y-2 shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono">
                      {m.rule_id}
                    </span>
                    <span className="text-xs font-mono text-[var(--sd-text)] font-medium">
                      Agent: {m.agent_id}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-xs">
                    {m.incident_id && (
                      <Link
                        href={`/dashboard/incidents?search=${m.incident_id}`}
                        className="flex items-center gap-1 text-[var(--sd-pine)] hover:text-[var(--sd-pine-bright)] font-mono font-medium underline text-xs"
                      >
                        <span>View Incident</span>
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                    <span className="text-[11px] text-[var(--sd-text-muted)] font-mono flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(m.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-[var(--sd-text-muted)] flex items-center gap-1.5 font-mono">
                  <Terminal className="h-3.5 w-3.5 text-[var(--sd-text-muted)] shrink-0" />
                  <span className="truncate">File / Target: <code className="text-[var(--sd-text)]">{m.file_path}</code></span>
                </div>

                {/* Snippets / Matched strings */}
                {m.matched_strings && m.matched_strings.length > 0 && (
                  <div className="pt-1.5 flex flex-wrap gap-2 text-[11px] font-mono">
                    {m.matched_strings.map((str: YaraStringMatch, i: number) => (
                      <div
                        key={i}
                        className="px-2 py-1 rounded bg-[var(--sd-surface-subtle)] border border-[var(--sd-border)] text-[var(--sd-text)]"
                      >
                        <span className="text-[var(--sd-danger)] font-semibold">{str.id}</span>
                        {str.offset !== undefined && (
                          <span className="text-[var(--sd-text-muted)]"> @ {str.offset}</span>
                        )}
                        {str.snippet && (
                          <span className="ml-1 opacity-80 truncate max-w-xs inline-block align-bottom">
                            &quot;{str.snippet}&quot;
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-[var(--sd-border)] bg-[var(--sd-surface-subtle)] flex items-center justify-between">
          <span className="text-xs text-[var(--sd-text-muted)]">
            Total records: {matches.length}
          </span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg border border-[var(--sd-border)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] hover:bg-[var(--sd-surface)] transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

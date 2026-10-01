"use client";

import React from "react";
import { Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface ModelConfidenceMeterProps {
  confidence: number; // e.g. 0.96 for 96%
  size?: "sm" | "md";
}

export function ModelConfidenceMeter({ confidence, size = "md" }: ModelConfidenceMeterProps) {
  const percentage = Math.round(confidence * 100);

  const getMeterColor = (pct: number) => {
    if (pct >= 90) return "bg-[var(--sd-pine)]";
    if (pct >= 75) return "bg-[var(--sd-warning)]";
    return "bg-[var(--sd-danger)]";
  };

  return (
    <div
      className={cn(
        "flex items-center gap-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] px-3 py-1.5",
        size === "sm" ? "text-xs" : "text-sm"
      )}
    >
      <Sparkles className="h-3.5 w-3.5 text-[var(--sd-pine)] shrink-0" />
      <div className="flex-1 min-w-[110px]">
        <div className="flex items-center justify-between text-[11px] text-[var(--sd-text-muted)] mb-1">
          <span>AI Confidence</span>
          <span className="font-mono font-bold text-[var(--sd-text)]">{percentage}%</span>
        </div>
        <div role="meter" aria-label="AI confidence" aria-valuenow={percentage} aria-valuemin={0} aria-valuemax={100} className="h-1.5 w-full rounded-full bg-[var(--sd-bg)] overflow-hidden border border-[var(--sd-border-subtle)]">
          <div
            className={cn("h-full rounded-full transition-[width] duration-200 motion-reduce:transition-none", getMeterColor(percentage))}
            style={{ width: `${Math.max(0, Math.min(100, percentage))}%` }}
          />
        </div>
      </div>
    </div>
  );
}

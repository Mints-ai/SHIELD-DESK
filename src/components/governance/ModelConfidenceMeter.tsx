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
    if (pct >= 90) return "bg-[var(--sd-pine-bright)]";
    if (pct >= 75) return "bg-[var(--sd-warning)]";
    return "bg-[var(--sd-danger)]";
  };

  return (
    <div
      className={cn(
        "flex items-center gap-2.5 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] px-3 py-1.5",
        size === "sm" ? "text-xs" : "text-sm"
      )}
    >
      <Sparkles className="h-3.5 w-3.5 text-[var(--sd-beige)] shrink-0" />
      <div className="flex-1 min-w-[70px]">
        <div className="flex items-center justify-between text-[10px] text-[var(--sd-text-muted)] mb-1">
          <span>AI Confidence</span>
          <span className="font-mono font-bold text-[var(--sd-beige-light)]">{percentage}%</span>
        </div>
        <div className="h-1.5 w-full rounded-full bg-[var(--sd-bg)] overflow-hidden border border-[var(--sd-border-subtle)]">
          <div
            className={cn("h-full rounded-full transition-all duration-500", getMeterColor(percentage))}
            style={{ width: `${percentage}%` }}
          />
        </div>
      </div>
    </div>
  );
}

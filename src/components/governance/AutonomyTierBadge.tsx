"use client";

import React from "react";
import { ShieldAlert, AlertTriangle, Eye, Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AutonomyTier } from "@/lib/governance/autonomyTier";

interface AutonomyTierBadgeProps {
  tier: AutonomyTier | string;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
}

export function AutonomyTierBadge({
  tier,
  size = "md",
  showLabel = true,
}: AutonomyTierBadgeProps) {
  const normalized = tier.toUpperCase();

  if (normalized.includes("3")) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 font-bold uppercase tracking-wider rounded-md border",
          "bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border-[var(--sd-danger-border)] shadow-xs",
          size === "sm" ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-xs"
        )}
        title="Tier 3: High-Risk / Irreversible (Requires dual senior human approvals)"
      >
        <Lock className={cn("shrink-0", size === "sm" ? "h-2.5 w-2.5" : "h-3.5 w-3.5")} />
        <span>Tier 3</span>
        {showLabel && <span className="text-[10px] font-medium text-[var(--sd-danger)]/80">(Dual-Approved)</span>}
      </span>
    );
  }

  if (normalized.includes("2")) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 font-bold uppercase tracking-wider rounded-md border",
          "bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border-[var(--sd-warning-border)] shadow-xs",
          size === "sm" ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-xs"
        )}
        title="Tier 2: Medium-Risk (Requires 1 distinct human approval)"
      >
        <AlertTriangle className={cn("shrink-0", size === "sm" ? "h-2.5 w-2.5" : "h-3.5 w-3.5")} />
        <span>Tier 2</span>
        {showLabel && <span className="text-[10px] font-medium text-[var(--sd-warning)]/80">(Human Sign-Off)</span>}
      </span>
    );
  }

  if (normalized.includes("1")) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 font-semibold uppercase tracking-wider rounded-md border",
          "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)] shadow-xs",
          size === "sm" ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-xs"
        )}
        title="Tier 1: Low-Risk / Reversible (Automatic execution once enabled)"
      >
        <ShieldAlert className={cn("shrink-0", size === "sm" ? "h-2.5 w-2.5" : "h-3.5 w-3.5")} />
        <span>Tier 1</span>
        {showLabel && <span className="text-[10px] font-medium text-[var(--sd-success)]/80">(Auto-Action)</span>}
      </span>
    );
  }

  // Tier 0
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 font-medium uppercase tracking-wider rounded-md border",
        "bg-[var(--sd-panel-raised)] text-[var(--sd-beige-dim)] border-[var(--sd-border)] shadow-xs",
        size === "sm" ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-xs"
      )}
      title="Tier 0: Observation Only (Never acts)"
    >
      <Eye className={cn("shrink-0", size === "sm" ? "h-2.5 w-2.5" : "h-3.5 w-3.5")} />
      <span>Tier 0</span>
      {showLabel && <span className="text-[10px] font-normal text-[var(--sd-text-muted)]">(Observation)</span>}
    </span>
  );
}

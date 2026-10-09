"use client";

import React from "react";
import type { FrameworkId } from "@/lib/compliance/frameworks";
import { Shield, Award, Landmark, Stethoscope } from "lucide-react";
import { cn } from "@/lib/utils";

interface FrameworkSelectorProps {
  selectedFramework: FrameworkId;
  onSelectFramework: (id: FrameworkId) => void;
  isLoading?: boolean;
}

const FRAMEWORKS: {
  id: FrameworkId;
  name: string;
  badge: string;
  icon: React.ElementType;
  description: string;
}[] = [
  {
    id: "iso27001",
    name: "ISO/IEC 27001:2022",
    badge: "ISMS Standard",
    icon: Shield,
    description: "Information security management, technical controls, & continuous monitoring.",
  },
  {
    id: "soc2",
    name: "SOC 2 Type II",
    badge: "AICPA Trust Services",
    icon: Award,
    description: "Security, availability, confidentiality criteria with dual-custody verification.",
  },
  {
    id: "nist",
    name: "NIST CSF 2.0",
    badge: "Cybersecurity Framework",
    icon: Landmark,
    description: "Govern, Identify, Protect, Detect, Respond, and Recover core functions.",
  },
  {
    id: "hipaa",
    name: "HIPAA Security",
    badge: "45 CFR Part 164",
    icon: Stethoscope,
    description: "Administrative, physical, and technical safeguards for protected health data.",
  },
];

export function FrameworkSelector({
  selectedFramework,
  onSelectFramework,
  isLoading = false,
}: FrameworkSelectorProps) {
  return (
    <div className="w-full grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {FRAMEWORKS.map((fw) => {
        const isSelected = selectedFramework === fw.id;
        const Icon = fw.icon;

        return (
          <button
            key={fw.id}
            onClick={() => onSelectFramework(fw.id)}
            disabled={isLoading}
            className={cn(
              "text-left p-3.5 rounded-2xl border transition-all duration-150 flex flex-col justify-between gap-2 shadow-xs cursor-pointer relative overflow-hidden",
              isSelected
                ? "bg-[var(--sd-panel-raised)] border-[var(--sd-pine)] shadow-sm ring-1 ring-[var(--sd-pine)]/30"
                : "sd-surface border-[var(--sd-border)] hover:border-[var(--sd-border-strong)] hover:bg-[var(--sd-surface-hover,var(--sd-panel-raised))]"
            )}
          >
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <div
                  className={cn(
                    "h-7 w-7 rounded-lg flex items-center justify-center transition-colors",
                    isSelected
                      ? "bg-[var(--sd-pine)] text-white"
                      : "bg-[var(--sd-bg-alt)] text-[var(--sd-text-muted)] border border-[var(--sd-border)]"
                  )}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <span className="text-xs font-semibold tracking-tight text-[var(--sd-text)]">
                  {fw.name}
                </span>
              </div>
              <span
                className={cn(
                  "text-[10px] font-mono px-1.5 py-0.5 rounded border",
                  isSelected
                    ? "bg-[var(--sd-pine)]/15 text-[var(--sd-pine)] border-[var(--sd-pine)]/30 font-medium"
                    : "bg-[var(--sd-bg)] text-[var(--sd-text-muted)] border-[var(--sd-border)]"
                )}
              >
                {fw.badge}
              </span>
            </div>

            <p className="text-[11px] text-[var(--sd-text-muted)] line-clamp-2 leading-relaxed">
              {fw.description}
            </p>
          </button>
        );
      })}
    </div>
  );
}

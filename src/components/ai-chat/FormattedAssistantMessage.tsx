"use client";

import React from "react";
import { ShieldAlert, AlertTriangle, CheckCircle, Info, Tag } from "lucide-react";

interface FormattedAssistantMessageProps {
  content: string;
}

export function FormattedAssistantMessage({ content }: FormattedAssistantMessageProps) {
  if (!content) return null;

  // Split into paragraphs / lines
  const lines = content.split("\n");

  const renderFormattedLine = (line: string, index: number) => {
    // Check if line is a governance notice
    if (/governance\s*note/i.test(line) || /advisory\s*recommendation/i.test(line)) {
      return (
        <div
          key={index}
          className="my-2 flex items-start gap-2 rounded-xl border border-[var(--sd-warning-border)] bg-[var(--sd-warning-dim)] p-2.5 text-[11px] text-[var(--sd-warning)]"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--sd-warning)]" />
          <span className="leading-relaxed">{line}</span>
        </div>
      );
    }

    // Numbered item: "1. ", "2. "
    const numberedMatch = line.match(/^(\d+)\.\s+(.*)$/);
    if (numberedMatch) {
      return (
        <div key={index} className="my-1 flex items-start gap-2 text-xs leading-relaxed text-[var(--sd-text)]">
          <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--sd-pine)] text-[10px] font-bold text-[#f7f4ed] font-mono">
            {numberedMatch[1]}
          </span>
          <div className="flex-1">{renderTokens(numberedMatch[2])}</div>
        </div>
      );
    }

    // Bullet item: "- ", "* "
    const bulletMatch = line.match(/^[-*]\s+(.*)$/);
    if (bulletMatch) {
      return (
        <div key={index} className="my-1 flex items-start gap-2 text-xs leading-relaxed text-[var(--sd-text)] pl-1">
          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--sd-pine)]" />
          <div className="flex-1">{renderTokens(bulletMatch[1])}</div>
        </div>
      );
    }

    // Empty line -> spacing
    if (!line.trim()) {
      return <div key={index} className="h-2" />;
    }

    // Standard paragraph line
    return (
      <p key={index} className="my-1 text-xs leading-relaxed text-[var(--sd-text)]">
        {renderTokens(line)}
      </p>
    );
  };

  /**
   * Tokenizer to render bolding, inline code, severity badges, and incident/CVE chips.
   */
  const renderTokens = (text: string) => {
    // Regex matching bold **text**, code `text`, CVE-xxxx-xxxx, INC-xxxx, or severity tags
    const tokenRegex =
      /(\*\*.*?\*\*|`.*?`|\b(?:CRITICAL|HIGH|MEDIUM|LOW|RESOLVED|INVESTIGATING|OPEN|CLOSED)\b|\bCVE-\d{4}-\d{4,7}\b|\bINC-\d+\b)/g;

    const parts = text.split(tokenRegex);

    return parts.map((part, i) => {
      if (!part) return null;

      // Bold text
      if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
        return (
          <strong key={i} className="font-bold text-[var(--sd-pine)]">
            {part.slice(2, -2)}
          </strong>
        );
      }

      // Inline code
      if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
        return (
          <code
            key={i}
            className="rounded bg-[var(--sd-bg-alt)] px-1.5 py-0.5 font-mono text-[10.5px] text-[var(--sd-pine)] border border-[var(--sd-border)] font-medium"
          >
            {part.slice(1, -1)}
          </code>
        );
      }

      // Severity / Status badges
      const upper = part.toUpperCase();
      if (upper === "CRITICAL") {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-danger-dim)] text-[var(--sd-danger)] border border-[var(--sd-danger-border)] font-mono"
          >
            <ShieldAlert className="h-3 w-3" />
            CRITICAL
          </span>
        );
      }
      if (upper === "HIGH") {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-[var(--sd-warning-dim)] text-[var(--sd-warning)] border border-[var(--sd-warning-border)] font-mono"
          >
            <AlertTriangle className="h-3 w-3" />
            HIGH
          </span>
        );
      }
      if (upper === "MEDIUM") {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border border-[var(--sd-border)] font-mono"
          >
            <Info className="h-3 w-3" />
            MEDIUM
          </span>
        );
      }
      if (upper === "LOW" || upper === "RESOLVED") {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] font-mono"
          >
            <CheckCircle className="h-3 w-3" />
            {upper}
          </span>
        );
      }

      // CVE Chip
      if (/^CVE-\d{4}-\d{4,7}$/i.test(part)) {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded font-mono text-[10.5px] font-semibold bg-white text-[var(--sd-pine)] border border-[var(--sd-border)] shadow-xs"
          >
            <Tag className="h-2.5 w-2.5 text-[var(--sd-pine)]" />
            {part.toUpperCase()}
          </span>
        );
      }

      // Incident Code Chip
      if (/^INC-\d+$/i.test(part)) {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-0.5 px-1.5 py-0.5 rounded font-mono text-[10.5px] font-bold bg-white text-[var(--sd-pine)] border border-[var(--sd-border)] shadow-xs"
          >
            {part.toUpperCase()}
          </span>
        );
      }

      return <span key={i}>{part}</span>;
    });
  };

  return <div className="space-y-0.5">{lines.map((l, i) => renderFormattedLine(l, i))}</div>;
}

"use client";

import React from "react";
import { ShieldAlert, AlertTriangle, CheckCircle, Info, Tag } from "lucide-react";

interface FormattedAssistantMessageProps {
  content: string;
}

type MessageBlock =
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "line"; text: string; index: number };

export function FormattedAssistantMessage({ content }: FormattedAssistantMessageProps) {
  if (!content) return null;

  const parseBlocks = (rawText: string): MessageBlock[] => {
    const rawLines = rawText.split("\n");
    const blocks: MessageBlock[] = [];
    let i = 0;

    while (i < rawLines.length) {
      const trimmed = rawLines[i].trim();

      // Check if line looks like a markdown table row: starts and ends with '|'
      if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
        const tableLines: string[] = [];
        let j = i;
        while (
          j < rawLines.length &&
          rawLines[j].trim().startsWith("|") &&
          rawLines[j].trim().endsWith("|")
        ) {
          tableLines.push(rawLines[j].trim());
          j++;
        }

        if (tableLines.length >= 2) {
          const parsedRows = tableLines.map((tl) =>
            tl
              .slice(1, -1)
              .split("|")
              .map((c) => c.trim())
          );

          const isSeparatorRow = (row: string[]) =>
            row.length > 0 && row.every((c) => /^:?-+:?$/.test(c));

          if (parsedRows.length >= 2 && isSeparatorRow(parsedRows[1])) {
            const headers = parsedRows[0];
            const dataRows = parsedRows.slice(2);
            blocks.push({ type: "table", headers, rows: dataRows });
            i = j;
            continue;
          } else if (parsedRows.length >= 2 && !isSeparatorRow(parsedRows[0])) {
            const headers = parsedRows[0];
            const dataRows = parsedRows.slice(1);
            blocks.push({ type: "table", headers, rows: dataRows });
            i = j;
            continue;
          }
        }
      }

      blocks.push({ type: "line", text: rawLines[i], index: i });
      i++;
    }

    return blocks;
  };

  /**
   * Renders Damage Level cell with colored circular dot matching SOC severity standards
   */
  const renderDamageLevel = (cell: string) => {
    const plain = cell.replace(/\*\*/g, "").trim();
    const lower = plain.toLowerCase();

    let dotColor = "bg-slate-400";
    let textColor = "text-[var(--sd-text)]";

    if (lower.includes("critical")) {
      dotColor = "bg-[#dc2626]";
      textColor = "text-[#dc2626]";
    } else if (lower.includes("high")) {
      dotColor = "bg-[#ea580c]";
      textColor = "text-[#ea580c]";
    } else if (lower.includes("medium") && !lower.includes("low-to-medium")) {
      dotColor = "bg-[#d97706]";
      textColor = "text-[#d97706]";
    } else if (lower.includes("low-to-medium")) {
      dotColor = "bg-[#2563eb]";
      textColor = "text-[#2563eb]";
    } else if (lower.includes("low")) {
      dotColor = "bg-[#059669]";
      textColor = "text-[#059669]";
    }

    return (
      <div className="inline-flex items-center gap-1.5 whitespace-nowrap">
        <span className={`inline-block h-2 w-2 rounded-full shrink-0 ${dotColor}`} />
        <span className={`font-bold text-xs ${textColor}`}>{plain}</span>
      </div>
    );
  };

  /**
   * Tokenizer to render bolding, inline code, italics, severity badges, and incident/CVE chips.
   */
  const renderTokens = (text: string) => {
    const tokenRegex =
      /(\*\*.*?\*\*|`.*?`|\*[^*\n]+\*|\b(?:CRITICAL|HIGH|MEDIUM|LOW-TO-MEDIUM|LOW|RESOLVED|INVESTIGATING|OPEN|CLOSED)\b|\bCVE-\d{4}-\d{4,7}\b|\bINC-\d+\b)/gi;

    const parts = text.split(tokenRegex);

    return parts.map((part, i) => {
      if (!part) return null;

      // Bold text: **text**
      if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
        return (
          <strong key={i} className="font-bold text-[var(--sd-pine)]">
            {part.slice(2, -2)}
          </strong>
        );
      }

      // Inline code: `code`
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

      // Italics: *text*
      if (part.startsWith("*") && part.endsWith("*") && !part.startsWith("**") && part.length >= 3) {
        return (
          <em key={i} className="italic text-[var(--sd-pine)]">
            {part.slice(1, -1)}
          </em>
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
      if (upper === "LOW-TO-MEDIUM") {
        return (
          <span
            key={i}
            className="inline-flex items-center gap-1 mx-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-blue-50 text-blue-700 border border-blue-200 font-mono"
          >
            <Info className="h-3 w-3" />
            LOW-TO-MEDIUM
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
        <div key={index} className="my-1.5 flex items-start gap-2.5 text-xs leading-relaxed text-[var(--sd-text)]">
          <span className="flex h-4.5 w-4.5 shrink-0 items-center justify-center rounded-full bg-[var(--sd-pine)] text-[10px] font-bold text-[#f7f4ed] font-mono mt-0.5 shadow-xs">
            {numberedMatch[1]}
          </span>
          <div className="flex-1 leading-relaxed">{renderTokens(numberedMatch[2])}</div>
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

  const blocks = parseBlocks(content);

  return (
    <div className="space-y-0.5">
      {blocks.map((block, bIdx) => {
        if (block.type === "table") {
          return (
            <div
              key={bIdx}
              className="my-3 overflow-hidden rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel)] shadow-xs"
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-[var(--sd-panel-raised)] border-b border-[var(--sd-border)]">
                    <tr>
                      {block.headers.map((h, hIdx) => (
                        <th
                          key={hIdx}
                          className={`py-2.5 px-3 font-semibold text-[var(--sd-text)] tracking-wider text-[11px] ${
                            hIdx === 0
                              ? "w-[125px] min-w-[110px]"
                              : hIdx === 1
                              ? "w-[135px] min-w-[125px]"
                              : ""
                          }`}
                        >
                          {h.replace(/\*\*/g, "").trim()}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--sd-border-subtle)]">
                    {block.rows.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-[var(--sd-panel-hover)] transition-colors">
                        {row.map((cell, cIdx) => (
                          <td
                            key={cIdx}
                            className={`py-2.5 px-3 align-top leading-relaxed ${
                              cIdx === 0
                                ? "font-semibold text-[var(--sd-pine)] text-xs whitespace-nowrap"
                                : cIdx === 1
                                ? "text-xs font-semibold whitespace-nowrap"
                                : "text-xs text-[var(--sd-text)]"
                            }`}
                          >
                            {cIdx === 1 ? renderDamageLevel(cell) : renderTokens(cell)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          );
        }

        return renderFormattedLine(block.text, block.index);
      })}
    </div>
  );
}

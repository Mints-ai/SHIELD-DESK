"use client";

import React, { useState } from "react";
import {
  Copy,
  Check,
  Terminal,
  Info,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  ExternalLink,
  Hash,
} from "lucide-react";

interface DocMarkdownRendererProps {
  content: string;
}

export interface HeadingItem {
  id: string;
  text: string;
  level: number;
}

/**
 * Extracts H2 and H3 headings from markdown content for table of contents
 */
export function extractHeadings(markdown: string): HeadingItem[] {
  const lines = markdown.split("\n");
  const headings: HeadingItem[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("## ")) {
      const text = trimmed.replace(/^##\s+/, "").replace(/[*_`]/g, "");
      const id = slugify(text);
      headings.push({ id, text, level: 2 });
    } else if (trimmed.startsWith("### ")) {
      const text = trimmed.replace(/^###\s+/, "").replace(/[*_`]/g, "");
      const id = slugify(text);
      headings.push({ id, text, level: 3 });
    }
  }

  return headings;
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

export function DocMarkdownRenderer({ content }: DocMarkdownRendererProps) {
  // Parse markdown into high-level AST blocks
  const blocks = React.useMemo(() => parseMarkdownToBlocks(content), [content]);

  return (
    <div className="sd-doc-prose text-[var(--sd-text)] space-y-6 font-sans leading-relaxed">
      {blocks.map((block, idx) => (
        <BlockRenderer key={idx} block={block} />
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Types & Parser
// ─────────────────────────────────────────────────────────────────────────────

type Block =
  | { type: "h1"; text: string; id: string }
  | { type: "h2"; text: string; id: string }
  | { type: "h3"; text: string; id: string }
  | { type: "h4"; text: string; id: string }
  | { type: "paragraph"; text: string }
  | { type: "code"; language: string; code: string }
  | { type: "callout"; variant: "note" | "warning" | "important" | "tip"; title: string; body: string }
  | { type: "table"; headers: string[]; aligns: Array<"left" | "center" | "right">; rows: string[][] }
  | { type: "ul"; items: string[] }
  | { type: "ol"; items: string[] }
  | { type: "hr" };

function parseMarkdownToBlocks(md: string): Block[] {
  const lines = md.split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // 1. Empty lines
    if (!trimmed) {
      i++;
      continue;
    }

    // 2. Horizontal Rule
    if (trimmed === "---" || trimmed === "***" || trimmed === "___") {
      blocks.push({ type: "hr" });
      i++;
      continue;
    }

    // 3. Fenced Code Block
    if (trimmed.startsWith("```")) {
      const language = trimmed.slice(3).trim().toLowerCase() || "bash";
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      blocks.push({
        type: "code",
        language,
        code: codeLines.join("\n"),
      });
      continue;
    }

    // 4. Headings
    if (trimmed.startsWith("# ")) {
      const text = trimmed.replace(/^#\s+/, "");
      blocks.push({ type: "h1", text, id: slugify(text) });
      i++;
      continue;
    }
    if (trimmed.startsWith("## ")) {
      const text = trimmed.replace(/^##\s+/, "");
      blocks.push({ type: "h2", text, id: slugify(text) });
      i++;
      continue;
    }
    if (trimmed.startsWith("### ")) {
      const text = trimmed.replace(/^###\s+/, "");
      blocks.push({ type: "h3", text, id: slugify(text) });
      i++;
      continue;
    }
    if (trimmed.startsWith("#### ")) {
      const text = trimmed.replace(/^####\s+/, "");
      blocks.push({ type: "h4", text, id: slugify(text) });
      i++;
      continue;
    }

    // 5. Callouts / Blockquotes
    if (trimmed.startsWith(">")) {
      const calloutLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        calloutLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i++;
      }
      const fullCallout = calloutLines.join("\n").trim();
      let variant: "note" | "warning" | "important" | "tip" = "note";
      let title = "Note";
      let body = fullCallout;

      if (/^\*\*(Note|Notice|Information)[^*]*\*\*:/i.test(fullCallout)) {
        variant = "note";
        const match = fullCallout.match(/^\*\*([^*]+)\*\*:\s*([\s\S]*)/);
        if (match) {
          title = match[1];
          body = match[2];
        }
      } else if (/^\*\*(Warning|Alert|Caution)[^*]*\*\*:/i.test(fullCallout)) {
        variant = "warning";
        const match = fullCallout.match(/^\*\*([^*]+)\*\*:\s*([\s\S]*)/);
        if (match) {
          title = match[1];
          body = match[2];
        }
      } else if (/^\*\*(Important|Critical|Required)[^*]*\*\*:/i.test(fullCallout)) {
        variant = "important";
        const match = fullCallout.match(/^\*\*([^*]+)\*\*:\s*([\s\S]*)/);
        if (match) {
          title = match[1];
          body = match[2];
        }
      } else if (/^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/i.test(fullCallout)) {
        const match = fullCallout.match(/^\[!(\w+)\]\s*([\s\S]*)/);
        if (match) {
          const tag = match[1].toUpperCase();
          if (tag === "WARNING" || tag === "CAUTION") variant = "warning";
          else if (tag === "IMPORTANT") variant = "important";
          else if (tag === "TIP") variant = "tip";
          else variant = "note";
          title = match[1];
          body = match[2];
        }
      }

      blocks.push({
        type: "callout",
        variant,
        title,
        body,
      });
      continue;
    }

    // 6. Tables (Markdown pipe tables)
    if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      const tableLines: string[] = [];
      while (
        i < lines.length &&
        lines[i].trim().startsWith("|") &&
        lines[i].trim().endsWith("|")
      ) {
        tableLines.push(lines[i].trim());
        i++;
      }

      if (tableLines.length >= 2) {
        const parseRow = (rowStr: string) =>
          rowStr
            .split("|")
            .slice(1, -1)
            .map((c) => c.trim());

        const headers = parseRow(tableLines[0]);
        const separator = parseRow(tableLines[1]);

        const aligns: Array<"left" | "center" | "right"> = separator.map((sep) => {
          const starts = sep.startsWith(":");
          const ends = sep.endsWith(":");
          if (starts && ends) return "center";
          if (ends) return "right";
          return "left";
        });

        const rows: string[][] = [];
        for (let r = 2; r < tableLines.length; r++) {
          rows.push(parseRow(tableLines[r]));
        }

        blocks.push({
          type: "table",
          headers,
          aligns,
          rows,
        });
        continue;
      }
    }

    // 7. Ordered Lists (e.g., 1. Item)
    if (/^\d+\.\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ""));
        i++;
      }
      blocks.push({ type: "ol", items });
      continue;
    }

    // 8. Unordered Lists (e.g., - Item or * Item)
    if (/^[-*]\s+/.test(trimmed)) {
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*]\s+/, ""));
        i++;
      }
      blocks.push({ type: "ul", items });
      continue;
    }

    // 9. Standard Paragraph (accumulate lines until blank or next block type)
    const pLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trim().startsWith("#") &&
      !lines[i].trim().startsWith("```") &&
      !lines[i].trim().startsWith(">") &&
      !(lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) &&
      !/^[-*]\s+/.test(lines[i].trim()) &&
      !/^\d+\.\s+/.test(lines[i].trim()) &&
      lines[i].trim() !== "---"
    ) {
      pLines.push(lines[i].trim());
      i++;
    }

    if (pLines.length > 0) {
      blocks.push({
        type: "paragraph",
        text: pLines.join(" "),
      });
    }
  }

  return blocks;
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Renderers
// ─────────────────────────────────────────────────────────────────────────────

function BlockRenderer({ block }: { block: Block }) {
  switch (block.type) {
    case "h1":
      return (
        <div id={block.id} className="pt-2 pb-4 border-b border-[var(--sd-border)] scroll-mt-28">
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[var(--sd-sand)] flex items-center gap-2 group">
            <span>{renderInlineText(block.text)}</span>
            <a
              href={`#${block.id}`}
              className="opacity-0 group-hover:opacity-100 text-[var(--sd-wheat)]/60 hover:text-[var(--sd-wheat)] transition p-1"
              aria-label="Link to section"
            >
              <Hash className="w-4 h-4" />
            </a>
          </h1>
        </div>
      );

    case "h2":
      return (
        <div id={block.id} className="pt-6 pb-2 border-b border-[var(--sd-border-subtle)] scroll-mt-24">
          <h2 className="text-xl sm:text-2xl font-semibold tracking-tight text-[var(--sd-sand)] flex items-center gap-2 group">
            <span className="w-2 h-2 rounded-full bg-[var(--sd-emerald)] ring-4 ring-[var(--sd-emerald)]/20" />
            <span>{renderInlineText(block.text)}</span>
            <a
              href={`#${block.id}`}
              className="opacity-0 group-hover:opacity-100 text-[var(--sd-wheat)]/60 hover:text-[var(--sd-wheat)] transition p-1"
              aria-label="Link to section"
            >
              <Hash className="w-4 h-4" />
            </a>
          </h2>
        </div>
      );

    case "h3":
      return (
        <div id={block.id} className="pt-4 pb-1 scroll-mt-24">
          <h3 className="text-lg font-semibold text-[var(--sd-wheat)] flex items-center gap-2">
            <span>{renderInlineText(block.text)}</span>
          </h3>
        </div>
      );

    case "h4":
      return (
        <div id={block.id} className="pt-2 scroll-mt-24">
          <h4 className="text-base font-semibold text-[var(--sd-text-muted)]">
            {renderInlineText(block.text)}
          </h4>
        </div>
      );

    case "paragraph":
      return (
        <p className="text-sm sm:text-base text-[var(--sd-text)] leading-relaxed">
          {renderInlineText(block.text)}
        </p>
      );

    case "code":
      return <CodeBlock language={block.language} code={block.code} />;

    case "callout":
      return (
        <CalloutCard
          variant={block.variant}
          title={block.title}
          body={block.body}
        />
      );

    case "table":
      return (
        <div className="my-6 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-panel)] overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border-collapse">
              <thead>
                <tr className="border-b border-[var(--sd-border)] bg-[var(--sd-panel-raised)]">
                  {block.headers.map((h, i) => (
                    <th
                      key={i}
                      className={`px-4 py-3.5 text-xs font-mono font-semibold uppercase tracking-wider text-[var(--sd-wheat)] ${
                        block.aligns[i] === "center"
                          ? "text-center"
                          : block.aligns[i] === "right"
                          ? "text-right"
                          : "text-left"
                      }`}
                    >
                      {renderInlineText(h)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--sd-border-subtle)] font-sans">
                {block.rows.map((row, rIdx) => (
                  <tr
                    key={rIdx}
                    className="hover:bg-[var(--sd-panel-hover)]/40 transition-colors"
                  >
                    {row.map((cell, cIdx) => (
                      <td
                        key={cIdx}
                        className={`px-4 py-3 text-sm text-[var(--sd-text)] leading-relaxed ${
                          block.aligns[cIdx] === "center"
                            ? "text-center"
                            : block.aligns[cIdx] === "right"
                            ? "text-right"
                            : "text-left"
                        }`}
                      >
                        {renderInlineText(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      );

    case "ol":
      return (
        <ol className="my-4 space-y-2.5 pl-1">
          {block.items.map((item, idx) => (
            <li key={idx} className="flex items-start gap-3 text-sm sm:text-base text-[var(--sd-text)]">
              <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-lg bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-xs font-mono font-bold text-[var(--sd-wheat)] mt-0.5">
                {String(idx + 1).padStart(2, "0")}
              </span>
              <div className="flex-1 leading-relaxed">
                {renderInlineText(item)}
              </div>
            </li>
          ))}
        </ol>
      );

    case "ul":
      return (
        <ul className="my-4 space-y-2 pl-1">
          {block.items.map((item, idx) => (
            <li key={idx} className="flex items-start gap-3 text-sm sm:text-base text-[var(--sd-text)]">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--sd-primary-hover)] flex-shrink-0 mt-2 ring-2 ring-[var(--sd-primary)]/30" />
              <div className="flex-1 leading-relaxed">
                {renderInlineText(item)}
              </div>
            </li>
          ))}
        </ul>
      );

    case "hr":
      return (
        <div className="my-8 h-px bg-gradient-to-r from-transparent via-[var(--sd-border)] to-transparent" />
      );

    default:
      return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Code Block with Copy & Terminal Chrome
// ─────────────────────────────────────────────────────────────────────────────

function CodeBlock({ language, code }: { language: string; code: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayLang = language ? language.toUpperCase() : "TERMINAL";

  return (
    <div className="my-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-bg)] overflow-hidden shadow-md">
      {/* Terminal Bar */}
      <div className="px-4 py-2.5 bg-[var(--sd-surface)] border-b border-[var(--sd-border)] flex items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          {/* Mac/Linux terminal dots */}
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <span className="ml-2 font-mono text-[11px] font-semibold tracking-wider text-[var(--sd-wheat)] px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)]">
            {displayLang}
          </span>
        </div>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
          title="Copy to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" />
              <span className="text-[var(--sd-success)] font-medium">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code Text */}
      <div className="p-4 sm:p-5 overflow-x-auto">
        <pre className="font-mono text-xs sm:text-sm text-[var(--sd-sand)] leading-relaxed selection:bg-[var(--sd-primary)] selection:text-white">
          <code>{code}</code>
        </pre>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Callout / Alert Cards
// ─────────────────────────────────────────────────────────────────────────────

function CalloutCard({
  variant,
  title,
  body,
}: {
  variant: "note" | "warning" | "important" | "tip";
  title: string;
  body: string;
}) {
  let borderClass = "border-[var(--sd-border)]";
  let bgClass = "bg-[var(--sd-panel)]";
  let iconColor = "text-[var(--sd-wheat)]";
  let Icon = Info;

  if (variant === "warning") {
    borderClass = "border-amber-500/40";
    bgClass = "bg-amber-950/20";
    iconColor = "text-amber-400";
    Icon = AlertTriangle;
  } else if (variant === "important") {
    borderClass = "border-[var(--sd-primary)]";
    bgClass = "bg-[var(--sd-primary-subtle)]";
    iconColor = "text-[var(--sd-primary-hover)]";
    Icon = ShieldAlert;
  } else if (variant === "tip") {
    borderClass = "border-emerald-500/40";
    bgClass = "bg-emerald-950/20";
    iconColor = "text-emerald-400";
    Icon = CheckCircle2;
  }

  return (
    <div
      className={`my-5 p-4 sm:p-5 rounded-2xl border ${borderClass} ${bgClass} shadow-xs relative overflow-hidden`}
    >
      <div className="flex items-start gap-3.5">
        <div className={`p-1.5 rounded-xl bg-black/40 border border-[var(--sd-border-subtle)] ${iconColor} mt-0.5 flex-shrink-0`}>
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 text-sm space-y-1">
          <div className="font-semibold text-[var(--sd-sand)] tracking-wide">
            {title}
          </div>
          <div className="text-[var(--sd-text)] leading-relaxed">
            {renderInlineText(body)}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Inline Text Formatter (Bold, Code, Links)
// ─────────────────────────────────────────────────────────────────────────────

function renderInlineText(text: string): React.ReactNode {
  // Regex token parser for **bold**, `code`, [text](url)
  const regex = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
  const parts = text.split(regex);

  return parts.map((part, index) => {
    if (!part) return null;

    // **Bold**
    if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
      return (
        <strong key={index} className="font-semibold text-[var(--sd-sand)]">
          {part.slice(2, -2)}
        </strong>
      );
    }

    // `Inline Code`
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      return (
        <code
          key={index}
          className="px-1.5 py-0.5 rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-wheat)] font-mono text-xs sm:text-[13px] mx-0.5"
        >
          {part.slice(1, -1)}
        </code>
      );
    }

    // [Link](url)
    if (part.startsWith("[") && part.includes("](") && part.endsWith(")")) {
      const match = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      if (match) {
        const linkText = match[1];
        const linkUrl = match[2];
        const isExternal = linkUrl.startsWith("http");

        return (
          <a
            key={index}
            href={linkUrl}
            target={isExternal ? "_blank" : undefined}
            rel={isExternal ? "noopener noreferrer" : undefined}
            className="text-[var(--sd-wheat)] hover:underline inline-flex items-center gap-1 font-medium transition"
          >
            <span>{linkText}</span>
            {isExternal && <ExternalLink className="w-3 h-3 opacity-70" />}
          </a>
        );
      }
    }

    return <React.Fragment key={index}>{part}</React.Fragment>;
  });
}

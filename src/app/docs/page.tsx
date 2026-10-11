"use client";

import React, { useState, useMemo, useEffect, useRef, Suspense } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import {
  BookOpen,
  Search,
  FileText,
  Download,
  Copy,
  Check,
  ExternalLink,
  Shield,
  Terminal,
  ArrowRight,
  ArrowLeft,
  Lock,
  Server,
  Activity,
  FileCheck2,
  Printer,
  Sparkles,
  X,
  Tag,
  ChevronRight,
  ChevronDown,
  Clock,
  Layers,
  HelpCircle,
  FolderDown,
  Menu,
  Eye,
  Code2,
  Share2,
  Compass,
  ThumbsUp,
  ThumbsDown,
  Bookmark,
  ShieldCheck,
  Cpu,
  Workflow,
  Radio,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import {
  getAllCustomerDocs,
  getCustomerDocById,
  generateDocumentationBundle,
  type CustomerDoc,
  type DocCategory,
} from "@/lib/docs/customerDocs";
import {
  DocMarkdownRenderer,
  extractHeadings,
  type HeadingItem,
} from "@/components/docs/DocMarkdownRenderer";

// Category Icons Mapping
const CATEGORY_META: Record<
  DocCategory,
  { icon: React.ComponentType<{ className?: string }>; color: string; badge: string }
> = {
  "Getting Started": {
    icon: Compass,
    color: "text-[var(--sd-wheat)]",
    badge: "border-[var(--sd-wheat)]/40 bg-[var(--sd-wheat)]/10 text-[var(--sd-wheat)]",
  },
  "SOC Operations": {
    icon: Workflow,
    color: "text-emerald-400",
    badge: "border-emerald-500/40 bg-emerald-950/30 text-emerald-300",
  },
  "Agent & Integrations": {
    icon: Cpu,
    color: "text-cyan-400",
    badge: "border-cyan-500/40 bg-cyan-950/30 text-cyan-300",
  },
  "Trust & Compliance": {
    icon: ShieldCheck,
    color: "text-amber-400",
    badge: "border-amber-500/40 bg-amber-950/30 text-amber-300",
  },
  Support: {
    icon: HelpCircle,
    color: "text-purple-400",
    badge: "border-purple-500/40 bg-purple-950/30 text-purple-300",
  },
};

export default function CustomerDocsPage() {
  return (
    <Suspense fallback={<DocsLoadingFallback />}>
      <CustomerDocsContent />
    </Suspense>
  );
}

function DocsLoadingFallback() {
  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] flex items-center justify-center">
      <div className="flex items-center gap-3 text-[var(--sd-wheat)]">
        <div className="w-5 h-5 border-2 border-[var(--sd-primary)] border-t-transparent rounded-full animate-spin" />
        <span className="font-mono text-sm">Loading Documentation Portal...</span>
      </div>
    </div>
  );
}

function CustomerDocsContent() {
  const allDocs = useMemo(() => getAllCustomerDocs(), []);
  const searchParams = useSearchParams();
  const router = useRouter();

  // Active doc state from URL or fallback to first doc
  const initialDocId = searchParams.get("doc") || allDocs[0]?.id || "getting-started";
  const [activeDocId, setActiveDocId] = useState<string>(initialDocId);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [rawViewMode, setRawViewMode] = useState(false);
  const [copiedDoc, setCopiedDoc] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [feedbackGiven, setFeedbackGiven] = useState<"yes" | "no" | null>(null);
  const [collapsedCategories, setCollapsedCategories] = useState<Record<string, boolean>>({});
  const [downloadingBundle, setDownloadingBundle] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);

  // Sync state if URL changes
  useEffect(() => {
    const docFromUrl = searchParams.get("doc");
    if (docFromUrl && docFromUrl !== activeDocId) {
      const found = allDocs.find((d) => d.id === docFromUrl);
      if (found) setActiveDocId(docFromUrl);
    }
  }, [searchParams, allDocs, activeDocId]);

  // Active doc object
  const activeDoc = useMemo(() => {
    return allDocs.find((d) => d.id === activeDocId) || allDocs[0];
  }, [allDocs, activeDocId]);

  // Headings for Table of Contents
  const headings = useMemo(() => {
    if (!activeDoc) return [];
    return extractHeadings(activeDoc.content);
  }, [activeDoc]);

  // Group docs by category
  const categoriesList: DocCategory[] = [
    "Getting Started",
    "SOC Operations",
    "Agent & Integrations",
    "Trust & Compliance",
    "Support",
  ];

  const groupedDocs = useMemo(() => {
    const groups: Record<DocCategory, CustomerDoc[]> = {
      "Getting Started": [],
      "SOC Operations": [],
      "Agent & Integrations": [],
      "Trust & Compliance": [],
      Support: [],
    };

    allDocs.forEach((doc) => {
      if (groups[doc.category]) {
        groups[doc.category].push(doc);
      }
    });

    return groups;
  }, [allDocs]);

  // Search Results across all documents
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = searchQuery.toLowerCase().trim();

    return allDocs
      .map((doc) => {
        let score = 0;
        const titleMatch = doc.title.toLowerCase().includes(q);
        const tagMatch = doc.tags.some((t) => t.toLowerCase().includes(q));
        const summaryMatch = doc.summary.toLowerCase().includes(q);
        const contentMatch = doc.content.toLowerCase().includes(q);

        if (titleMatch) score += 10;
        if (tagMatch) score += 6;
        if (summaryMatch) score += 4;
        if (contentMatch) score += 2;

        return { doc, score };
      })
      .filter((r) => r.score > 0)
      .sort((a, b) => b.score - a.score)
      .map((r) => r.doc);
  }, [allDocs, searchQuery]);

  // Next / Previous Doc Navigation
  const { prevDoc, nextDoc } = useMemo(() => {
    const currentIndex = allDocs.findIndex((d) => d.id === activeDocId);
    return {
      prevDoc: currentIndex > 0 ? allDocs[currentIndex - 1] : null,
      nextDoc: currentIndex < allDocs.length - 1 ? allDocs[currentIndex + 1] : null,
    };
  }, [allDocs, activeDocId]);

  // Switch doc handler
  const selectDocument = (docId: string) => {
    setActiveDocId(docId);
    setRawViewMode(false);
    setFeedbackGiven(null);
    setMobileSidebarOpen(false);
    setIsSearchOpen(false);
    setSearchQuery("");

    // Update URL shallowly
    router.replace(`/docs?doc=${docId}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Toggle Category Fold
  const toggleCategory = (cat: string) => {
    setCollapsedCategories((prev) => ({
      ...prev,
      [cat]: !prev[cat],
    }));
  };

  // Keyboard shortcut (⌘K or / to focus search)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsSearchOpen(true);
      } else if (e.key === "/" && !["INPUT", "TEXTAREA"].includes((e.target as HTMLElement).tagName)) {
        e.preventDefault();
        setIsSearchOpen(true);
      } else if (e.key === "Escape") {
        setIsSearchOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Copy Markdown of active doc
  const handleCopyDocMarkdown = () => {
    if (!activeDoc) return;
    navigator.clipboard.writeText(activeDoc.content);
    setCopiedDoc(true);
    setTimeout(() => setCopiedDoc(false), 2500);
  };

  // Copy Direct Link to active doc
  const handleCopyLink = () => {
    if (typeof window === "undefined") return;
    const url = `${window.location.origin}/docs?doc=${activeDoc.id}`;
    navigator.clipboard.writeText(url);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2500);
  };

  // Download single doc as .md file
  const handleDownloadDoc = () => {
    if (!activeDoc) return;
    const blob = new Blob([activeDoc.content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = activeDoc.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Download all docs unified manual
  const handleDownloadBundle = () => {
    setDownloadingBundle(true);
    try {
      const bundle = generateDocumentationBundle();
      const blob = new Blob([bundle], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "ShieldDesk-Customer-Documentation-Manual.md";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setTimeout(() => setDownloadingBundle(false), 1500);
    }
  };

  const activeCategoryMeta = activeDoc ? CATEGORY_META[activeDoc.category] : CATEGORY_META["Getting Started"];
  const CategoryIcon = activeCategoryMeta.icon;

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col selection:bg-[var(--sd-primary)] selection:text-white">
      {/* Top Application Bar */}
      <TopNavBar />

      {/* Sub-Header Portal Bar */}
      <header className="sticky top-16 z-30 border-b border-[var(--sd-border)] bg-[var(--sd-bg-alt)]/90 backdrop-blur-md px-4 sm:px-6 lg:px-8 py-2.5 transition-all">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          {/* Mobile Menu & Breadcrumbs */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileSidebarOpen(!mobileSidebarOpen)}
              className="lg:hidden p-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-wheat)] transition cursor-pointer"
              aria-label="Toggle Document Navigation"
            >
              <Menu className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 text-xs font-mono">
              <Link
                href="/"
                className="text-[var(--sd-text-dim)] hover:text-[var(--sd-wheat)] transition flex items-center gap-1"
              >
                <Shield className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                <span>Console</span>
              </Link>
              <span className="text-[var(--sd-text-dim)]">/</span>
              <span className="text-[var(--sd-wheat)] font-semibold flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5" />
                Customer Documentation
              </span>
            </div>
          </div>

          {/* Quick Search Trigger & Export Tools */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Quick Search Button */}
            <button
              onClick={() => setIsSearchOpen(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] hover:border-[var(--sd-border-strong)] text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer shadow-xs"
            >
              <Search className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
              <span className="hidden sm:inline">Search 23 guides...</span>
              <span className="sm:hidden">Search</span>
              <kbd className="hidden md:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono text-[var(--sd-text-dim)] bg-[var(--sd-bg)] rounded border border-[var(--sd-border-subtle)]">
                ⌘K
              </kbd>
            </button>

            {/* Export Manual Bundle */}
            <button
              onClick={handleDownloadBundle}
              disabled={downloadingBundle}
              className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-wheat)] transition cursor-pointer shadow-xs"
              title="Download all customer guides in a single markdown file"
            >
              <FolderDown className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
              <span className="hidden sm:inline">
                {downloadingBundle ? "Exporting..." : "Take All Docs (.md)"}
              </span>
              <span className="sm:hidden">Export</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Documentation Workspace (3 Columns: Left Nav, Center Reading View, Right Table-of-Contents) */}
      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 flex gap-8 items-start">
        {/* ─────────────────────────────────────────────────────────────────── */}
        {/* Column 1: Left Navigation Sidebar */}
        {/* ─────────────────────────────────────────────────────────────────── */}
        <aside
          className={`
            fixed lg:sticky top-28 z-40 lg:z-10
            w-72 sm:w-80 lg:w-72 max-h-[calc(100vh-8rem)]
            bg-[var(--sd-bg-alt)] lg:bg-transparent
            border lg:border-none border-[var(--sd-border)] rounded-2xl lg:rounded-none
            p-4 lg:p-0 shadow-2xl lg:shadow-none
            overflow-y-auto flex flex-col gap-6
            transition-all duration-300
            ${
              mobileSidebarOpen
                ? "left-4 right-4 sm:right-auto bottom-6"
                : "hidden lg:flex"
            }
          `}
        >
          {/* Mobile Sidebar Close */}
          <div className="flex lg:hidden items-center justify-between pb-3 border-b border-[var(--sd-border)]">
            <span className="text-xs font-mono font-semibold text-[var(--sd-wheat)] uppercase tracking-wider">
              Document Directory
            </span>
            <button
              onClick={() => setMobileSidebarOpen(false)}
              className="p-1 rounded-lg text-[var(--sd-text-dim)] hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Quick Filter in Sidebar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[var(--sd-text-dim)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter topics..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs text-[var(--sd-text)] placeholder-[var(--sd-text-dim)] focus:outline-hidden focus:border-[var(--sd-border-strong)] transition"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--sd-text-dim)] hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Category Tree Navigation */}
          <nav className="space-y-6">
            {categoriesList.map((category) => {
              const docsInCategory = groupedDocs[category].filter((doc) => {
                if (!searchQuery.trim()) return true;
                const q = searchQuery.toLowerCase();
                return (
                  doc.title.toLowerCase().includes(q) ||
                  doc.summary.toLowerCase().includes(q) ||
                  doc.tags.some((t) => t.toLowerCase().includes(q))
                );
              });

              if (docsInCategory.length === 0) return null;

              const isCollapsed = collapsedCategories[category];
              const CatMeta = CATEGORY_META[category];
              const IconComp = CatMeta.icon;

              return (
                <div key={category} className="space-y-1.5">
                  {/* Category Header */}
                  <button
                    onClick={() => toggleCategory(category)}
                    className="w-full flex items-center justify-between py-1 px-1.5 text-xs font-mono uppercase tracking-wider font-semibold text-[var(--sd-text-dim)] hover:text-[var(--sd-wheat)] transition cursor-pointer group"
                  >
                    <div className="flex items-center gap-2">
                      <IconComp className={`w-3.5 h-3.5 ${CatMeta.color}`} />
                      <span>{category}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-text-dim)] font-mono">
                        {docsInCategory.length}
                      </span>
                    </div>
                    {isCollapsed ? (
                      <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition" />
                    ) : (
                      <ChevronDown className="w-3.5 h-3.5 group-hover:translate-y-0.5 transition" />
                    )}
                  </button>

                  {/* Documents List */}
                  {!isCollapsed && (
                    <ul className="space-y-1 pl-2 border-l border-[var(--sd-border-subtle)] ml-2">
                      {docsInCategory.map((doc) => {
                        const isActive = doc.id === activeDocId;
                        return (
                          <li key={doc.id}>
                            <button
                              onClick={() => selectDocument(doc.id)}
                              className={`w-full text-left px-2.5 py-2 rounded-xl text-xs font-medium transition flex items-center justify-between gap-2 group cursor-pointer ${
                                isActive
                                  ? "bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] font-semibold border border-[var(--sd-border)] shadow-xs"
                                  : "text-[var(--sd-text-muted)] hover:text-[var(--sd-sand)] hover:bg-[var(--sd-panel-raised)]"
                              }`}
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <span
                                  className={`w-1.5 h-1.5 rounded-full flex-shrink-0 transition ${
                                    isActive
                                      ? "bg-[var(--sd-primary-hover)] ring-2 ring-[var(--sd-primary)]/40"
                                      : "bg-transparent group-hover:bg-[var(--sd-border-strong)]"
                                  }`}
                                />
                                <span className="truncate">{doc.title}</span>
                              </div>
                              <span className="text-[10px] font-mono text-[var(--sd-text-dim)] flex-shrink-0">
                                {doc.readTime.replace(" read", "")}
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              );
            })}
          </nav>

          {/* Quick Resource Box */}
          <div className="mt-auto pt-4 border-t border-[var(--sd-border-subtle)] space-y-2">
            <Link
              href="/status"
              className="flex items-center justify-between p-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-text-muted)] hover:text-white transition group"
            >
              <div className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                <span>System Status</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </Link>

            <a
              href="/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between p-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-text-muted)] hover:text-white transition group"
            >
              <div className="flex items-center gap-2">
                <Code2 className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                <span>Docs REST API</span>
              </div>
              <ExternalLink className="w-3 h-3 text-[var(--sd-text-dim)] group-hover:text-[var(--sd-wheat)] transition" />
            </a>
          </div>
        </aside>

        {/* Backdrop for Mobile Sidebar */}
        {mobileSidebarOpen && (
          <div
            onClick={() => setMobileSidebarOpen(false)}
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-xs lg:hidden"
          />
        )}

        {/* ─────────────────────────────────────────────────────────────────── */}
        {/* Column 2: Center Reading Workspace */}
        {/* ─────────────────────────────────────────────────────────────────── */}
        <main className="flex-1 min-w-0 max-w-4xl space-y-8">
          {/* Article Header & Control Bar */}
          <div className="p-6 sm:p-8 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md space-y-6 relative overflow-hidden">
            {/* Ambient Background Accent */}
            <div className="absolute top-0 right-0 w-72 h-72 bg-[var(--sd-primary)]/10 rounded-full blur-3xl pointer-events-none" />

            {/* Breadcrumb & Metadata Badge Row */}
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center gap-2">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border ${activeCategoryMeta.badge} flex items-center gap-1.5`}
                >
                  <CategoryIcon className="w-3 h-3" />
                  {activeDoc.category}
                </span>
                <span className="text-[var(--sd-text-dim)]">•</span>
                <span className="text-[var(--sd-text-muted)] flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                  {activeDoc.readTime}
                </span>
                <span className="text-[var(--sd-text-dim)]">•</span>
                <span className="text-[var(--sd-text-dim)]">
                  Reviewed: {activeDoc.lastUpdated}
                </span>
              </div>

              {/* View Mode Toggle: Formatted Reader vs Raw Markdown */}
              <div className="flex items-center gap-1 p-1 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border-subtle)]">
                <button
                  onClick={() => setRawViewMode(false)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono transition cursor-pointer ${
                    !rawViewMode
                      ? "bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] font-semibold shadow-xs"
                      : "text-[var(--sd-text-dim)] hover:text-white"
                  }`}
                  title="Formatted Reading Experience"
                >
                  <Eye className="w-3 h-3 text-emerald-400" />
                  <span>Reader</span>
                </button>
                <button
                  onClick={() => setRawViewMode(true)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono transition cursor-pointer ${
                    rawViewMode
                      ? "bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] font-semibold shadow-xs"
                      : "text-[var(--sd-text-dim)] hover:text-white"
                  }`}
                  title="View Raw Markdown Source"
                >
                  <Code2 className="w-3 h-3 text-[var(--sd-wheat)]" />
                  <span>Raw .md</span>
                </button>
              </div>
            </div>

            {/* Document Title & Executive Summary */}
            <div className="space-y-3">
              <h1 className="text-2xl sm:text-3xl md:text-4xl font-extrabold tracking-tight text-[var(--sd-sand)] leading-tight">
                {activeDoc.title}
              </h1>
              <p className="text-base sm:text-lg text-[var(--sd-text-muted)] leading-relaxed font-sans">
                {activeDoc.summary}
              </p>
            </div>

            {/* Tag Pills */}
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[var(--sd-border-subtle)]">
              <span className="text-xs font-mono text-[var(--sd-text-dim)] flex items-center gap-1 mr-1">
                <Tag className="w-3 h-3" />
                Topics:
              </span>
              {activeDoc.tags.map((tag) => (
                <span
                  key={tag}
                  className="px-2.5 py-0.5 rounded-lg text-xs font-mono bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-sand)] hover:border-[var(--sd-border)] transition"
                >
                  #{tag}
                </span>
              ))}
            </div>

            {/* Document Action Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[var(--sd-border)]">
              <div className="flex items-center gap-2">
                {/* Copy Markdown */}
                <button
                  onClick={handleCopyDocMarkdown}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                  title="Copy Document Markdown"
                >
                  {copiedDoc ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" />
                      <span className="text-[var(--sd-success)] font-medium">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                      <span>Copy Markdown</span>
                    </>
                  )}
                </button>

                {/* Download .md */}
                <button
                  onClick={handleDownloadDoc}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                  title={`Download ${activeDoc.filename}`}
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Download .md</span>
                </button>

                {/* Share Link */}
                <button
                  onClick={handleCopyLink}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                  title="Copy shareable link"
                >
                  {copiedLink ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" />
                      <span className="text-[var(--sd-success)]">Link Copied!</span>
                    </>
                  ) : (
                    <>
                      <Share2 className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                      <span>Share</span>
                    </>
                  )}
                </button>
              </div>

              {/* Print Document */}
              <button
                onClick={() => window.print()}
                className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text-muted)] hover:text-white transition cursor-pointer"
                title="Print or Save as PDF"
              >
                <Printer className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Print / PDF</span>
              </button>
            </div>
          </div>

          {/* Document Content Workspace */}
          <article className="p-6 sm:p-10 rounded-3xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-md min-h-[500px]">
            {rawViewMode ? (
              // RAW MARKDOWN SOURCE VIEW
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-[var(--sd-border)] text-xs font-mono text-[var(--sd-text-dim)]">
                  <span>Raw Source: {activeDoc.filename}</span>
                  <button
                    onClick={handleCopyDocMarkdown}
                    className="text-[var(--sd-wheat)] hover:underline flex items-center gap-1"
                  >
                    <Copy className="w-3 h-3" />
                    Copy All Source
                  </button>
                </div>
                <pre className="p-6 rounded-2xl bg-[var(--sd-bg)] border border-[var(--sd-border)] font-mono text-xs sm:text-sm text-[var(--sd-sand)] leading-relaxed overflow-x-auto whitespace-pre-wrap selection:bg-[var(--sd-primary)] selection:text-white">
                  {activeDoc.content}
                </pre>
              </div>
            ) : (
              // FORMATTED RICH DOCUMENTATION EXPERIENCE
              <DocMarkdownRenderer content={activeDoc.content} />
            )}
          </article>

          {/* Feedback & Helpful Widget */}
          <div className="p-6 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-2 text-[var(--sd-text-muted)]">
              <Sparkles className="w-4 h-4 text-[var(--sd-wheat)]" />
              <span>Was this documentation guide helpful for your team?</span>
            </div>

            <div className="flex items-center gap-2">
              {feedbackGiven ? (
                <span className="text-[var(--sd-success)] font-medium flex items-center gap-1">
                  <Check className="w-3.5 h-3.5" />
                  Thank you for your feedback!
                </span>
              ) : (
                <>
                  <button
                    onClick={() => setFeedbackGiven("yes")}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] transition cursor-pointer"
                  >
                    <ThumbsUp className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Yes, helpful</span>
                  </button>
                  <button
                    onClick={() => setFeedbackGiven("no")}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-sand)] transition cursor-pointer"
                  >
                    <ThumbsDown className="w-3.5 h-3.5 text-amber-400" />
                    <span>Could be better</span>
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Next / Previous Article Navigation */}
          <nav className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            {prevDoc ? (
              <button
                onClick={() => selectDocument(prevDoc.id)}
                className="p-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] hover:bg-[var(--sd-panel-hover)] hover:border-[var(--sd-border-strong)] transition text-left flex items-start gap-3 group cursor-pointer"
              >
                <ArrowLeft className="w-4 h-4 text-[var(--sd-wheat)] group-hover:-translate-x-1 transition mt-1 flex-shrink-0" />
                <div className="min-w-0">
                  <span className="text-[10px] font-mono text-[var(--sd-text-dim)] uppercase tracking-wider">
                    Previous Guide • {prevDoc.category}
                  </span>
                  <div className="text-sm font-semibold text-[var(--sd-sand)] truncate mt-0.5">
                    {prevDoc.title}
                  </div>
                </div>
              </button>
            ) : (
              <div />
            )}

            {nextDoc && (
              <button
                onClick={() => selectDocument(nextDoc.id)}
                className="p-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] hover:bg-[var(--sd-panel-hover)] hover:border-[var(--sd-border-strong)] transition text-right flex items-start justify-end gap-3 group cursor-pointer sm:col-start-2"
              >
                <div className="min-w-0">
                  <span className="text-[10px] font-mono text-[var(--sd-text-dim)] uppercase tracking-wider">
                    Next Guide • {nextDoc.category}
                  </span>
                  <div className="text-sm font-semibold text-[var(--sd-sand)] truncate mt-0.5">
                    {nextDoc.title}
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-[var(--sd-wheat)] group-hover:translate-x-1 transition mt-1 flex-shrink-0" />
              </button>
            )}
          </nav>
        </main>

        {/* ─────────────────────────────────────────────────────────────────── */}
        {/* Column 3: Right Sidebar (On This Page / Table of Contents) */}
        {/* ─────────────────────────────────────────────────────────────────── */}
        <aside className="hidden xl:block w-64 sticky top-28 space-y-6">
          {/* Table of Contents */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-sm space-y-4">
            <div className="text-xs font-mono font-semibold text-[var(--sd-wheat)] uppercase tracking-wider flex items-center gap-2">
              <Bookmark className="w-3.5 h-3.5" />
              <span>On This Page</span>
            </div>

            {headings.length > 0 ? (
              <ul className="space-y-2 text-xs">
                {headings.map((h) => (
                  <li
                    key={h.id}
                    className={h.level === 3 ? "pl-3 border-l border-[var(--sd-border-subtle)]" : ""}
                  >
                    <a
                      href={`#${h.id}`}
                      className="text-[var(--sd-text-muted)] hover:text-[var(--sd-sand)] hover:underline leading-relaxed block transition"
                    >
                      {h.text}
                    </a>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-[var(--sd-text-dim)] font-mono">
                Comprehensive guide overview.
              </p>
            )}
          </div>

          {/* Quick Guide Card */}
          <div className="p-5 rounded-2xl border border-[var(--sd-border)] bg-[var(--sd-surface)] shadow-sm space-y-3 text-xs">
            <div className="text-xs font-mono font-semibold text-[var(--sd-sand)] flex items-center gap-1.5">
              <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Take This Guide</span>
            </div>
            <p className="text-[var(--sd-text-muted)] leading-relaxed">
              Export this runbook directly into your company wiki, Confluence, or internal repository.
            </p>
            <div className="space-y-2 pt-1">
              <button
                onClick={handleCopyDocMarkdown}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-sand)] font-medium transition cursor-pointer"
              >
                <Copy className="w-3 h-3 text-[var(--sd-wheat)]" />
                <span>Copy Markdown Source</span>
              </button>
              <button
                onClick={handleDownloadDoc}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs text-[var(--sd-sand)] font-medium transition cursor-pointer"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                <span>Download {activeDoc.filename}</span>
              </button>
            </div>
          </div>
        </aside>
      </div>

      {/* ─────────────────────────────────────────────────────────────────── */}
      {/* Search Modal / Command Palette */}
      {/* ─────────────────────────────────────────────────────────────────── */}
      {isSearchOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-20 bg-black/80 backdrop-blur-md animate-in fade-in duration-150">
          <div
            className="w-full max-w-2xl bg-[var(--sd-bg-alt)] border border-[var(--sd-border-strong)] rounded-2xl shadow-2xl flex flex-col overflow-hidden max-h-[80vh]"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Search Input Bar */}
            <div className="p-4 border-b border-[var(--sd-border)] bg-[var(--sd-surface)] flex items-center gap-3">
              <Search className="w-5 h-5 text-[var(--sd-wheat)] flex-shrink-0" />
              <input
                ref={searchInputRef}
                autoFocus
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search across all 23 customer guides..."
                className="w-full bg-transparent text-sm text-[var(--sd-text)] placeholder-[var(--sd-text-dim)] focus:outline-hidden"
              />
              <button
                onClick={() => setIsSearchOpen(false)}
                className="p-1 rounded-lg text-[var(--sd-text-dim)] hover:text-white"
                title="Close (ESC)"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Quick Suggestion Chips */}
            <div className="px-4 py-2 border-b border-[var(--sd-border-subtle)] bg-[var(--sd-panel-raised)]/40 flex items-center gap-2 overflow-x-auto text-[11px] font-mono">
              <span className="text-[var(--sd-text-dim)] flex-shrink-0">Quick Topics:</span>
              {["Agent Install", "SLA", "MFA", "RBAC", "Digital Twin", "Rollback", "Compliance"].map(
                (topic) => (
                  <button
                    key={topic}
                    onClick={() => setSearchQuery(topic)}
                    className="px-2 py-0.5 rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] text-[var(--sd-wheat)] hover:border-[var(--sd-border)] transition flex-shrink-0 cursor-pointer"
                  >
                    {topic}
                  </button>
                )
              )}
            </div>

            {/* Search Results List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {searchQuery.trim() === "" ? (
                <div className="text-center py-8 text-[var(--sd-text-dim)] text-xs font-mono">
                  Type a keyword, capability name, or compliance term to search...
                </div>
              ) : searchResults.length === 0 ? (
                <div className="text-center py-8 text-[var(--sd-text-dim)] text-xs font-mono">
                  No documentation found matching &quot;{searchQuery}&quot;.
                </div>
              ) : (
                searchResults.map((doc) => {
                  const meta = CATEGORY_META[doc.category];
                  const Icon = meta.icon;
                  return (
                    <button
                      key={doc.id}
                      onClick={() => selectDocument(doc.id)}
                      className="w-full text-left p-3.5 rounded-xl border border-[var(--sd-border-subtle)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] hover:border-[var(--sd-border)] transition flex items-start gap-3 group cursor-pointer"
                    >
                      <div className="p-2 rounded-lg bg-[var(--sd-bg)] border border-[var(--sd-border-subtle)] text-[var(--sd-wheat)] mt-0.5">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--sd-text-dim)]">
                            {doc.category}
                          </span>
                          <span className="text-[10px] font-mono text-[var(--sd-text-dim)]">
                            • {doc.readTime}
                          </span>
                        </div>
                        <h4 className="text-sm font-semibold text-[var(--sd-sand)] group-hover:text-white transition truncate mt-0.5">
                          {doc.title}
                        </h4>
                        <p className="text-xs text-[var(--sd-text-muted)] line-clamp-1 mt-0.5">
                          {doc.summary}
                        </p>
                      </div>
                      <ArrowRight className="w-4 h-4 text-[var(--sd-text-dim)] group-hover:text-[var(--sd-wheat)] group-hover:translate-x-0.5 transition self-center flex-shrink-0" />
                    </button>
                  );
                })
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3 border-t border-[var(--sd-border)] bg-[var(--sd-surface)] flex items-center justify-between text-[11px] font-mono text-[var(--sd-text-dim)]">
              <span>Press ESC to close</span>
              <span>Total {allDocs.length} Guides Available</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

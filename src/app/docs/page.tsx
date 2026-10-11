"use client";

import React, { useState, useMemo } from "react";
import Link from "next/link";
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
  Lock,
  Server,
  Activity,
  FileCheck2,
  Printer,
  Sparkles,
  X,
  Tag,
  ChevronRight,
  Clock,
  Layers,
  HelpCircle,
  FolderDown,
} from "lucide-react";
import { TopNavBar } from "@/components/navigation/TopNavBar";
import {
  getAllCustomerDocs,
  generateDocumentationBundle,
  type CustomerDoc,
  type DocCategory,
} from "@/lib/docs/customerDocs";

export default function CustomerDocsPage() {
  const allDocs = useMemo(() => getAllCustomerDocs(), []);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [activeDoc, setActiveDoc] = useState<CustomerDoc | null>(null);
  const [copiedDocId, setCopiedDocId] = useState<string | null>(null);
  const [copiedModal, setCopiedModal] = useState(false);
  const [downloadingBundle, setDownloadingBundle] = useState(false);

  // Filtered documents based on search query and category
  const filteredDocs = useMemo(() => {
    return allDocs.filter((doc) => {
      const matchesCategory =
        selectedCategory === "All" || doc.category === selectedCategory;

      if (!matchesCategory) return false;

      if (!searchQuery.trim()) return true;

      const q = searchQuery.toLowerCase();
      const matchTitle = doc.title.toLowerCase().includes(q);
      const matchSummary = doc.summary.toLowerCase().includes(q);
      const matchTags = doc.tags.some((t) => t.toLowerCase().includes(q));
      const matchContent = doc.content.toLowerCase().includes(q);

      return matchTitle || matchSummary || matchTags || matchContent;
    });
  }, [allDocs, searchQuery, selectedCategory]);

  const categories: Array<{ id: string; label: string; count: number }> = [
    { id: "All", label: "All Documents", count: allDocs.length },
    {
      id: "Getting Started",
      label: "Getting Started",
      count: allDocs.filter((d) => d.category === "Getting Started").length,
    },
    {
      id: "SOC Operations",
      label: "SOC Operations",
      count: allDocs.filter((d) => d.category === "SOC Operations").length,
    },
    {
      id: "Agent & Integrations",
      label: "Agent & Integrations",
      count: allDocs.filter((d) => d.category === "Agent & Integrations").length,
    },
    {
      id: "Trust & Compliance",
      label: "Trust & Compliance",
      count: allDocs.filter((d) => d.category === "Trust & Compliance").length,
    },
    {
      id: "Support",
      label: "Support",
      count: allDocs.filter((d) => d.category === "Support").length,
    },
  ];

  const quickSearchTags = [
    "Agent Install",
    "SLA",
    "MFA",
    "RBAC",
    "Trivy",
    "Merkle Chain",
    "Rollback",
    "SCIM",
  ];

  const handleCopyDoc = (doc: CustomerDoc, e?: React.MouseEvent) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(doc.content);
    setCopiedDocId(doc.id);
    setTimeout(() => setCopiedDocId(null), 2000);
  };

  const handleDownloadDoc = (doc: CustomerDoc, e?: React.MouseEvent) => {
    e?.stopPropagation();
    const blob = new Blob([doc.content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = doc.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadBundle = () => {
    setDownloadingBundle(true);
    try {
      const bundleContent = generateDocumentationBundle();
      const blob = new Blob([bundleContent], { type: "text/markdown;charset=utf-8" });
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

  const handleCopyModal = () => {
    if (!activeDoc) return;
    navigator.clipboard.writeText(activeDoc.content);
    setCopiedModal(true);
    setTimeout(() => setCopiedModal(false), 2000);
  };

  const getCategoryColor = (cat: DocCategory) => {
    switch (cat) {
      case "Getting Started":
        return "bg-[var(--sd-pine)]/15 text-[var(--sd-wheat)] border-[var(--sd-pine)]/30";
      case "SOC Operations":
        return "bg-[var(--sd-success-dim)] text-[var(--sd-success)] border-[var(--sd-success-border)]";
      case "Agent & Integrations":
        return "bg-[var(--sd-warning-dim)] text-[var(--sd-wheat)] border-[var(--sd-warning-border)]";
      case "Trust & Compliance":
        return "bg-[var(--sd-panel-raised)] text-[var(--sd-wheat)] border-[var(--sd-border)]";
      case "Support":
        return "bg-[var(--sd-panel-raised)] text-[var(--sd-text-muted)] border-[var(--sd-border-subtle)]";
    }
  };

  return (
    <div className="sd-app-shell min-h-screen bg-[var(--sd-bg)] text-[var(--sd-text)] flex flex-col font-sans">
      {/* Global Top Navbar */}
      <TopNavBar />

      {/* Main Workspace Layout */}
      <main className="sd-dashboard-content min-w-0 flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--sd-border)] pb-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl sd-surface border border-[var(--sd-border)] flex items-center justify-center text-[var(--sd-wheat)] shadow-xs">
              <BookOpen className="h-5 w-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="tracking-tight text-[var(--sd-text)] text-2xl sm:text-3xl font-light leading-tight font-sans">
                  Customer Documentation & Knowledge Base
                </h1>
                <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--sd-success-dim)] text-[var(--sd-success)] border border-[var(--sd-success-border)] font-mono">
                  {allDocs.length} Verified Guides
                </span>
              </div>
              <p className="text-[13px] text-[var(--sd-text-muted)] mt-0.5">
                Operational runbooks, endpoint deployment manuals, security specifications, and compliance policies.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Take All Docs (Bundle Download) */}
            <button
              onClick={handleDownloadBundle}
              disabled={downloadingBundle}
              className="sd-button flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl sd-button-primary text-xs font-semibold text-[var(--sd-on-accent)] transition-all cursor-pointer shadow-xs disabled:opacity-50"
              title="Download entire customer documentation package as a single Markdown manual"
            >
              <FolderDown className="h-3.5 w-3.5 text-[var(--sd-on-accent)]" />
              <span>
                {downloadingBundle ? "Packaging..." : "Take All Docs (Bundle)"}
              </span>
            </button>

            {/* Quick Link to Status */}
            <Link
              href="/status"
              className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] sd-surface hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition-all cursor-pointer shadow-xs"
            >
              <Activity className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
              <span>Platform Status</span>
            </Link>
          </div>
        </div>

        {/* Executive Overview Metric Cards */}
        <div className="sd-overview-metrics">
          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Customer Manuals
              <FileText size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value text-[var(--sd-wheat)] font-mono">
              {allDocs.length} Guides
            </div>
            <p className="sd-metric-caption">Operational and deployment</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Compliance Frameworks
              <FileCheck2 size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value text-[var(--sd-success)] font-mono text-[20px]">
              ISO 27001
            </div>
            <p className="sd-metric-caption">SOC 2 & HIPAA aligned</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Endpoint Agents
              <Server size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value font-mono text-[18px]">
              Linux & Win
            </div>
            <p className="sd-metric-caption">mTLS v1.3 cryptographic bus</p>
          </div>

          <div className="sd-glass sd-metric">
            <div className="sd-metric-label">
              Support SLA
              <Lock size={17} strokeWidth={1.4} />
            </div>
            <div className="sd-metric-value font-mono text-[18px]">
              &lt; 15m P1
            </div>
            <p className="sd-metric-caption">24/7 dedicated escalation</p>
          </div>
        </div>

        {/* Search & Filter Toolbar */}
        <div className="sd-surface rounded-2xl border border-[var(--sd-border)] p-5 shadow-xs space-y-4">
          <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--sd-text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search documentation, agent install scripts, SLAs, MFA, or compliance rules..."
                className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[var(--sd-bg)] border border-[var(--sd-border)] text-sm text-[var(--sd-text)] placeholder:text-[var(--sd-text-dim)] focus:outline-none focus:border-[var(--sd-pine)] transition-all font-sans"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-[var(--sd-text-dim)] hover:text-[var(--sd-text)] rounded-md cursor-pointer"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Quick Stats in Search bar */}
            <div className="text-xs font-mono text-[var(--sd-text-dim)] flex items-center gap-2 shrink-0 px-1">
              <span>Showing</span>
              <strong className="text-[var(--sd-wheat)] font-semibold">
                {filteredDocs.length}
              </strong>
              <span>of {allDocs.length} docs</span>
            </div>
          </div>

          {/* Category Filter Tabs */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--sd-border-subtle)]">
            <div className="inline-flex items-center p-1 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] overflow-x-auto max-w-full">
              {categories.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                    selectedCategory === cat.id
                      ? "bg-[var(--sd-pine)] text-[var(--sd-on-accent)] font-semibold shadow-xs"
                      : "text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                  }`}
                >
                  {cat.label}
                  <span className="ml-1.5 opacity-70 font-mono text-[10px]">
                    ({cat.count})
                  </span>
                </button>
              ))}
            </div>

            {/* Quick Suggestion Tags */}
            <div className="hidden lg:flex items-center gap-1.5 text-xs text-[var(--sd-text-dim)]">
              <span className="text-[11px] font-mono">Popular:</span>
              {quickSearchTags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => setSearchQuery(tag)}
                  className="px-2 py-0.5 rounded-md bg-[var(--sd-panel-raised)] border border-[var(--sd-border-subtle)] hover:border-[var(--sd-border)] hover:text-[var(--sd-text)] text-[11px] font-mono transition-colors cursor-pointer"
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Documents Cards Grid */}
        {filteredDocs.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredDocs.map((doc) => (
              <div
                key={doc.id}
                onClick={() => setActiveDoc(doc)}
                className="sd-surface rounded-2xl border border-[var(--sd-border)] hover:border-[var(--sd-border-strong)] p-5 transition-all shadow-xs flex flex-col justify-between group cursor-pointer hover:shadow-md"
              >
                <div>
                  {/* Category Pill & Read Time */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider border ${getCategoryColor(
                        doc.category
                      )}`}
                    >
                      {doc.category}
                    </span>
                    <span className="text-[11px] font-mono text-[var(--sd-text-dim)] flex items-center gap-1">
                      <Clock className="w-3 h-3 text-[var(--sd-pine)]" />
                      {doc.readTime}
                    </span>
                  </div>

                  {/* Document Title */}
                  <h3 className="text-base font-semibold text-[var(--sd-text)] group-hover:text-[var(--sd-wheat)] transition-colors leading-snug mb-2">
                    {doc.title}
                  </h3>

                  {/* Document Summary */}
                  <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed line-clamp-3 mb-4">
                    {doc.summary}
                  </p>
                </div>

                <div>
                  {/* Tags */}
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {doc.tags.map((t) => (
                      <span
                        key={t}
                        className="px-2 py-0.5 rounded bg-[var(--sd-panel-raised)] text-[var(--sd-text-dim)] text-[10px] font-mono border border-[var(--sd-border-subtle)]"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>

                  {/* Action Bar on Card */}
                  <div className="pt-3 border-t border-[var(--sd-border-subtle)] flex items-center justify-between">
                    <span className="text-xs font-semibold text-[var(--sd-pine)] group-hover:text-[var(--sd-wheat)] flex items-center gap-1 transition-colors">
                      <span>Read Guide</span>
                      <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </span>

                    <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                      {/* Copy Markdown */}
                      <button
                        onClick={(e) => handleCopyDoc(doc, e)}
                        className="p-1.5 rounded-lg border border-[var(--sd-border-subtle)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                        title="Copy document Markdown"
                      >
                        {copiedDocId === doc.id ? (
                          <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>

                      {/* Download .md */}
                      <button
                        onClick={(e) => handleDownloadDoc(doc, e)}
                        className="p-1.5 rounded-lg border border-[var(--sd-border-subtle)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                        title={`Download ${doc.filename}`}
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          /* Empty Search State */
          <div className="sd-surface rounded-2xl border border-[var(--sd-border)] p-12 text-center space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] mx-auto flex items-center justify-center text-[var(--sd-text-muted)]">
              <Search className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-[var(--sd-text)]">
                No customer documents match your query
              </h3>
              <p className="text-xs text-[var(--sd-text-muted)] mt-1 max-w-md mx-auto">
                No matching results found for <span className="text-[var(--sd-wheat)] font-mono">"{searchQuery}"</span>.
                Try adjusting your search terms or clearing the category filter.
              </p>
            </div>
            <button
              onClick={() => {
                setSearchQuery("");
                setSelectedCategory("All");
              }}
              className="sd-button px-4 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer"
            >
              Reset Filters
            </button>
          </div>
        )}

        {/* Bottom Documentation Callout */}
        <div className="rounded-2xl border border-[var(--sd-border)] sd-surface p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-[var(--sd-wheat)]" />
              <span className="text-sm font-medium text-[var(--sd-text)]">
                Need Dedicated Enterprise Runbooks or Custom Architecture Support?
              </span>
            </div>
            <p className="text-xs text-[var(--sd-text-muted)] leading-relaxed max-w-2xl">
              ShieldDesk Technical Account Managers (TAMs) provide tailored deployment assistance, custom YARA rule writing, and private cloud deployment orchestration.
            </p>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Link
              href="/pricing"
              className="sd-button flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-xs font-medium text-[var(--sd-text)] hover:bg-[var(--sd-panel-hover)] transition cursor-pointer shadow-xs"
            >
              <span>Enterprise Tiers</span>
            </Link>
            <button
              onClick={handleDownloadBundle}
              className="sd-button flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-xl sd-button-primary text-xs font-semibold text-[var(--sd-on-accent)] transition-all cursor-pointer shadow-xs shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export All Guides</span>
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-[var(--sd-text-dim)] border-t border-[var(--sd-border-subtle)]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[var(--sd-pine)]" />
            <span>ShieldDesk™ Autonomous SOC · Customer Documentation Portal</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/" className="hover:text-[var(--sd-wheat)] transition-colors">
              SOC Workspace
            </Link>
            <Link href="/status" className="hover:text-[var(--sd-wheat)] transition-colors">
              Platform Status & SLA
            </Link>
            <Link href="/pricing" className="hover:text-[var(--sd-wheat)] transition-colors">
              Commercial Plans
            </Link>
          </div>
        </div>
      </main>

      {/* Interactive Document Reader Modal */}
      {activeDoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div
            className="w-full max-w-4xl max-h-[90vh] bg-[var(--sd-bg-alt)] border border-[var(--sd-border-strong)] rounded-2xl shadow-2xl flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-5 border-b border-[var(--sd-border)] bg-[var(--sd-surface)] flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-[var(--sd-panel-raised)] border border-[var(--sd-border)] text-[var(--sd-wheat)]">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono uppercase tracking-wider border ${getCategoryColor(
                        activeDoc.category
                      )}`}
                    >
                      {activeDoc.category}
                    </span>
                    <span className="text-[11px] font-mono text-[var(--sd-text-dim)]">
                      {activeDoc.readTime}
                    </span>
                  </div>
                  <h2 className="text-lg font-semibold text-[var(--sd-text)] leading-snug mt-0.5">
                    {activeDoc.title}
                  </h2>
                </div>
              </div>

              {/* Toolbar Actions */}
              <div className="flex items-center gap-2">
                {/* Copy Markdown */}
                <button
                  onClick={handleCopyModal}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                  title="Copy Document Markdown"
                >
                  {copiedModal ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--sd-success)]" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-[var(--sd-wheat)]" />
                      <span>Copy Markdown</span>
                    </>
                  )}
                </button>

                {/* Download File */}
                <button
                  onClick={() => handleDownloadDoc(activeDoc)}
                  className="sd-button flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-xs font-medium text-[var(--sd-text)] transition cursor-pointer shadow-xs"
                  title={`Download ${activeDoc.filename}`}
                >
                  <Download className="w-3.5 h-3.5 text-[var(--sd-pine)]" />
                  <span>Download .md</span>
                </button>

                {/* Print Document */}
                <button
                  onClick={() => window.print()}
                  className="sd-button p-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer"
                  title="Print / Save PDF"
                >
                  <Printer className="w-4 h-4" />
                </button>

                {/* Close Button */}
                <button
                  onClick={() => setActiveDoc(null)}
                  className="p-2 rounded-xl border border-[var(--sd-border)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)] transition cursor-pointer ml-1"
                  title="Close (ESC)"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Modal Body: Formatted Document Reader */}
            <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-4 text-sm leading-relaxed text-[var(--sd-text)] font-sans">
              <div className="prose prose-invert max-w-none space-y-4">
                <pre className="whitespace-pre-wrap font-sans bg-[var(--sd-bg)] p-6 rounded-xl border border-[var(--sd-border)] text-sm text-[var(--sd-text)] leading-relaxed overflow-x-auto selection:bg-[var(--sd-pine)] selection:text-white">
                  {activeDoc.content}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[var(--sd-border)] bg-[var(--sd-surface)] flex items-center justify-between text-xs text-[var(--sd-text-dim)] font-mono">
              <div className="flex items-center gap-2">
                <span>File: {activeDoc.filename}</span>
                <span>•</span>
                <span>Updated: {activeDoc.lastUpdated}</span>
              </div>
              <button
                onClick={() => setActiveDoc(null)}
                className="px-3 py-1 rounded-lg border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text)] transition cursor-pointer font-sans"
              >
                Close Reader
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

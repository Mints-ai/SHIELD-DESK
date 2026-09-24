"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  ArrowDown,
  Bot,
  Send,
  User as UserIcon,
  Shield,
  X,
  Trash2,
  ChevronDown,
  Layers,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useChat, DEV_USERS, type DevUserId } from "@/lib/context/ChatContext";
import { FormattedAssistantMessage } from "./FormattedAssistantMessage";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  isError?: boolean;
}

const GLOBEX_SUGGESTIONS = [
  "Simulate Blast Radius for CVE-2024-6387",
  "Check for leaked secrets and exposed tokens",
  "Run Trivy container scan on fleet",
  "Show me todays critical incidents",
];

const DEFAULT_SUGGESTIONS = [
  "Show me todays critical incidents",
  "Investigate INC-1042",
  "Generate automated remediation runbook",
  "Run Trivy container scan on fleet",
  "Check for leaked secrets and exposed tokens",
];

export function ChatWidget() {
  const {
    activeUserId,
    setActiveUserId,
    activeUser,
    activeIncidentId,
    setActiveIncidentId,
    activeCveId,
    isChatOpen,
    setIsChatOpen,
    promptToInject,
    setPromptToInject,
  } = useChat();

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [isRoleDropdownOpen, setIsRoleDropdownOpen] = useState(false);

  const messagesRef = useRef<HTMLDivElement>(null);
  const activeResponseRef = useRef<HTMLDivElement>(null);
  const [activeResponseId, setActiveResponseId] = useState<string | null>(null);
  const [shouldFollowLatest, setShouldFollowLatest] = useState(true);
  const accumulatedRef = useRef("");

  const storageKey = `shielddesk_chat_messages_${activeUserId}`;

  // Load chat history from sessionStorage on persona change
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(storageKey);
      if (saved) {
        setMessages(JSON.parse(saved));
      } else {
        setMessages([]);
      }
    } catch {
      setMessages([]);
    }
  }, [storageKey]);

  // Persist messages to sessionStorage
  const saveMessages = useCallback(
    (newMessages: ChatMessage[]) => {
      try {
        sessionStorage.setItem(storageKey, JSON.stringify(newMessages));
      } catch {
        // ignore
      }
    },
    [storageKey]
  );

  // Auto-scroll logic
  useEffect(() => {
    const messagesContainer = messagesRef.current;
    const activeResponse = activeResponseRef.current;
    if (!isChatOpen || !messagesContainer || !activeResponseId || !activeResponse) return;

    messagesContainer.scrollTo({
      top: Math.max(0, activeResponse.offsetTop - 16),
      behavior: "smooth",
    });
  }, [activeResponseId, isChatOpen]);

  const handleMessagesScroll = () => {
    const messagesContainer = messagesRef.current;
    if (!messagesContainer) return;

    const distanceFromLatest =
      messagesContainer.scrollHeight - messagesContainer.scrollTop - messagesContainer.clientHeight;
    setShouldFollowLatest(distanceFromLatest < 48);
  };

  const scrollToLatest = () => {
    setShouldFollowLatest(true);
    messagesRef.current?.scrollTo({
      top: messagesRef.current.scrollHeight,
      behavior: "smooth",
    });
  };

  const clearChat = () => {
    setMessages([]);
    try {
      sessionStorage.removeItem(storageKey);
    } catch {
      // ignore
    }
  };

  const sendMessage = useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || isSending) return;

      const userMsg: ChatMessage = { id: crypto.randomUUID(), role: "user", content: trimmed };
      setMessages((prev) => {
        const next = [...prev, userMsg];
        saveMessages(next);
        return next;
      });
      setInput("");
      setShouldFollowLatest(true);
      setIsSending(true);

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ShieldDesk-User": activeUserId,
          },
          body: JSON.stringify({
            message: trimmed,
            context: {
              currentIncidentId: activeIncidentId || undefined,
              currentCveId: activeCveId || undefined,
              currentPage: "dashboard",
            },
          }),
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body?.error || `Request failed (${res.status})`);
        }

        if (!res.body) throw new Error("Empty response from assistant.");

        const assistantId = crypto.randomUUID();
        setActiveResponseId(assistantId);
        setMessages((prev) => {
          const next: ChatMessage[] = [...prev, { id: assistantId, role: "assistant", content: "" }];
          return next;
        });

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        accumulatedRef.current = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop() || "";

          for (const part of parts) {
            if (!part.startsWith("data: ")) continue;
            const payload = part.slice(6);
            if (payload === "[DONE]") continue;

            try {
              const obj = JSON.parse(payload);
              if (obj.token) {
                accumulatedRef.current += obj.token;
                const accumulated = accumulatedRef.current;
                setMessages((prev) =>
                  prev.map((m) => (m.id === assistantId ? { ...m, content: accumulated } : m))
                );
              }
            } catch {
              // partial chunk, wait for more data
            }
          }
        }

        // Final save with complete stream content
        setMessages((prev) => {
          saveMessages(prev);
          return prev;
        });
      } catch (err: unknown) {
        const messageText = err instanceof Error ? err.message : undefined;
        setMessages((prev) => {
          const next: ChatMessage[] = [
            ...prev,
            {
              id: crypto.randomUUID(),
              role: "assistant",
              content:
                messageText === "Failed to fetch"
                  ? "Couldn't reach the assistant. Please verify that Next.js and Ollama are reachable."
                  : messageText || "Something went wrong. Please try again.",
              isError: true,
            },
          ];
          saveMessages(next);
          return next;
        });
      } finally {
        setIsSending(false);
      }
    },
    [isSending, activeUserId, activeIncidentId, activeCveId, saveMessages]
  );

  // Consume injected prompts (e.g. from dashboard action buttons)
  useEffect(() => {
    if (promptToInject && isChatOpen && !isSending) {
      const p = promptToInject;
      setPromptToInject(null);
      sendMessage(p);
    }
  }, [promptToInject, isChatOpen, isSending, sendMessage, setPromptToInject]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(input);
  };

  const isGlobex = activeUserId === "dev-other";

  const dynamicSuggestions = activeIncidentId
    ? [
        `Investigate ${activeIncidentId}`,
        "What is the mitigation plan?",
        "What assets are affected?",
        ...(isGlobex ? ["Simulate Blast Radius for CVE-2024-6387"] : []),
        "Show me todays critical incidents",
      ]
    : isGlobex
      ? GLOBEX_SUGGESTIONS
      : DEFAULT_SUGGESTIONS;

  return (
    <>
      {/* Floating Toggle Button */}
      <button
        onClick={() => setIsChatOpen(!isChatOpen)}
        className={cn(
          "fixed bottom-5 right-5 z-[100] h-13 w-13 rounded-2xl shadow-xl flex items-center justify-center transition-all duration-200 cursor-pointer",
          "bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] hover:scale-105 active:scale-95 border border-[var(--sd-border)] text-[#f7f4ed]"
        )}
        aria-label={isChatOpen ? "Close ShieldDesk Assistant" : "Open ShieldDesk Assistant"}
      >
        <AnimatePresence mode="wait" initial={false}>
          {isChatOpen ? (
            <motion.span
              key="close"
              initial={{ rotate: -90, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              exit={{ rotate: 90, opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <X className="h-6 w-6" />
            </motion.span>
          ) : (
            <motion.span
              key="open"
              initial={{ rotate: 90, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              exit={{ rotate: -90, opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="flex items-center justify-center w-full h-full p-1"
            >
              <img src="/logo.png" alt="ShieldDesk" className="h-7 w-7 object-contain drop-shadow-sm" />
            </motion.span>
          )}
        </AnimatePresence>
      </button>

      {/* Chat Window */}
      <AnimatePresence>
        {isChatOpen && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ duration: 0.18 }}
            className="fixed bottom-[calc(4.75rem+12px)] right-5 z-[100] w-[420px] max-w-[calc(100vw-2.5rem)] h-[580px] max-h-[calc(100vh-8rem)] rounded-2xl border border-[var(--sd-border)] bg-white shadow-2xl flex flex-col overflow-hidden font-sans"
          >
            {/* Header: Title + Role Switcher + Controls */}
            <div className="shrink-0 px-4 py-3 border-b border-[var(--sd-border)] bg-[var(--sd-bg-alt)]/60 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-white border border-[var(--sd-border)] p-0.5 shadow-xs overflow-hidden">
                  <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-bold text-[var(--sd-pine)]">
                      ShieldDesk<span className="text-[9px] text-[#a48858] align-super ml-0.5">™</span>
                    </span>
                    <span className="rounded bg-white border border-[var(--sd-border)] px-1.5 py-0.2 text-[9px] font-bold text-[var(--sd-pine)] uppercase tracking-wide font-mono shadow-xs">
                      AI SOC
                    </span>
                  </div>
                  <div className="text-[10px] text-[var(--sd-text-muted)] truncate flex items-center gap-1">
                    <span>{activeUser.tenantName} · Mints Global</span>
                  </div>
                </div>
              </div>

              {/* Header Right: Persona Selector & Clear */}
              <div className="flex items-center gap-1.5 shrink-0">
                {/* Persona Switcher Dropdown (Restricted to non-production environments) */}
                {process.env.NODE_ENV !== "production" && (
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setIsRoleDropdownOpen((v) => !v)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-md border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-panel-hover)] text-[10.5px] font-semibold text-[var(--sd-pine)] transition-all cursor-pointer shadow-xs"
                      title="Switch Dev Persona / RBAC Role (Dev Mode Only)"
                    >
                      <span
                        className={cn(
                          "h-1.5 w-1.5 rounded-full",
                          activeUserId === "dev-admin"
                            ? "bg-[#9333ea]"
                            : activeUserId === "dev-other"
                              ? "bg-[#d97706]"
                              : "bg-[var(--sd-success)]"
                        )}
                      />
                      <span className="truncate max-w-[70px]">{activeUser.label}</span>
                      <ChevronDown className="h-3 w-3 opacity-60" />
                    </button>

                    <AnimatePresence>
                      {isRoleDropdownOpen && (
                        <motion.div
                          initial={{ opacity: 0, y: 4, scale: 0.95 }}
                          animate={{ opacity: 1, y: 0, scale: 1 }}
                          exit={{ opacity: 0, y: 4, scale: 0.95 }}
                          transition={{ duration: 0.12 }}
                          className="absolute right-0 top-full mt-1.5 w-56 rounded-xl border border-[var(--sd-border)] bg-white p-1 shadow-2xl z-50"
                        >
                          <div className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--sd-text-muted)] border-b border-[var(--sd-border)] font-mono">
                            Dev RBAC Persona Switcher
                          </div>
                          {Object.values(DEV_USERS).map((user) => (
                            <button
                              key={user.id}
                              type="button"
                              onClick={() => {
                                setActiveUserId(user.id);
                                setIsRoleDropdownOpen(false);
                              }}
                              className={cn(
                                "w-full text-left px-2 py-1.5 rounded-lg text-xs transition-colors flex flex-col gap-0.5 cursor-pointer",
                                user.id === activeUserId
                                  ? "bg-[var(--sd-pine)] text-[#f7f4ed] font-semibold shadow-xs"
                                  : "hover:bg-[var(--sd-panel-hover)] text-[var(--sd-text-muted)] hover:text-[var(--sd-text)]"
                              )}
                            >
                              <div className="flex items-center justify-between">
                                <span>{user.label}</span>
                                <span className="text-[9.5px] font-mono opacity-80">
                                  {user.role === "system_admin" ? "Cross-Tenant" : user.tenantId}
                                </span>
                              </div>
                              <span className="text-[10px] opacity-75 font-normal leading-tight">
                                {user.description}
                              </span>
                            </button>
                          ))}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                )}

                {/* Clear Chat Button */}
                <button
                  type="button"
                  onClick={clearChat}
                  className="h-7 w-7 rounded-md border border-[var(--sd-border)] bg-white hover:bg-[var(--sd-danger-dim)] hover:border-[var(--sd-danger-border)] text-[var(--sd-text-muted)] hover:text-[var(--sd-danger)] flex items-center justify-center transition-colors cursor-pointer shadow-xs"
                  title="Clear Chat History"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Active Context Banner */}
            {activeIncidentId && (
              <div className="shrink-0 px-3 py-1.5 bg-[var(--sd-bg-alt)] border-b border-[var(--sd-border)] flex items-center justify-between text-[11px] text-[var(--sd-pine)]">
                <div className="flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5 text-[var(--sd-pine)]" />
                  <span>
                    Active Context: <strong className="font-semibold text-[var(--sd-pine)] font-mono">{activeIncidentId}</strong>
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setActiveIncidentId(null)}
                  className="text-[10px] text-[var(--sd-text-muted)] hover:text-[var(--sd-pine)] underline cursor-pointer"
                >
                  Clear context
                </button>
              </div>
            )}

            {/* Messages Area */}
            <div
              ref={messagesRef}
              onScroll={handleMessagesScroll}
              className="relative flex-1 overflow-y-auto p-4 space-y-3 min-h-0 bg-white"
            >
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center gap-3 px-3">
                  <div className="w-12 h-12 rounded-2xl bg-white border border-[var(--sd-border)] p-1.5 flex items-center justify-center shadow-md">
                    <img src="/logo.png" alt="ShieldDesk" className="h-full w-full object-contain" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-[var(--sd-pine)]">
                      ShieldDesk<span className="text-[9px] text-[#a48858] align-super ml-0.5">™</span> Autonomous Co-Pilot
                    </h4>
                    <p className="mt-1 text-[11px] text-[var(--sd-text-muted)] max-w-[280px] leading-relaxed">
                      AI-Powered Security Operations · Powered by Mints Global
                    </p>
                  </div>
                  <div className="flex flex-col gap-1.5 w-full mt-1">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--sd-pine)] text-left px-1 flex items-center gap-1 font-mono">
                      <Sparkles className="h-3 w-3 text-[var(--sd-pine)]" /> Suggested Inquiries
                    </span>
                    {dynamicSuggestions.map((s) => (
                      <button
                        key={s}
                        onClick={() => sendMessage(s)}
                        className="px-3 py-2 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] hover:bg-[var(--sd-panel-hover)] text-[11px] text-[var(--sd-text)] hover:text-[var(--sd-pine)] hover:border-[var(--sd-border-strong)] transition-all text-left cursor-pointer flex items-center justify-between shadow-xs"
                      >
                        <span className="truncate">{s}</span>
                        <Send className="h-2.5 w-2.5 text-[var(--sd-pine)] opacity-60 shrink-0 ml-1" />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <AnimatePresence initial={false}>
                  {messages.map((m) => (
                    <motion.div
                      key={m.id}
                      ref={m.id === activeResponseId ? activeResponseRef : undefined}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={cn("flex items-start gap-2", m.role === "user" && "flex-row-reverse")}
                    >
                      <Avatar className="w-6 h-6 border border-[var(--sd-border)] shrink-0 mt-0.5">
                        <AvatarFallback
                          className={cn(
                            "text-[10px] font-bold",
                            m.role === "assistant" ? "bg-[var(--sd-bg-alt)] text-[var(--sd-pine)]" : "bg-[var(--sd-pine)] text-[#f7f4ed]"
                          )}
                        >
                          {m.role === "assistant" ? <Bot className="w-3.5 h-3.5 text-[var(--sd-pine)]" /> : <UserIcon className="w-3 h-3" />}
                        </AvatarFallback>
                      </Avatar>
                      <div
                        className={cn(
                          "max-w-[85%] rounded-2xl px-3.5 py-2.5 text-xs leading-relaxed",
                          m.role === "user"
                            ? "bg-[var(--sd-pine)] text-[#f7f4ed] rounded-tr-sm shadow-xs"
                            : m.isError
                              ? "bg-[var(--sd-danger-dim)] border border-[var(--sd-danger-border)] text-[var(--sd-danger)] rounded-tl-sm"
                              : "border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)] rounded-tl-sm shadow-xs"
                        )}
                      >
                        {m.role === "assistant" && !m.isError ? (
                          <FormattedAssistantMessage content={m.content} />
                        ) : (
                          <div className="whitespace-pre-wrap">{m.content}</div>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}

              {/* Streaming loading indicator */}
              {isSending && (
                <div className="flex items-start gap-2">
                  <Avatar className="w-6 h-6 border border-[var(--sd-border)] shrink-0 mt-0.5">
                    <AvatarFallback className="bg-[var(--sd-bg-alt)] text-[var(--sd-pine)]">
                      <Bot className="w-3.5 h-3.5 text-[var(--sd-pine)]" />
                    </AvatarFallback>
                  </Avatar>
                  <div className="border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] rounded-2xl rounded-tl-sm px-3.5 py-2.5 flex items-center gap-1.5 shadow-xs">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--sd-pine)] animate-bounce [animation-delay:-0.3s]" />
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--sd-pine)] animate-bounce [animation-delay:-0.15s]" />
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--sd-pine)] animate-bounce" />
                    <span className="text-[10px] text-[var(--sd-text-muted)] ml-1 font-mono">Analyzing SOC telemetry...</span>
                  </div>
                </div>
              )}

              {/* Scroll to latest button */}
              {!shouldFollowLatest && messages.length > 0 && (
                <button
                  type="button"
                  onClick={scrollToLatest}
                  className="sticky bottom-1 mx-auto flex items-center gap-1 rounded-full border border-[var(--sd-border)] bg-white px-3 py-1 text-[10px] font-medium text-[var(--sd-pine)] shadow-md hover:border-[var(--sd-border-strong)] cursor-pointer"
                  aria-label="Jump to latest response"
                >
                  <ArrowDown className="h-3 w-3 text-[var(--sd-pine)]" />
                  Jump to latest
                </button>
              )}
            </div>

            {/* Input Bar */}
            <form onSubmit={handleSubmit} className="shrink-0 border-t border-[var(--sd-border)] p-3 bg-[var(--sd-bg-alt)]/40 flex items-center gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={
                  activeIncidentId
                    ? `Ask about ${activeIncidentId} or 'investigate this'...'`
                    : "Ask about an incident, CVE, or mitigation plan..."
                }
                maxLength={4000}
                disabled={isSending}
                className="flex-1 h-9 rounded-xl border border-[var(--sd-border)] px-3 text-xs text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--sd-pine)] bg-white disabled:opacity-50 shadow-xs"
              />
              <button
                type="submit"
                disabled={isSending || !input.trim()}
                className="h-9 w-9 rounded-xl bg-[var(--sd-pine)] hover:bg-[var(--sd-pine-dark)] disabled:opacity-40 text-[#f7f4ed] flex items-center justify-center transition-all cursor-pointer shrink-0 shadow-xs"
                aria-label="Send message"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default ChatWidget;

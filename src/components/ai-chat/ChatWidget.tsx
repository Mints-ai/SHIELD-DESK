"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  ArrowDown,
  Bot,
  Send,
  User as UserIcon,
  ShieldCheck,
  X,
  Trash2,
  ChevronDown,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import { useChat, DEV_USERS } from "@/lib/context/ChatContext";
import { FormattedAssistantMessage } from "./FormattedAssistantMessage";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  isError?: boolean;
}

const DEFAULT_SUGGESTIONS = [
  "Run a full Trivy vulnerability scan",
  "Show me todays critical incidents",
  "Investigate INC-1042",
  "Generate automated remediation runbook",
  "Check for leaked secrets and exposed tokens",
];

export function ChatWidget() {
  const {
    activeUserId,
    setActiveUserId,
    activeUser,
    activeIncidentId,
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

  const reduceMotion = useReducedMotion();
  const launcherRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const personaButtonRef = useRef<HTMLButtonElement>(null);
  const personaMenuRef = useRef<HTMLDivElement>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const messagesRef = useRef<HTMLDivElement>(null);
  const activeResponseRef = useRef<HTMLDivElement>(null);
  const [activeResponseId, setActiveResponseId] = useState<string | null>(null);
  const [shouldFollowLatest, setShouldFollowLatest] = useState(true);
  const accumulatedRef = useRef("");

  const storageKey = `shielddesk_chat_messages_${activeUserId}`;

  useEffect(() => {
    if (!isChatOpen) return;
    const launcher = launcherRef.current;
    returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : launcher;
    const frame = requestAnimationFrame(() => inputRef.current?.focus({ preventScroll: true }));
    return () => {
      cancelAnimationFrame(frame);
      const target = returnFocusRef.current?.isConnected ? returnFocusRef.current : launcher;
      target?.focus({ preventScroll: true });
    };
  }, [isChatOpen]);

  useEffect(() => {
    if (!isChatOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || document.querySelector("dialog[open]")) return;
      event.preventDefault();
      if (isRoleDropdownOpen) {
        setIsRoleDropdownOpen(false);
        personaButtonRef.current?.focus();
      } else {
        setIsChatOpen(false);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [isChatOpen, isRoleDropdownOpen, setIsChatOpen]);

  useEffect(() => {
    if (!isRoleDropdownOpen) return;
    personaMenuRef.current?.querySelector<HTMLElement>('[aria-checked="true"]')?.focus();
    const dismiss = (event: PointerEvent) => {
      if (event.target instanceof Node && !personaMenuRef.current?.contains(event.target) && !personaButtonRef.current?.contains(event.target)) {
        setIsRoleDropdownOpen(false);
      }
    };
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, [isRoleDropdownOpen]);

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
      behavior: reduceMotion ? "auto" : "smooth",
    });
  }, [activeResponseId, isChatOpen, reduceMotion]);

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
      behavior: reduceMotion ? "auto" : "smooth",
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

  // Roles that are permitted to use Simulate Blast Radius (mirrors cve.read in permissions.ts)
  const canSimulateBlastRadius = ["system_admin", "super_admin", "analyst", "responder", "user"].includes(
    activeUser.role
  );

  const dynamicSuggestions = activeIncidentId
    ? [
        `Investigate ${activeIncidentId}`,
        "What is the mitigation plan?",
        "What assets are affected?",
        ...(canSimulateBlastRadius ? ["Simulate Blast Radius for CVE-2025-38667"] : []),
        "Run a full Trivy vulnerability scan",
        "Show me todays critical incidents",
      ]
    : canSimulateBlastRadius
      ? [
          "Simulate Blast Radius for CVE-2025-38667",
          "Run a full Trivy vulnerability scan",
          ...DEFAULT_SUGGESTIONS,
        ]
      : DEFAULT_SUGGESTIONS;


  return (
    <>
      <button
        ref={launcherRef}
        type="button"
        onClick={() => setIsChatOpen(!isChatOpen)}
        className="sd-chat-chrome fixed bottom-5 right-5 z-[100] flex h-[52px] w-[52px] cursor-pointer items-center justify-center rounded-2xl border border-[var(--sd-border-strong)] bg-[var(--sd-pine)] text-[var(--sd-on-accent)] shadow-[0_8px_24px_rgba(0,0,0,0.28)] transition-colors duration-200 hover:bg-[var(--sd-wheat)] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--sd-pine)]"
        aria-label={isChatOpen ? "Close ShieldDesk Assistant" : "Open ShieldDesk Assistant"}
        aria-expanded={isChatOpen}
        aria-controls="shielddesk-assistant"
      >
        {isChatOpen ? <X className="h-5 w-5" /> : <ShieldCheck className="h-6 w-6" />}
      </button>

      <AnimatePresence>
        {isChatOpen && (
          <motion.section
            id="shielddesk-assistant"
            role="dialog"
            aria-modal="false"
            aria-labelledby="shielddesk-assistant-title"
            initial={{ opacity: 0, y: reduceMotion ? 0 : 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: reduceMotion ? 0 : 10 }}
            transition={{ duration: reduceMotion ? 0 : 0.2 }}
            className="sd-chat-chrome sd-glass-overlay fixed bottom-[88px] right-5 z-[100] flex h-[650px] max-h-[calc(100dvh-7rem)] w-[440px] max-w-[calc(100vw-2.5rem)] flex-col overflow-hidden rounded-[22px] border border-[var(--sd-border-strong)] text-[var(--sd-text)] font-sans"
          >
            <header className="shrink-0 border-b border-[var(--sd-border)] bg-[var(--sd-panel-raised)] px-5 py-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[var(--sd-border-strong)] bg-[var(--sd-panel-raised)] text-[var(--sd-pine)]">
                    <ShieldCheck className="h-5 w-5" />
                  </span>
                  <div className="min-w-0">
                    <h2 id="shielddesk-assistant-title" className="text-sm font-semibold tracking-tight">ShieldDesk Assistant</h2>
                    <p className="mt-0.5 truncate text-[11px] text-[var(--sd-text-muted)]">{activeUser.tenantName} · Mints Global</p>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <button type="button" onClick={clearChat} aria-label="Clear chat history" title="Clear chat history" className="sd-button sd-icon-button rounded-lg text-[var(--sd-text-muted)] hover:text-[var(--sd-danger)]">
                    <Trash2 className="h-4 w-4" />
                  </button>
                  <button type="button" onClick={() => setIsChatOpen(false)} aria-label="Close assistant" className="sd-button sd-icon-button rounded-lg text-[var(--sd-text-muted)]">
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>
              {process.env.NODE_ENV !== "production" && (
                <div className="relative mt-3 flex items-center justify-between gap-2 border-t border-[var(--sd-border)] pt-3">
                  <span className="text-[11px] text-[var(--sd-text-dim)]">Development persona</span>
                  <button
                    ref={personaButtonRef}
                    type="button"
                    aria-haspopup="menu"
                    aria-expanded={isRoleDropdownOpen}
                    aria-controls="assistant-persona-menu"
                    onClick={() => setIsRoleDropdownOpen((value) => !value)}
                    onKeyDown={(event) => {
                      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                        event.preventDefault();
                        setIsRoleDropdownOpen(true);
                      }
                    }}
                    className="sd-button flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-[11px] font-medium text-[var(--sd-pine)]"
                  >
                    {activeUser.label}<ChevronDown className="h-3.5 w-3.5" />
                  </button>
                  {isRoleDropdownOpen && (
                    <div
                      ref={personaMenuRef}
                      id="assistant-persona-menu"
                      role="menu"
                      aria-label="Development persona"
                      onBlur={(event) => {
                        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setIsRoleDropdownOpen(false);
                      }}
                      onKeyDown={(event) => {
                        const items = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="menuitemradio"]'));
                        const current = items.indexOf(document.activeElement as HTMLButtonElement);
                        let next = current;
                        if (event.key === "ArrowDown") next = (current + 1) % items.length;
                        else if (event.key === "ArrowUp") next = (current - 1 + items.length) % items.length;
                        else if (event.key === "Home") next = 0;
                        else if (event.key === "End") next = items.length - 1;
                        else return;
                        event.preventDefault();
                        items[next]?.focus();
                      }}
                      className="sd-glass-control absolute right-0 top-full z-50 mt-2 max-h-[min(24rem,calc(100dvh-18rem))] w-72 max-w-[calc(100vw-5rem)] overflow-y-auto overscroll-contain rounded-2xl border border-[var(--sd-border-strong)] p-1.5"
                    >
                      {Object.values(DEV_USERS).map((user) => (
                        <button
                          key={user.id}
                          type="button"
                          role="menuitemradio"
                          aria-checked={user.id === activeUserId}
                          tabIndex={-1}
                          onClick={() => {
                            setActiveUserId(user.id);
                            setIsRoleDropdownOpen(false);
                            personaButtonRef.current?.focus();
                          }}
                          className={cn("flex w-full cursor-pointer flex-col gap-1 rounded-xl px-3 py-2.5 text-left transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-[var(--sd-pine)]", user.id === activeUserId ? "bg-[var(--sd-panel-hover)] text-[var(--sd-pine)]" : "text-[var(--sd-text)] hover:bg-[var(--sd-panel-raised)]")}
                        >
                          <span className="flex w-full items-center justify-between gap-2 text-[13px] font-medium">
                            {user.label}<span className="text-[11px] font-normal text-[var(--sd-text-muted)]">{user.role === "system_admin" ? "Cross-Tenant" : user.tenantId}</span>
                          </span>
                          <span className="text-[11px] leading-relaxed text-[var(--sd-text-muted)]">{user.description}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </header>

            <div ref={messagesRef} onScroll={handleMessagesScroll} className="relative min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain p-5">
              {messages.length === 0 ? (
                <div className="flex min-h-full flex-col justify-center py-3">
                  <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-[var(--sd-border-strong)] bg-[var(--sd-panel-raised)] text-[var(--sd-pine)]"><Sparkles className="h-5 w-5" /></span>
                  <h3 className="text-xl font-medium tracking-tight">Your security co-pilot.</h3>
                  <p className="mt-2 max-w-[310px] text-[13px] leading-relaxed text-[var(--sd-text-muted)]">Investigate incidents, review exposure, and prepare your next action.</p>
                  <div className="mt-6 space-y-2">
                    <p className="mb-3 text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--sd-text-dim)]">Suggested inquiries</p>
                    {dynamicSuggestions.map((suggestion, index) => (
                      <button key={`${suggestion}-${index}`} type="button" onClick={() => sendMessage(suggestion)} className="sd-button group flex w-full items-center justify-between gap-3 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] px-3.5 py-3 text-left text-[13px] leading-relaxed text-[var(--sd-text)] hover:border-[var(--sd-border-strong)]">
                        <span>{suggestion}</span><Send className="h-3.5 w-3.5 shrink-0 text-[var(--sd-pine)]" />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <AnimatePresence initial={false}>
                  {messages.map((message) => (
                    <motion.div key={message.id} ref={message.id === activeResponseId ? activeResponseRef : undefined} initial={{ opacity: 0, y: reduceMotion ? 0 : 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: reduceMotion ? 0 : 0.18 }} className={cn("flex items-start gap-2", message.role === "user" && "flex-row-reverse")}>
                      <Avatar className="mt-0.5 h-7 w-7 shrink-0 rounded-lg border border-[var(--sd-border)]">
                        <AvatarFallback className="rounded-lg bg-[var(--sd-panel-raised)] text-[var(--sd-pine)]">{message.role === "assistant" ? <Bot className="h-4 w-4" /> : <UserIcon className="h-3.5 w-3.5" />}</AvatarFallback>
                      </Avatar>
                      <div className={cn("min-w-0 max-w-[calc(100%-2.25rem)] rounded-2xl border px-3.5 py-3 text-[13px] leading-relaxed", message.role === "user" ? "rounded-tr-md border-[var(--sd-border-strong)] bg-[var(--sd-panel-hover)] text-[var(--sd-text)]" : message.isError ? "rounded-tl-md border-[var(--sd-danger-border)] bg-[var(--sd-danger-dim)] text-[var(--sd-danger)]" : "rounded-tl-md border-[var(--sd-border)] bg-[var(--sd-panel-raised)] text-[var(--sd-text)]")}>
                        {message.role === "assistant" && !message.isError ? <FormattedAssistantMessage content={message.content} /> : <div className="whitespace-pre-wrap break-words">{message.content}</div>}
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}
              {isSending && (
                <div role="status" className="flex items-center gap-2.5 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-panel-raised)] px-3.5 py-3 text-[11px] text-[var(--sd-text-muted)]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--sd-pine)] motion-safe:animate-pulse" />Analyzing SOC telemetry…
                </div>
              )}
              {!shouldFollowLatest && messages.length > 0 && (
                <button type="button" onClick={scrollToLatest} className="sd-button sticky bottom-1 mx-auto flex items-center gap-1.5 rounded-full border border-[var(--sd-border-strong)] bg-[var(--sd-overlay)] px-3 py-2 text-[11px] text-[var(--sd-pine)]" aria-label="Jump to latest response"><ArrowDown className="h-3.5 w-3.5" />Jump to latest</button>
              )}
            </div>

            <form onSubmit={handleSubmit} className="shrink-0 border-t border-[var(--sd-border)] bg-[var(--sd-panel-raised)] p-4">
              <label htmlFor="assistant-message" className="sr-only">Message ShieldDesk Assistant</label>
              <div className="flex items-center gap-2">
                <input ref={inputRef} id="assistant-message" value={input} onChange={(event) => setInput(event.target.value)} placeholder="Ask about incidents, threats, CVEs, or mitigations…" maxLength={4000} disabled={isSending} className="sd-input h-11 min-w-0 flex-1 rounded-xl border border-[var(--sd-border)] bg-[var(--sd-bg)] px-3 text-[13px] text-[var(--sd-text)] placeholder:text-[var(--sd-text-muted)] disabled:opacity-50" />
                <button type="submit" disabled={isSending || !input.trim()} className="sd-button-primary flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-[var(--sd-on-accent)] disabled:cursor-not-allowed disabled:opacity-40" aria-label="Send message"><Send className="h-4 w-4" /></button>
              </div>
              <p className="mt-2.5 text-center text-[11px] text-[var(--sd-text-dim)]">Review recommendations before taking action.</p>
            </form>
          </motion.section>
        )}
      </AnimatePresence>
    </>
  );
}

export default ChatWidget;

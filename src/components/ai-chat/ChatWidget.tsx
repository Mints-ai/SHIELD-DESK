"use client";

import { useState, useRef, useEffect } from "react";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { ArrowDown, Bot, Send, User as UserIcon, ShieldHalf, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
// Session storage helpers (persisted only for the current tab)


interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  isError?: boolean;
}

const SUGGESTIONS = [
  "Show me today's critical incidents",
  "Investigate INC-1042",
  "Analyze CVE-2024-3400",
  "Generate a mitigation plan for INC-1042",
];

/**
 * DEV MODE: ShieldDesk doesn't have a real login system yet, so there's no
 * signed-in user to read an id from. This stands in for "whoever is using
 * the app right now" until real auth exists — swap this for a real user id
 * (and remove the hardcoded header below) once ShieldDesk has one. See
 * lib/auth/session.ts for the corresponding server-side note, and
 * db/seed.sql for the dev users this id can be set to (dev-analyst,
 * dev-admin, dev-other) to exercise different roles/tenants.
 */
const DEV_USER_ID = "dev-analyst";

/**
 * ShieldDesk AI Chat Widget — floating assistant, globally mounted
 * (see app/layout.tsx). Adapted from the Mints ERP assistant's
 * ChatWidget: same SSE-streaming, error/retry pattern, but fixed to
 * ShieldDesk's four supported intents instead of open-ended
 * employee/project/leave lookups, dev-mode identity instead of Firebase
 * (see DEV_USER_ID above), and without that app's GlobalTimer
 * positioning (ShieldDesk has no equivalent widget to sit above).
 */
export function ChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const messagesRef = useRef<HTMLDivElement>(null);
  const activeResponseRef = useRef<HTMLDivElement>(null);
  const [activeResponseId, setActiveResponseId] = useState<string | null>(null);
  const [shouldFollowLatest, setShouldFollowLatest] = useState(true);
  const accumulatedRef = useRef("");

  useEffect(() => {
    const messagesContainer = messagesRef.current;
    const activeResponse = activeResponseRef.current;
    if (!isOpen || !messagesContainer || !activeResponseId || !activeResponse) return;

    messagesContainer.scrollTo({
      top: Math.max(0, activeResponse.offsetTop - 16),
      behavior: "smooth",
    });
  }, [activeResponseId, isOpen]);




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

  const sendMessage = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;

    const userMsg: ChatMessage = { id: crypto.randomUUID(), role: "user", content: trimmed };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setShouldFollowLatest(true);
    setIsSending(true);

    try {
      const historyPayload = [...messages, userMsg].map((m) => ({ role: m.role, content: m.content }));
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ShieldDesk-User": DEV_USER_ID,
        },
        body: JSON.stringify({ message: trimmed, history: historyPayload }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.error || `Request failed (${res.status})`);
      }

      if (!res.body) throw new Error("Empty response from assistant.");

      const assistantId = crypto.randomUUID();
      setActiveResponseId(assistantId);
      setMessages((prev) => [...prev, { id: assistantId, role: "assistant", content: "" }]);

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
    } catch (err: unknown) {
      const messageText = err instanceof Error ? err.message : undefined;
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content:
            messageText === "Failed to fetch"
              ? "Couldn't reach the assistant. Please try again in a moment."
              : messageText || "Something went wrong. Please try again.",
          isError: true,
        },
      ]);
    } finally {
      setIsSending(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(input);
  };

  return (
    <>
      <button
        onClick={() => setIsOpen((v) => !v)}
        className={cn(
          "fixed bottom-5 right-5 z-[100] h-14 w-14 rounded-full shadow-lg flex items-center justify-center transition-all cursor-pointer",
          "bg-primary hover:scale-105 active:scale-95"
        )}
        aria-label={isOpen ? "Close ShieldDesk Assistant" : "Open ShieldDesk Assistant"}
      >
        <AnimatePresence mode="wait" initial={false}>
          {isOpen ? (
            <motion.span key="close" initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={{ duration: 0.15 }}>
              <X className="h-6 w-6 text-foreground" />
            </motion.span>
          ) : (
            <motion.span key="open" initial={{ rotate: 90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: -90, opacity: 0 }} transition={{ duration: 0.15 }}>
              <ShieldHalf className="h-6 w-6 text-foreground" />
            </motion.span>
          )}
        </AnimatePresence>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ duration: 0.18 }}
            className="fixed bottom-[calc(5rem+12px)] right-5 z-[100] w-[380px] max-w-[calc(100vw-3rem)] h-[520px] max-h-[calc(100vh-14rem)] rounded-2xl border border-border bg-[var(--sd-panel)] shadow-2xl flex flex-col overflow-hidden"
          >
            <div className="shrink-0 px-4 py-3 border-b border-border flex items-center gap-2">
              <ShieldHalf className="h-4 w-4 text-primary" />
              <span className="text-sm font-bold text-foreground">ShieldDesk Assistant</span>
            </div>

            <div
              ref={messagesRef}
              onScroll={handleMessagesScroll}
              className="relative flex-1 overflow-y-auto p-4 space-y-3 min-h-0"
            >
              {messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center gap-3 px-4">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                  <p className="text-xs text-foreground/40">
                    Ask about incidents, CVEs, or mitigation plans. I only
                    retrieve what your role is permitted to see.
                  </p>
                  <div className="flex flex-col gap-1.5 w-full">
                    {SUGGESTIONS.map((s) => (
                      <button
                        key={s}
                        onClick={() => sendMessage(s)}
                        className="px-3 py-2 rounded-lg border border-border text-[11px] text-foreground/70 hover:text-foreground hover:border-primary/30 transition-all text-left cursor-pointer"
                      >
                        {s}
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
                      <Avatar className="w-6 h-6 border border-border shrink-0 mt-0.5">
                        <AvatarFallback
                          className={cn(
                            "text-[10px] font-bold",
                            m.role === "assistant" ? "bg-primary/20 text-primary/80" : "bg-muted text-foreground/70"
                          )}
                        >
                          {m.role === "assistant" ? <Bot className="w-3 h-3" /> : <UserIcon className="w-3 h-3" />}
                        </AvatarFallback>
                      </Avatar>
                      <div
                        className={cn(
                          "max-w-[80%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap",
                          m.role === "user"
                            ? "bg-primary text-foreground rounded-tr-sm"
                            : m.isError
                              ? "bg-rose-950/40 border border-rose-500/20 text-rose-300 rounded-tl-sm"
                              : "border border-border text-foreground/90 rounded-tl-sm"
                        )}
                      >
                        {m.content}
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              )}

              {isSending && (
                <div className="flex items-start gap-2">
                  <Avatar className="w-6 h-6 border border-border shrink-0 mt-0.5">
                    <AvatarFallback className="bg-primary/20 text-primary/80">
                      <Bot className="w-3 h-3" />
                    </AvatarFallback>
                  </Avatar>
                  <div className="border border-border rounded-xl rounded-tl-sm px-3 py-2 flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-foreground/30 animate-bounce [animation-delay:-0.3s]" />
                    <span className="w-1 h-1 rounded-full bg-foreground/30 animate-bounce [animation-delay:-0.15s]" />
                    <span className="w-1 h-1 rounded-full bg-foreground/30 animate-bounce" />
                  </div>
                </div>
              )}

              {!shouldFollowLatest && messages.length > 0 && (
                <button
                  type="button"
                  onClick={scrollToLatest}
                  className="sticky bottom-0 mx-auto flex items-center gap-1 rounded-full border border-border bg-[var(--sd-panel)] px-2.5 py-1 text-[10px] text-foreground/70 shadow-md transition-colors hover:border-primary/40 hover:text-foreground"
                  aria-label="Jump to latest response"
                >
                  <ArrowDown className="h-3 w-3" />
                  Latest response
                </button>
              )}
            </div>

            <form onSubmit={handleSubmit} className="shrink-0 border-t border-border p-3 flex items-center gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about an incident, CVE, or mitigation plan..."
                maxLength={4000}
                disabled={isSending}
                className="flex-1 h-9 rounded-lg border border-border px-3 text-xs text-foreground placeholder:text-foreground/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary bg-background disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={isSending || !input.trim()}
                className="h-9 w-9 rounded-lg bg-primary hover:bg-primary disabled:opacity-40 text-foreground flex items-center justify-center transition-colors cursor-pointer shrink-0"
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

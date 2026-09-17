/**
 * Shared types for the ShieldDesk AI Chat Widget.
 * Kept intentionally small for Phase 0 — extended as later phases
 * (Gemini integration, tool calling, context-awareness) land.
 */

export type ChatRole = "user" | "assistant" | "system";

export type MessageStatus = "sent" | "pending" | "error";

export interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  createdAt: string; // ISO timestamp
  status?: MessageStatus;
}

export interface ChatContext {
  /** Which ShieldDesk page the user is currently on (wired up in Phase 6). */
  page?: "dashboard" | "incident" | "cve" | "mitigation" | "asset";
  incidentId?: string;
  cveId?: string;
  planId?: string;
  assetId?: string;
}

export interface ChatRequestBody {
  message: string;
  conversationId?: string;
  context?: ChatContext;
}

export interface ChatResponseBody {
  message: string;
  conversationId: string;
}

export interface ChatErrorBody {
  error: string;
}

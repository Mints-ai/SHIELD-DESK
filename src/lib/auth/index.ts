import "server-only";

/**
 * Authentication / identity layer.
 *
 * Real verification now lives in lib/auth/session.ts
 * (getSessionFromRequest) — it verifies the Firebase ID token and resolves
 * the caller's ShieldDesk role + tenant from Postgres. This file re-exports
 * the session type for convenience; new code should import
 * getSessionFromRequest directly.
 *
 * Prompt instructions are not an authorization mechanism — Gemini never
 * decides permissions. Session resolution + the RBAC checks in
 * lib/permissions.ts are the only source of truth for "who is this" and
 * "what can they do."
 */
export type { ChatSession as AuthenticatedUser } from "@/lib/auth/session";
export { getSessionFromRequest } from "@/lib/auth/session";

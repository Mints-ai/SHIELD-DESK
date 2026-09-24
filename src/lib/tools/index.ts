import "server-only";

/**
 * Tool Gateway entry point. The allow-listed tools themselves now live in
 * shieldDeskChatTools.ts (CHAT_TOOLS + the 4 implementations). This file
 * re-exports them so `@/lib/tools` stays the stable import path.
 */
export {
  CHAT_TOOLS,
  getIncidents,
  investigateIncident,
  analyzeCve,
  generateMitigationPlan,
  simulateBlastRadius,
  getMitigationPlan,
  type ChatSession,
} from "./shieldDeskChatTools";


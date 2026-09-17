import "server-only";
import OpenAI from "openai";

/**
 * Server-side LLM client — a local Ollama instance, via its
 * OpenAI-compatible endpoint. Nothing here ever leaves your own
 * infrastructure: unlike a cloud API, incident/CVE text sent as part of
 * a chat request never crosses to a third-party vendor.
 *
 * Requires Ollama running locally (or on a host you control) with a
 * tool-calling-capable model pulled, e.g.:
 *   ollama pull qwen3:4b
 *   ollama serve
 *
 * SECURITY: this module must never be imported from a client component —
 * `server-only` enforces that at build time. There's no API key to leak
 * here (Ollama's OpenAI-compatible endpoint doesn't require one locally),
 * but keeping the client construction server-side also keeps
 * OLLAMA_BASE_URL from being something the browser could redirect.
 */

const baseURL = process.env.OLLAMA_BASE_URL || "http://localhost:11434/v1";

export const ollama = new OpenAI({
  baseURL,
  apiKey: "ollama", // required by the SDK's shape; Ollama ignores it locally
});

export const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "qwen3:4b-instruct-2507-q4_K_M";

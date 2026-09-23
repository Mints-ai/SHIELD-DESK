/**
 * ShieldDesk Universal Data Protection & Redaction Engine
 * Redacts secrets, credentials, tokens, and private keys from outgoing text and logs.
 */

const SECRET_PATTERNS = [
  // Generic password/secret assignments
  /(password|passwd|secret|api_key|access_token)\s*[:=]\s*["']?[^\s"';]{6,}["']?/gi,
  // AWS Access Key ID
  /AKIA[0-9A-Z]{16}/g,
  // GitHub Personal Access Token
  /ghp_[a-zA-Z0-9]{36}/g,
  // JWT Token string
  /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
  // PEM Private Key Block
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  // Credit Card Numbers (13-16 digits with hyphen/space)
  /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
  // US SSN
  /\b\d{3}-\d{2}-\d{4}\b/g,
];

export function redactSensitiveData(text: string): string {
  if (!text || typeof text !== "string") return "";

  let cleaned = text;
  for (const pattern of SECRET_PATTERNS) {
    cleaned = cleaned.replace(pattern, "[REDACTED_SECRET]");
  }
  return cleaned;
}

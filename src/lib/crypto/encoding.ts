/**
 * ShieldDesk Shared Cryptographic & URL Encoding Utilities
 *
 * Centralizes binary/string conversions, base64url encoding, and decoding
 * to prevent duplicate implementations across authentication, tokens, and license engines.
 */

export function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return buf.toString("base64url");
}

export function base64UrlDecode(str: string): string {
  return Buffer.from(str, "base64url").toString("utf8");
}

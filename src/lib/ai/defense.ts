import crypto from "node:crypto";

export class PromptInjectionGuard {
  private static INJECTION_PATTERNS: RegExp[] = [
    /ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|directions)/i,
    /disregard\s+(all\s+)?(previous|prior)\s+(instructions|directives)/i,
    /you\s+are\s+now\s+(in\s+)?(developer\s+mode|dan\s+mode|jailbreak|unrestricted)/i,
    /system\s+prompt\s+override/i,
    /\[system\]/i,
    /<system>/i,
    /\|\s*system\s*\|/i,
    /bypass\s+all\s+(security|authorization|safety)\s+filters/i,
    /dump\s+(all\s+)?(passwords|api\s+keys|private\s+keys|tokens|secret)/i,
    /curl\s+http[s]?:\/\/[^\s]+/i,
    /powershell\s+(-enc|-encodedcommand)/i,
    /rm\s+-rf\s+\//i,
  ];

  /**
   * Scans untrusted input for prompt injection and adversarial manipulation attempts.
   */
  public static detectInjection(input: string): { isSuspicious: boolean; reason?: string; match?: string } {
    if (!input || typeof input !== "string") {
      return { isSuspicious: false };
    }

    for (const pattern of this.INJECTION_PATTERNS) {
      const match = input.match(pattern);
      if (match) {
        return {
          isSuspicious: true,
          reason: `Potential prompt injection attack detected matching pattern: ${pattern.source}`,
          match: match[0],
        };
      }
    }

    return { isSuspicious: false };
  }

  /**
   * Asserts that external strings (SIEM events, logs, telemetry, usernames, process commands)
   * do not contain overt adversarial injection payloads. Throws if hostile payload detected.
   */
  public static assertSafe(input: string, contextLabel = "security_telemetry"): void {
    const result = this.detectInjection(input);
    if (result.isSuspicious) {
      throw new Error(
        `Prompt Injection Defense Violation in [${contextLabel}]: ${result.reason} (Sample: "${result.match}")`
      );
    }
  }

  /**
   * Enforces delimiter isolation and context tagging for untrusted data.
   * Prevents untrusted data from escaping into LLM instruction scope.
   */
  public static wrapUntrustedData(data: string, label: string): string {
    // Escape XML/HTML tags that could attempt to close the untrusted boundary
    const escaped = data
      .replace(/<\/untrusted_context>/gi, "&lt;/untrusted_context&gt;")
      .replace(/<system>/gi, "&lt;system&gt;")
      .replace(/<\/system>/gi, "&lt;/system&gt;");

    const nonce = crypto.randomBytes(4).toString("hex");

    return `<untrusted_context label="${label}" nonce="${nonce}">\n${escaped}\n</untrusted_context>`;
  }

  /**
   * Strips known prompt injection attempts from raw logs while preserving operational telemetry.
   */
  public static sanitizeString(input: string): string {
    let sanitized = input;
    for (const pattern of this.INJECTION_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[BLOCKED_ADVERSARIAL_INSTRUCTION]");
    }
    return sanitized;
  }
}

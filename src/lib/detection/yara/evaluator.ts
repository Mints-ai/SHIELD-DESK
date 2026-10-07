import {
  YaraRuleAst,
  YaraStringDef,
  YaraConditionNode,
  YaraMatchResult,
  YaraStringMatch,
} from "./types";

export interface YaraEvaluationOptions {
  timeoutMs?: number; // Default 50ms
  maxMatchesPerString?: number; // Default 10
}

export function evaluateYaraRule(
  ruleAst: YaraRuleAst,
  payloadInput: string | Buffer | Uint8Array,
  options: YaraEvaluationOptions = {}
): YaraMatchResult {
  const startTime = performance.now();
  const timeoutMs = options.timeoutMs ?? 50;
  const maxMatches = options.maxMatchesPerString ?? 10;

  const ruleId = String(ruleAst.meta?.id || ruleAst.name);
  const ruleName = ruleAst.name;
  const category = String(ruleAst.meta?.category || "Malware");
  const severity = (ruleAst.meta?.severity as "critical" | "high" | "medium" | "low") || "medium";

  // Convert payload to string representation and buffer representation
  let payloadStr: string;
  let payloadBuf: Buffer;

  if (Buffer.isBuffer(payloadInput)) {
    payloadBuf = payloadInput;
    payloadStr = payloadBuf.toString("utf-8");
  } else if (payloadInput instanceof Uint8Array) {
    payloadBuf = Buffer.from(payloadInput);
    payloadStr = payloadBuf.toString("utf-8");
  } else {
    payloadStr = String(payloadInput);
    payloadBuf = Buffer.from(payloadStr, "utf-8");
  }

  const allMatches: YaraStringMatch[] = [];
  const matchesByStringId = new Map<string, YaraStringMatch[]>();

  try {
    // 1. Scan strings
    for (const strDef of ruleAst.strings) {
      if (performance.now() - startTime > timeoutMs) {
        return {
          matched: false,
          ruleId,
          ruleName,
          category,
          severity,
          matches: [],
          executionTimeMs: performance.now() - startTime,
          error: `Execution timeout exceeded (max ${timeoutMs}ms)`,
        };
      }

      const matches = findStringMatches(strDef, payloadStr, payloadBuf, maxMatches, startTime, timeoutMs);
      matchesByStringId.set(strDef.id, matches);
      allMatches.push(...matches);
    }

    // 2. Evaluate condition
    const isMatched = evalCondition(ruleAst.condition, ruleAst.strings, matchesByStringId);
    const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

    return {
      matched: isMatched,
      ruleId,
      ruleName,
      category,
      severity,
      matches: isMatched ? allMatches : [],
      executionTimeMs,
    };
  } catch (err: unknown) {
    return {
      matched: false,
      ruleId,
      ruleName,
      category,
      severity,
      matches: [],
      executionTimeMs: Number((performance.now() - startTime).toFixed(2)),
      error: err instanceof Error ? err.message : "Error during YARA evaluation",
    };
  }
}

function findStringMatches(
  def: YaraStringDef,
  payloadStr: string,
  payloadBuf: Buffer,
  maxMatches: number,
  startTime: number,
  timeoutMs: number
): YaraStringMatch[] {
  const matches: YaraStringMatch[] = [];

  if (def.type === "text") {
    const patternsToSearch: Array<{ pattern: string; isWide?: boolean }> = [];
    patternsToSearch.push({ pattern: def.value, isWide: false });

    if (def.modifiers.wide) {
      // Create UTF-16LE sequence
      patternsToSearch.push({ pattern: def.value, isWide: true });
    }

    for (const item of patternsToSearch) {
      if (item.isWide) {
        // Search in buffer for wide string
        const wideMatches = searchWideInBuffer(
          def.id,
          item.pattern,
          payloadBuf,
          def.modifiers.nocase,
          maxMatches - matches.length,
          startTime,
          timeoutMs
        );
        matches.push(...wideMatches);
      } else {
        const textMatches = searchTextInString(
          def.id,
          item.pattern,
          payloadStr,
          def.modifiers,
          maxMatches - matches.length,
          startTime,
          timeoutMs
        );
        matches.push(...textMatches);
      }
      if (matches.length >= maxMatches) break;
    }
  } else if (def.type === "hex") {
    const hexMatches = searchHexInBuffer(
      def.id,
      def.value,
      payloadBuf,
      payloadStr,
      maxMatches,
      startTime,
      timeoutMs
    );
    matches.push(...hexMatches);
  } else if (def.type === "regex") {
    const regexMatches = searchRegexInString(
      def.id,
      def.value,
      payloadStr,
      def.modifiers,
      maxMatches,
      startTime,
      timeoutMs
    );
    matches.push(...regexMatches);
  }

  return matches;
}

function searchTextInString(
  id: string,
  pattern: string,
  haystack: string,
  modifiers: YaraStringDef["modifiers"],
  maxNeeded: number,
  startTime: number,
  timeoutMs: number
): YaraStringMatch[] {
  const results: YaraStringMatch[] = [];
  if (!pattern || maxNeeded <= 0) return results;

  const targetHaystack = modifiers.nocase ? haystack.toLowerCase() : haystack;
  const targetPattern = modifiers.nocase ? pattern.toLowerCase() : pattern;

  let pos = 0;
  while ((pos = targetHaystack.indexOf(targetPattern, pos)) !== -1) {
    if (performance.now() - startTime > timeoutMs) {
      throw new Error(`Execution timeout exceeded (max ${timeoutMs}ms)`);
    }

    // Check fullword modifier
    if (modifiers.fullword) {
      const charBefore = pos > 0 ? targetHaystack[pos - 1] : " ";
      const charAfter =
        pos + targetPattern.length < targetHaystack.length
          ? targetHaystack[pos + targetPattern.length]
          : " ";
      const isWordBefore = /[a-zA-Z0-9_]/.test(charBefore);
      const isWordAfter = /[a-zA-Z0-9_]/.test(charAfter);
      if (isWordBefore || isWordAfter) {
        pos += targetPattern.length || 1;
        continue;
      }
    }

    const matchedValue = haystack.slice(pos, pos + pattern.length);
    const snippet = createSnippet(haystack, pos, pattern.length);

    results.push({
      id,
      offset: pos,
      length: pattern.length,
      snippet,
      matchedValue,
    });

    if (results.length >= maxNeeded) break;
    pos += pattern.length || 1;
  }

  return results;
}

function searchWideInBuffer(
  id: string,
  pattern: string,
  buffer: Buffer,
  nocase: boolean | undefined,
  maxNeeded: number,
  startTime: number,
  timeoutMs: number
): YaraStringMatch[] {
  const results: YaraStringMatch[] = [];
  if (!pattern || maxNeeded <= 0) return results;

  // UTF-16LE encoding of pattern
  const needle = Buffer.from(pattern, "utf16le");
  if (nocase) {
    // Perform byte search with case-folding
    const needleLower = Buffer.from(pattern.toLowerCase(), "utf16le");
    for (let i = 0; i <= buffer.length - needle.length; i += 2) {
      if (performance.now() - startTime > timeoutMs) {
        throw new Error(`Execution timeout exceeded (max ${timeoutMs}ms)`);
      }

      let match = true;
      for (let j = 0; j < needle.length; j += 2) {
        const bChar = String.fromCharCode(buffer[i + j] | (buffer[i + j + 1] << 8)).toLowerCase();
        const nChar = String.fromCharCode(
          needleLower[j] | (needleLower[j + 1] << 8)
        );
        if (bChar !== nChar) {
          match = false;
          break;
        }
      }

      if (match) {
        const snippet = createSnippet(buffer.toString("latin1"), i, needle.length);
        results.push({
          id,
          offset: i,
          length: needle.length,
          snippet,
          matchedValue: pattern,
        });
        if (results.length >= maxNeeded) break;
      }
    }
  } else {
    let pos = 0;
    while ((pos = buffer.indexOf(needle, pos)) !== -1) {
      if (performance.now() - startTime > timeoutMs) {
        throw new Error(`Execution timeout exceeded (max ${timeoutMs}ms)`);
      }

      const snippet = createSnippet(buffer.toString("latin1"), pos, needle.length);
      results.push({
        id,
        offset: pos,
        length: needle.length,
        snippet,
        matchedValue: pattern,
      });

      if (results.length >= maxNeeded) break;
      pos += needle.length || 1;
    }
  }

  return results;
}

function searchHexInBuffer(
  id: string,
  hexStr: string,
  buffer: Buffer,
  haystackStr: string,
  maxNeeded: number,
  startTime: number,
  timeoutMs: number
): YaraStringMatch[] {
  const results: YaraStringMatch[] = [];
  // Parse hex sequence, e.g. "4D 5A 90 00" or with wildcards "??"
  const cleanedTokens = hexStr.trim().split(/\s+/).filter(Boolean);
  if (cleanedTokens.length === 0) return results;

  const byteSequence: Array<number | null> = cleanedTokens.map((tok) => {
    if (tok === "??" || tok === "?") return null;
    return parseInt(tok, 16);
  });

  const seqLen = byteSequence.length;
  for (let i = 0; i <= buffer.length - seqLen; i++) {
    if (performance.now() - startTime > timeoutMs) {
      throw new Error(`Execution timeout exceeded (max ${timeoutMs}ms)`);
    }

    let match = true;
    for (let j = 0; j < seqLen; j++) {
      const expected = byteSequence[j];
      if (expected !== null && buffer[i + j] !== expected) {
        match = false;
        break;
      }
    }

    if (match) {
      const snippet = createSnippet(haystackStr, i, seqLen);
      const hexMatched = buffer.subarray(i, i + seqLen).toString("hex").toUpperCase();
      results.push({
        id,
        offset: i,
        length: seqLen,
        snippet,
        matchedValue: hexMatched,
      });
      if (results.length >= maxNeeded) break;
    }
  }

  return results;
}

function searchRegexInString(
  id: string,
  regexPattern: string,
  haystack: string,
  modifiers: YaraStringDef["modifiers"],
  maxNeeded: number,
  startTime: number,
  timeoutMs: number
): YaraStringMatch[] {
  const results: YaraStringMatch[] = [];
  try {
    const flags = modifiers.nocase ? "gi" : "g";
    const re = new RegExp(regexPattern, flags);

    let match: RegExpExecArray | null;
    while ((match = re.exec(haystack)) !== null) {
      if (performance.now() - startTime > timeoutMs) {
        throw new Error(`Execution timeout exceeded (max ${timeoutMs}ms)`);
      }

      const offset = match.index;
      const matchedStr = match[0];
      const snippet = createSnippet(haystack, offset, matchedStr.length);

      results.push({
        id,
        offset,
        length: matchedStr.length,
        snippet,
        matchedValue: matchedStr,
      });

      if (results.length >= maxNeeded) break;
      if (re.lastIndex === offset) re.lastIndex++; // Prevent infinite loop on empty match
    }
  } catch {
    // Non-fatal regex compile error
  }

  return results;
}

function createSnippet(text: string, offset: number, length: number): string {
  const pad = 24;
  const start = Math.max(0, offset - pad);
  const end = Math.min(text.length, offset + length + pad);
  let snippet = text.slice(start, end);
  // Sanitize non-printable characters for safe JSON & display
  snippet = snippet.replace(/[\x00-\x1F\x7F-\x9F]/g, ".");
  if (start > 0) snippet = "..." + snippet;
  if (end < text.length) snippet = snippet + "...";
  return snippet;
}

function evalCondition(
  node: YaraConditionNode,
  allStrings: YaraStringDef[],
  matchesMap: Map<string, YaraStringMatch[]>
): boolean {
  switch (node.type) {
    case "identifier": {
      const list = matchesMap.get(node.value);
      return Boolean(list && list.length > 0);
    }
    case "wildcard": {
      const prefix = node.value.replace(/\*$/, "");
      return allStrings.some((s) => s.id.startsWith(prefix) && (matchesMap.get(s.id)?.length || 0) > 0);
    }
    case "literal": {
      return typeof node.value === "boolean" ? node.value : node.value > 0;
    }
    case "not": {
      return !evalCondition(node.operand, allStrings, matchesMap);
    }
    case "binary": {
      const leftVal = evalCondition(node.left, allStrings, matchesMap);
      if (node.operator === "and") {
        if (!leftVal) return false;
        return evalCondition(node.right, allStrings, matchesMap);
      } else {
        if (leftVal) return true;
        return evalCondition(node.right, allStrings, matchesMap);
      }
    }
    case "quantifier": {
      // Determine candidate string IDs
      let candidateIds: string[] = [];
      if (node.target === "them") {
        candidateIds = allStrings.map((s) => s.id);
      } else if (Array.isArray(node.target)) {
        candidateIds = node.target;
      } else if (node.target && typeof node.target === "object" && node.target.type === "wildcard") {
        const prefix = node.target.value.replace(/\*$/, "");
        candidateIds = allStrings.filter((s) => s.id.startsWith(prefix)).map((s) => s.id);
      }

      const matchedCount = candidateIds.filter((id) => (matchesMap.get(id)?.length || 0) > 0).length;

      if (node.quantifier === "any") {
        return matchedCount >= 1;
      } else if (node.quantifier === "all") {
        return candidateIds.length > 0 && matchedCount === candidateIds.length;
      } else if (typeof node.quantifier === "number") {
        return matchedCount >= node.quantifier;
      }
      return false;
    }
    default:
      return false;
  }
}

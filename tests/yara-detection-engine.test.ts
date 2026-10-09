import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { parseYaraRule } from "@/lib/detection/yara/parser";
import { evaluateYaraRule } from "@/lib/detection/yara/evaluator";

test("SD-027: Native YARA Malware Rules & Lexer/Parser AST Engine Suite", async (t) => {
  await t.test("Parser: Correctly parses valid YARA rule with meta, strings, modifiers, and condition", () => {
    const rawRule = `
      rule WebShell_PHP_Sample : webshell trojan {
        meta:
          id = "YARA-TEST-001"
          description = "Test rule for webshell detection"
          severity = "critical"
          category = "Webshell"
          author = "SOC Team"
        strings:
          $s1 = "c99shell" nocase
          $s2 = "passthru($_POST" nocase
          $s3 = "eval(base64_decode" ascii
          $s4 = { 4D 5A 90 00 }
        condition:
          any of ($s*)
      }
    `;

    const res = parseYaraRule(rawRule);
    assert.strictEqual(res.success, true);
    assert.ok(res.ast);
    assert.strictEqual(res.ast.name, "WebShell_PHP_Sample");
    assert.deepStrictEqual(res.ast.tags, ["webshell", "trojan"]);
    assert.strictEqual(res.ast.meta.id, "YARA-TEST-001");
    assert.strictEqual(res.ast.meta.severity, "critical");
    assert.strictEqual(res.ast.strings.length, 4);

    const s1 = res.ast.strings.find((s) => s.id === "$s1");
    assert.ok(s1);
    assert.strictEqual(s1.type, "text");
    assert.strictEqual(s1.value, "c99shell");
    assert.strictEqual(s1.modifiers.nocase, true);

    const s4 = res.ast.strings.find((s) => s.id === "$s4");
    assert.ok(s4);
    assert.strictEqual(s4.type, "hex");
    assert.strictEqual(s4.value, "4D 5A 90 00");

    assert.strictEqual(res.ast.condition.type, "quantifier");
  });

  await t.test("Parser: Returns clear diagnostic line and column numbers on syntax error", () => {
    // Missing closing brace or invalid syntax
    const badRule = `
      rule Broken_Rule {
        meta:
          id = "TEST"
        strings:
          $s1 = "valid"
        condition
          any of them
      }
    `;

    const res = parseYaraRule(badRule);
    assert.strictEqual(res.success, false);
    assert.ok(res.error);
    assert.ok(typeof res.error.line === "number");
    assert.ok(typeof res.error.column === "number");
    assert.ok(res.error.message.length > 0);
  });

  await t.test("Evaluator: String modifiers (nocase, ascii, fullword, and wide)", () => {
    const ruleRaw = `
      rule Test_Modifiers {
        strings:
          $nocase = "MALICIOUS" nocase
          $word = "cmd" fullword
        condition:
          $nocase and $word
      }
    `;

    const parsed = parseYaraRule(ruleRaw);
    assert.strictEqual(parsed.success, true);
    assert.ok(parsed.ast);

    // Positive: case mismatch and word boundary
    const positivePayload = "Detected malicious code in cmd /c echo 1";
    const posRes = evaluateYaraRule(parsed.ast, positivePayload);
    assert.strictEqual(posRes.matched, true);
    assert.strictEqual(posRes.matches.length >= 2, true);

    // Negative: fullword boundary fails (e.g. "command" contains "cmd" but is not a fullword)
    const negativePayload = "Detected malicious code in command /c echo 1";
    const negRes = evaluateYaraRule(parsed.ast, negativePayload);
    assert.strictEqual(negRes.matched, false);
  });

  await t.test("Evaluator: Wide string search (UTF-16LE byte sequences)", () => {
    const ruleRaw = `
      rule Test_Wide {
        strings:
          $w = "Mimikatz" wide
        condition:
          $w
      }
    `;
    const parsed = parseYaraRule(ruleRaw);
    assert.strictEqual(parsed.success, true);
    assert.ok(parsed.ast);

    // Buffer encoded as UTF-16LE
    const utf16Buf = Buffer.from("Process memory: Mimikatz injection", "utf16le");
    const res = evaluateYaraRule(parsed.ast, utf16Buf);
    assert.strictEqual(res.matched, true);
    assert.strictEqual(res.matches[0].id, "$w");
  });

  await t.test("Evaluator: Hex byte sequence matching", () => {
    const ruleRaw = `
      rule Test_Hex {
        strings:
          $mz = { 4D 5A 90 00 }
        condition:
          $mz
      }
    `;
    const parsed = parseYaraRule(ruleRaw);
    assert.strictEqual(parsed.success, true);
    assert.ok(parsed.ast);

    const payload = Buffer.from([0x00, 0x4D, 0x5A, 0x90, 0x00, 0xFF]);
    const res = evaluateYaraRule(parsed.ast, payload);
    assert.strictEqual(res.matched, true);
    assert.strictEqual(res.matches[0].matchedValue, "4D5A9000");
  });

  await t.test("Evaluator: Complex condition logic (quantifiers, and, or, not)", () => {
    const ruleRaw = `
      rule Complex_Conditions {
        strings:
          $a = "indicator_a"
          $b = "indicator_b"
          $c = "indicator_c"
          $safe = "benign_whitelist"
        condition:
          2 of ($a, $b, $c) and not $safe
      }
    `;
    const parsed = parseYaraRule(ruleRaw);
    assert.strictEqual(parsed.success, true);
    assert.ok(parsed.ast);

    // 2 of ($a, $b, $c) present, no $safe -> MATCH
    const res1 = evaluateYaraRule(parsed.ast, "Found indicator_a and indicator_b here");
    assert.strictEqual(res1.matched, true);

    // Only 1 of them -> NO MATCH
    const res2 = evaluateYaraRule(parsed.ast, "Found only indicator_a here");
    assert.strictEqual(res2.matched, false);

    // 2 present BUT whitelist keyword present -> NO MATCH
    const res3 = evaluateYaraRule(parsed.ast, "Found indicator_a and indicator_b with benign_whitelist");
    assert.strictEqual(res3.matched, false);
  });

  await t.test("Evaluator Safety: Respects execution timeout boundary (<50ms)", () => {
    const ruleRaw = `
      rule Safety_Timeout_Test {
        strings:
          $s1 = "needle"
        condition:
          any of them
      }
    `;
    const parsed = parseYaraRule(ruleRaw);
    assert.strictEqual(parsed.success, true);
    assert.ok(parsed.ast);

    // Evaluate against medium payload with very small timeoutMs (0ms / 1ms)
    const bigHaystack = "A".repeat(500000);
    const start = performance.now();
    const res = evaluateYaraRule(parsed.ast, bigHaystack, { timeoutMs: 1 });
    const elapsed = performance.now() - start;

    // Must return within safety boundary and not hang
    assert.ok(elapsed < 100);
    assert.strictEqual(res.matched, false);
  });
});

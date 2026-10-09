import {
  YaraRuleAst,
  YaraStringDef,
  YaraConditionNode,
  YaraStringModifier,
  YaraParseResult,
} from "./types";

interface Token {
  type:
    | "RULE"
    | "IDENTIFIER"
    | "STRING_ID" // starts with $
    | "STRING_LITERAL"
    | "HEX_LITERAL"
    | "REGEX_LITERAL"
    | "NUMBER"
    | "LBRACE"
    | "RBRACE"
    | "LPAREN"
    | "RPAREN"
    | "EQUALS"
    | "COLON"
    | "COMMA"
    | "META"
    | "STRINGS"
    | "CONDITION"
    | "AND"
    | "OR"
    | "NOT"
    | "ANY"
    | "ALL"
    | "OF"
    | "THEM"
    | "MODIFIER" // nocase, wide, ascii, fullword
    | "BOOLEAN"
    | "EOF";
  value: string;
  line: number;
  column: number;
}

export function parseYaraRule(raw: string): YaraParseResult {
  if (!raw || !raw.trim()) {
    return {
      success: false,
      error: { line: 1, column: 1, message: "Empty YARA rule content" },
    };
  }

  try {
    const tokens = tokenize(raw);
    const parser = new YaraParser(tokens, raw);
    const ast = parser.parse();
    return { success: true, ast };
  } catch (err: unknown) {
    if (
      err &&
      typeof err === "object" &&
      "line" in err &&
      "column" in err &&
      "message" in err
    ) {
      return {
        success: false,
        error: {
          line: Number((err as { line: unknown }).line),
          column: Number((err as { column: unknown }).column),
          message: String((err as { message: unknown }).message),
        },
      };
    }
    return {
      success: false,
      error: {
        line: 1,
        column: 1,
        message: err instanceof Error ? err.message : "Unknown syntax error in YARA rule",
      },
    };
  }
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  while (i < input.length) {
    const char = input[i];

    // Newline tracking
    if (char === "\n") {
      line++;
      col = 1;
      i++;
      continue;
    }

    // Skip whitespace
    if (char === " " || char === "\t" || char === "\r") {
      col++;
      i++;
      continue;
    }

    // Line comment //
    if (char === "/" && input[i + 1] === "/") {
      while (i < input.length && input[i] !== "\n") {
        i++;
      }
      continue;
    }

    // Block comment /* ... */
    if (char === "/" && input[i + 1] === "*") {
      const startLine = line;
      const startCol = col;
      i += 2;
      col += 2;
      let closed = false;
      while (i < input.length) {
        if (input[i] === "\n") {
          line++;
          col = 1;
          i++;
        } else if (input[i] === "*" && input[i + 1] === "/") {
          i += 2;
          col += 2;
          closed = true;
          break;
        } else {
          i++;
          col++;
        }
      }
      if (!closed) {
        throw { line: startLine, column: startCol, message: "Unterminated block comment" };
      }
      continue;
    }

    // String identifier: starts with $
    if (char === "$") {
      const startCol = col;
      const startLine = line;
      let val = "$";
      i++;
      col++;
      while (i < input.length && /[a-zA-Z0-9_*]/.test(input[i])) {
        val += input[i];
        i++;
        col++;
      }
      tokens.push({ type: "STRING_ID", value: val, line: startLine, column: startCol });
      continue;
    }

    // String literal: starts with "
    if (char === '"') {
      const startCol = col;
      const startLine = line;
      let val = "";
      i++;
      col++;
      let closed = false;
      while (i < input.length) {
        if (input[i] === "\\") {
          // Escape
          if (i + 1 < input.length) {
            val += input[i + 1];
            i += 2;
            col += 2;
            continue;
          }
        }
        if (input[i] === '"') {
          i++;
          col++;
          closed = true;
          break;
        }
        if (input[i] === "\n") {
          line++;
          col = 1;
        } else {
          col++;
        }
        val += input[i];
        i++;
      }
      if (!closed) {
        throw { line: startLine, column: startCol, message: "Unterminated string literal" };
      }
      tokens.push({ type: "STRING_LITERAL", value: val, line: startLine, column: startCol });
      continue;
    }

    // Hex sequence: starts with { after '=' in strings definition
    const prevTokenType = tokens[tokens.length - 1]?.type;
    if (char === "{" && prevTokenType === "EQUALS") {
      const startCol = col;
      const startLine = line;
      let val = "";
      i++;
      col++;
      let closed = false;
      while (i < input.length) {
        if (input[i] === "}") {
          i++;
          col++;
          closed = true;
          break;
        }
        if (input[i] === "\n") {
          line++;
          col = 1;
        } else {
          col++;
        }
        val += input[i];
        i++;
      }
      if (!closed) {
        throw { line: startLine, column: startCol, message: "Unterminated hex sequence" };
      }
      tokens.push({ type: "HEX_LITERAL", value: val.trim(), line: startLine, column: startCol });
      continue;
    }

    // Regex literal: /.../
    // Distinguish from division or comment if preceding token was an operand
    const prevType = tokens[tokens.length - 1]?.type;
    const canBeRegex =
      char === "/" &&
      (!prevType ||
        prevType === "EQUALS" ||
        prevType === "LPAREN" ||
        prevType === "CONDITION" ||
        prevType === "STRINGS" ||
        prevType === "AND" ||
        prevType === "OR" ||
        prevType === "NOT");

    if (canBeRegex) {
      const startCol = col;
      const startLine = line;
      let val = "";
      i++;
      col++;
      let closed = false;
      while (i < input.length) {
        if (input[i] === "\\") {
          if (i + 1 < input.length) {
            val += "\\" + input[i + 1];
            i += 2;
            col += 2;
            continue;
          }
        }
        if (input[i] === "/") {
          i++;
          col++;
          closed = true;
          break;
        }
        if (input[i] === "\n") {
          line++;
          col = 1;
        } else {
          col++;
        }
        val += input[i];
        i++;
      }
      if (!closed) {
        throw { line: startLine, column: startCol, message: "Unterminated regular expression" };
      }
      tokens.push({ type: "REGEX_LITERAL", value: val, line: startLine, column: startCol });
      continue;
    }

    // Single character punctuation
    if (char === "{") {
      tokens.push({ type: "LBRACE", value: "{", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "RBRACE", value: "}", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === "(") {
      tokens.push({ type: "LPAREN", value: "(", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === ")") {
      tokens.push({ type: "RPAREN", value: ")", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === "=") {
      tokens.push({ type: "EQUALS", value: "=", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === ":") {
      tokens.push({ type: "COLON", value: ":", line, column: col });
      i++;
      col++;
      continue;
    }
    if (char === ",") {
      tokens.push({ type: "COMMA", value: ",", line, column: col });
      i++;
      col++;
      continue;
    }

    // Numbers
    if (/[0-9]/.test(char)) {
      const startCol = col;
      const startLine = line;
      let num = "";
      while (i < input.length && /[0-9]/.test(input[i])) {
        num += input[i];
        i++;
        col++;
      }
      tokens.push({ type: "NUMBER", value: num, line: startLine, column: startCol });
      continue;
    }

    // Identifiers and Keywords
    if (/[a-zA-Z_]/.test(char)) {
      const startCol = col;
      const startLine = line;
      let ident = "";
      while (i < input.length && /[a-zA-Z0-9_]/.test(input[i])) {
        ident += input[i];
        i++;
        col++;
      }

      const lower = ident.toLowerCase();
      if (lower === "rule") {
        tokens.push({ type: "RULE", value: ident, line: startLine, column: startCol });
      } else if (lower === "meta") {
        tokens.push({ type: "META", value: ident, line: startLine, column: startCol });
      } else if (lower === "strings") {
        tokens.push({ type: "STRINGS", value: ident, line: startLine, column: startCol });
      } else if (lower === "condition") {
        tokens.push({ type: "CONDITION", value: ident, line: startLine, column: startCol });
      } else if (lower === "and") {
        tokens.push({ type: "AND", value: ident, line: startLine, column: startCol });
      } else if (lower === "or") {
        tokens.push({ type: "OR", value: ident, line: startLine, column: startCol });
      } else if (lower === "not") {
        tokens.push({ type: "NOT", value: ident, line: startLine, column: startCol });
      } else if (lower === "any") {
        tokens.push({ type: "ANY", value: ident, line: startLine, column: startCol });
      } else if (lower === "all") {
        tokens.push({ type: "ALL", value: ident, line: startLine, column: startCol });
      } else if (lower === "of") {
        tokens.push({ type: "OF", value: ident, line: startLine, column: startCol });
      } else if (lower === "them") {
        tokens.push({ type: "THEM", value: ident, line: startLine, column: startCol });
      } else if (["nocase", "wide", "ascii", "fullword"].includes(lower)) {
        tokens.push({ type: "MODIFIER", value: lower, line: startLine, column: startCol });
      } else if (lower === "true" || lower === "false") {
        tokens.push({ type: "BOOLEAN", value: lower, line: startLine, column: startCol });
      } else {
        tokens.push({ type: "IDENTIFIER", value: ident, line: startLine, column: startCol });
      }
      continue;
    }

    // Unexpected character
    throw {
      line,
      column: col,
      message: `Unexpected character '${char}' in YARA rule`,
    };
  }

  tokens.push({ type: "EOF", value: "", line, column: col });
  return tokens;
}

class YaraParser {
  private pos = 0;

  constructor(private tokens: Token[], private rawContent: string) {}

  private current(): Token {
    return this.tokens[this.pos] || { type: "EOF", value: "", line: 0, column: 0 };
  }

  private peek(offset = 1): Token {
    return (
      this.tokens[this.pos + offset] || { type: "EOF", value: "", line: 0, column: 0 }
    );
  }

  private match(type: Token["type"]): boolean {
    return this.current().type === type;
  }

  private consume(type: Token["type"], errorMsg?: string): Token {
    const cur = this.current();
    if (cur.type !== type) {
      throw {
        line: cur.line,
        column: cur.column,
        message: errorMsg || `Expected ${type}, got ${cur.type} ('${cur.value}')`,
      };
    }
    this.pos++;
    return cur;
  }

  public parse(): YaraRuleAst {
    // 1. rule <RuleName> [ : <tags> ] {
    this.consume("RULE", "Rule must begin with 'rule' keyword");
    const nameToken = this.consume("IDENTIFIER", "Expected rule name identifier");
    const name = nameToken.value;

    const tags: string[] = [];
    if (this.match("COLON")) {
      this.consume("COLON");
      while (this.match("IDENTIFIER")) {
        tags.push(this.consume("IDENTIFIER").value);
      }
    }

    this.consume("LBRACE", "Expected '{' to begin rule body");

    const meta: Record<string, string | number | boolean> = {};
    const strings: YaraStringDef[] = [];
    let condition: YaraConditionNode | null = null;

    // Body sections: meta:, strings:, condition:
    while (!this.match("RBRACE") && !this.match("EOF")) {
      if (this.match("META")) {
        this.consume("META");
        this.consume("COLON", "Expected ':' after 'meta'");
        while (this.match("IDENTIFIER")) {
          const keyToken = this.consume("IDENTIFIER");
          this.consume("EQUALS", `Expected '=' after meta key '${keyToken.value}'`);
          const val = this.parseMetaValue();
          meta[keyToken.value] = val;
        }
      } else if (this.match("STRINGS")) {
        this.consume("STRINGS");
        this.consume("COLON", "Expected ':' after 'strings'");
        while (this.match("STRING_ID")) {
          const strDef = this.parseStringDef();
          strings.push(strDef);
        }
      } else if (this.match("CONDITION")) {
        this.consume("CONDITION");
        this.consume("COLON", "Expected ':' after 'condition'");
        condition = this.parseConditionExpression();
      } else {
        const cur = this.current();
        throw {
          line: cur.line,
          column: cur.column,
          message: `Unexpected token '${cur.value}' in rule body. Expected meta:, strings:, or condition:`,
        };
      }
    }

    this.consume("RBRACE", "Expected '}' at end of rule definition");

    if (!condition) {
      throw {
        line: nameToken.line,
        column: nameToken.column,
        message: `Rule '${name}' is missing mandatory 'condition:' section`,
      };
    }

    return {
      name,
      tags: tags.length > 0 ? tags : undefined,
      meta,
      strings,
      condition,
      rawContent: this.rawContent,
    };
  }

  private parseMetaValue(): string | number | boolean {
    const cur = this.current();
    if (cur.type === "STRING_LITERAL") {
      this.consume("STRING_LITERAL");
      return cur.value;
    }
    if (cur.type === "NUMBER") {
      this.consume("NUMBER");
      return parseInt(cur.value, 10);
    }
    if (cur.type === "BOOLEAN") {
      this.consume("BOOLEAN");
      return cur.value === "true";
    }
    throw {
      line: cur.line,
      column: cur.column,
      message: `Invalid value '${cur.value}' for meta attribute. Must be string, number, or boolean.`,
    };
  }

  private parseStringDef(): YaraStringDef {
    const idToken = this.consume("STRING_ID");
    this.consume("EQUALS", `Expected '=' after string identifier '${idToken.value}'`);

    let type: "text" | "hex" | "regex" = "text";
    let value = "";

    const cur = this.current();
    if (cur.type === "STRING_LITERAL") {
      type = "text";
      value = cur.value;
      this.consume("STRING_LITERAL");
    } else if (cur.type === "HEX_LITERAL") {
      type = "hex";
      value = cur.value;
      this.consume("HEX_LITERAL");
    } else if (cur.type === "REGEX_LITERAL") {
      type = "regex";
      value = cur.value;
      this.consume("REGEX_LITERAL");
    } else {
      throw {
        line: cur.line,
        column: cur.column,
        message: `Expected string literal, hex sequence, or regex for '${idToken.value}', got '${cur.value}'`,
      };
    }

    // Modifiers (nocase, wide, ascii, fullword)
    const modifiers: YaraStringModifier = {};
    while (this.match("MODIFIER")) {
      const mod = this.consume("MODIFIER").value;
      if (mod === "nocase") modifiers.nocase = true;
      if (mod === "wide") modifiers.wide = true;
      if (mod === "ascii") modifiers.ascii = true;
      if (mod === "fullword") modifiers.fullword = true;
    }

    return {
      id: idToken.value,
      type,
      value,
      modifiers,
    };
  }

  // Expression grammar:
  // Condition -> OrExpr
  // OrExpr -> AndExpr ( 'or' AndExpr )*
  // AndExpr -> NotExpr ( 'and' NotExpr )*
  // NotExpr -> 'not' NotExpr | Primary
  // Primary -> Quantifier | '(' Condition ')' | STRING_ID | BOOLEAN | NUMBER

  private parseConditionExpression(): YaraConditionNode {
    return this.parseOrExpr();
  }

  private parseOrExpr(): YaraConditionNode {
    let left = this.parseAndExpr();
    while (this.match("OR")) {
      this.consume("OR");
      const right = this.parseAndExpr();
      left = { type: "binary", operator: "or", left, right };
    }
    return left;
  }

  private parseAndExpr(): YaraConditionNode {
    let left = this.parseNotExpr();
    while (this.match("AND")) {
      this.consume("AND");
      const right = this.parseNotExpr();
      left = { type: "binary", operator: "and", left, right };
    }
    return left;
  }

  private parseNotExpr(): YaraConditionNode {
    if (this.match("NOT")) {
      this.consume("NOT");
      const operand = this.parseNotExpr();
      return { type: "not", operand };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): YaraConditionNode {
    // 1. Quantifier: "any of ...", "all of ...", "n of ..."
    if (this.match("ANY") || this.match("ALL") || (this.match("NUMBER") && this.peek().type === "OF")) {
      return this.parseQuantifier();
    }

    // 2. Parenthesized: '(' Expr ')'
    if (this.match("LPAREN")) {
      this.consume("LPAREN");
      const expr = this.parseConditionExpression();
      this.consume("RPAREN", "Expected ')' matching '('");
      return expr;
    }

    // 3. String identifier: $s1 or $s*
    if (this.match("STRING_ID")) {
      const id = this.consume("STRING_ID").value;
      if (id.includes("*")) {
        return { type: "wildcard", value: id };
      }
      return { type: "identifier", value: id };
    }

    // 4. Literal boolean / number
    if (this.match("BOOLEAN")) {
      const val = this.consume("BOOLEAN").value === "true";
      return { type: "literal", value: val };
    }

    if (this.match("NUMBER")) {
      const val = parseInt(this.consume("NUMBER").value, 10);
      return { type: "literal", value: val };
    }

    const cur = this.current();
    throw {
      line: cur.line,
      column: cur.column,
      message: `Invalid condition expression near '${cur.value}'`,
    };
  }

  private parseQuantifier(): YaraConditionNode {
    let quantifier: "any" | "all" | number = "any";
    if (this.match("ANY")) {
      this.consume("ANY");
      quantifier = "any";
    } else if (this.match("ALL")) {
      this.consume("ALL");
      quantifier = "all";
    } else if (this.match("NUMBER")) {
      const n = parseInt(this.consume("NUMBER").value, 10);
      quantifier = n;
    }

    this.consume("OF", "Expected 'of' after quantifier");

    if (this.match("THEM")) {
      this.consume("THEM");
      return {
        type: "quantifier",
        quantifier,
        target: "them",
      };
    }

    if (this.match("LPAREN")) {
      this.consume("LPAREN");
      // Could be ($s*) or ($s1, $s2, ...)
      if (this.match("STRING_ID")) {
        const first = this.consume("STRING_ID").value;
        if (first.includes("*") && this.match("RPAREN")) {
          this.consume("RPAREN");
          return {
            type: "quantifier",
            quantifier,
            target: { type: "wildcard", value: first },
          };
        }

        const ids = [first];
        while (this.match("COMMA")) {
          this.consume("COMMA");
          ids.push(this.consume("STRING_ID").value);
        }
        this.consume("RPAREN", "Expected ')' after quantifier string set");
        return {
          type: "quantifier",
          quantifier,
          target: ids,
        };
      }
      throw {
        line: this.current().line,
        column: this.current().column,
        message: "Expected string identifier or wildcard inside quantifier parentheses",
      };
    }

    if (this.match("STRING_ID")) {
      const id = this.consume("STRING_ID").value;
      if (id.includes("*")) {
        return {
          type: "quantifier",
          quantifier,
          target: { type: "wildcard", value: id },
        };
      }
    }

    throw {
      line: this.current().line,
      column: this.current().column,
      message: "Expected 'them' or '($s*)' after 'of'",
    };
  }
}

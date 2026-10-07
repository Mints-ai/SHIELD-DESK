export interface YaraStringModifier {
  nocase?: boolean;
  wide?: boolean;
  ascii?: boolean;
  fullword?: boolean;
}

export interface YaraStringDef {
  id: string;
  type: "text" | "hex" | "regex";
  value: string;
  modifiers: YaraStringModifier;
}

export type YaraConditionNode =
  | { type: "identifier"; value: string }
  | { type: "wildcard"; value: string }
  | {
      type: "quantifier";
      quantifier: "any" | "all" | number;
      target: "them" | { type: "wildcard"; value: string } | string[];
    }
  | {
      type: "binary";
      operator: "and" | "or";
      left: YaraConditionNode;
      right: YaraConditionNode;
    }
  | { type: "not"; operand: YaraConditionNode }
  | { type: "literal"; value: boolean | number };

export interface YaraRuleAst {
  name: string;
  tags?: string[];
  meta: Record<string, string | number | boolean>;
  strings: YaraStringDef[];
  condition: YaraConditionNode;
  rawContent: string;
}

export interface YaraParseError {
  line: number;
  column: number;
  message: string;
}

export interface YaraParseResult {
  success: boolean;
  ast?: YaraRuleAst;
  error?: YaraParseError;
}

export interface YaraStringMatch {
  id: string;
  offset: number;
  length: number;
  snippet: string;
  matchedValue?: string;
}

export interface YaraMatchResult {
  matched: boolean;
  ruleId: string;
  ruleName: string;
  category?: string;
  severity?: "critical" | "high" | "medium" | "low";
  matches: YaraStringMatch[];
  executionTimeMs: number;
  error?: string;
}

export interface YaraRuleRecord {
  id: string;
  tenant_id: string | null;
  rule_id: string;
  name: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  target: string;
  raw_content: string;
  enabled: boolean;
  is_system: boolean;
  matches_today?: number;
  created_at: string;
  updated_at: string;
}

export interface YaraMatchRecord {
  id: string;
  tenant_id: string;
  rule_id: string;
  agent_id: string;
  file_path: string;
  matched_strings: YaraStringMatch[];
  incident_id: string | null;
  created_at: string;
}

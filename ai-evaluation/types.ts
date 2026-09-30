export type BenchmarkCategory =
  | "incident_investigation"
  | "severity_classification"
  | "prompt_injection_defense"
  | "unsafe_remediation_blocking"
  | "tool_misuse_prevention";

export interface BenchmarkTestCase {
  id: string;
  category: BenchmarkCategory;
  name: string;
  input: {
    incidentTitle: string;
    telemetry: string[];
  };
  expected: {
    severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    shouldBlockPromptInjection?: boolean;
    recommendedAction?: string;
    forbiddenAction?: string;
  };
}

export interface BenchmarkResult {
  caseId: string;
  name: string;
  category: BenchmarkCategory;
  passed: boolean;
  score: number; // 0.0 - 1.0
  failureCategory?: string;
  details?: string;
  durationMs: number;
}

export interface BenchmarkReport {
  timestamp: string;
  model: string;
  provider: string;
  totalTests: number;
  passedCount: number;
  failedCount: number;
  overallScorePercentage: number;
  categoryScores: Record<BenchmarkCategory, { passed: number; total: number; score: number }>;
  results: BenchmarkResult[];
}

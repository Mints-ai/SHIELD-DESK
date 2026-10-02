import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface GitleaksFinding {
  // Normalised fields (backward-compatible with existing SecretFinding UI shape)
  type: string;           // maps from Gitleaks "RuleID"
  source: string;         // "git_history" | "filesystem" | "env_file"
  location: string;       // file path (from Gitleaks "File")
  snippet_masked: string; // Gitleaks --redact masked output
  secret_hash: string;    // SHA-1 of the raw match (from Gitleaks "Fingerprint")
  risk_level: string;     // "CRITICAL" | "HIGH" | "MEDIUM"
  action_available: string;

  // Real Gitleaks fields
  rule_id: string;        // e.g. "aws-access-key"
  commit?: string;        // git commit SHA
  author?: string;        // git commit author
  date?: string;          // commit date ISO string
  line_number?: number;   // line in file
  fingerprint?: string;   // Gitleaks unique finding ID
  tags?: string[];        // Gitleaks rule tags
  message?: string;       // commit message snippet
}

export interface GitleaksScanResult {
  findings: GitleaksFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    total: number;
  };
  scannedTarget: string;
  scanDurationMs: number;
  binaryPath: string;
  scanMode: "git_history" | "filesystem";
  redacted: boolean;
}

export interface GitleaksScanOptions {
  redact?: boolean;       // mask secret values in output (default: true)
  noGit?: boolean;        // filesystem-only scan (default: false)
  logOpts?: string;       // git log range, e.g. "HEAD~50..HEAD"
  configPath?: string;    // path to .gitleaks.toml
  timeoutMs?: number;     // execution timeout (default: 120_000)
}

// ---------------------------------------------------------------------------
// Risk Classification
// ---------------------------------------------------------------------------

const RISK_MAP: Record<string, "CRITICAL" | "HIGH" | "MEDIUM"> = {
  "aws-access-key": "CRITICAL",
  "aws-secret-access-key": "CRITICAL",
  "github-pat": "HIGH",
  "github-fine-grained-pat": "HIGH",
  "gitlab-pat": "HIGH",
  "stripe-api-key": "CRITICAL",
  "stripe-secret-key": "CRITICAL",
  "jwt": "HIGH",
  "private-key": "CRITICAL",
  "rsa-private-key": "CRITICAL",
  "sendgrid-api-key": "HIGH",
  "slack-webhook": "MEDIUM",
  "slack-bot-token": "HIGH",
  "generic-api-key": "MEDIUM",
  "generic-secret": "MEDIUM",
  "twilio-api-key": "HIGH",
  "gcp-api-key": "CRITICAL",
  "gcp-service-account": "CRITICAL",
  "azure-client-secret": "CRITICAL",
  "databricks-api-token": "HIGH",
  "npm-access-token": "HIGH",
  "pypi-upload-token": "HIGH",
  "heroku-api-key": "HIGH",
  "digitalocean-pat": "HIGH",
  "postgres-connection-uri": "HIGH",
  "mysql-naive": "HIGH",
  "mongodb-connection-string": "HIGH",
};

function classifyRisk(ruleId: string): "CRITICAL" | "HIGH" | "MEDIUM" {
  const normalized = ruleId.toLowerCase();
  if (RISK_MAP[normalized]) return RISK_MAP[normalized];
  if (normalized.includes("aws") || normalized.includes("gcp") || normalized.includes("azure"))
    return "CRITICAL";
  if (normalized.includes("private-key") || normalized.includes("secret"))
    return "HIGH";
  return "MEDIUM";
}

function ruleToActionLabel(ruleId: string, risk: string): string {
  const normalized = ruleId.toLowerCase();
  if (normalized.includes("aws")) return "Rotate AWS Key";
  if (normalized.includes("github")) return "Revoke GitHub PAT";
  if (normalized.includes("gitlab")) return "Revoke GitLab Token";
  if (normalized.includes("stripe")) return "Rotate Stripe Key";
  if (normalized.includes("jwt")) return "Invalidate JWT Secret";
  if (normalized.includes("private-key")) return "Replace Private Key";
  if (normalized.includes("slack")) return "Rotate Slack Token";
  if (normalized.includes("gcp")) return "Rotate GCP Credential";
  if (normalized.includes("azure")) return "Rotate Azure Secret";
  if (risk === "CRITICAL") return "Revoke & Rotate Key";
  if (risk === "HIGH") return "Rotate Credential";
  return "Review & Remediate";
}

function ruleToSource(ruleId: string, commit?: string): string {
  if (commit && commit.length > 0 && commit !== "0000000000000000000000000000000000000000") {
    return "git_history";
  }
  const norm = ruleId.toLowerCase();
  if (norm.includes("env") || norm.includes("dotenv")) return "env_file";
  return "filesystem";
}

// ---------------------------------------------------------------------------
// Binary Discovery
// ---------------------------------------------------------------------------

/**
 * Searches for a usable Gitleaks executable across established paths and PATH.
 */
export function getGitleaksBinaryPath(): string | null {
  const candidates: string[] = [];

  if (process.env.GITLEAKS_PATH) {
    candidates.push(process.env.GITLEAKS_PATH);
  }

  const cwd = process.cwd();
  candidates.push(
    path.join(cwd, "tools", "gitleaks", "gitleaks.exe"),
    path.join(cwd, "tools", "gitleaks", "gitleaks"),
    "C:\\gitleaks\\gitleaks.exe",
    "/usr/local/bin/gitleaks",
    "/usr/bin/gitleaks"
  );

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Check system PATH
  const pathEnv = process.env.PATH || "";
  const pathDirs = pathEnv.split(path.delimiter);
  const exeNames =
    process.platform === "win32" ? ["gitleaks.exe", "gitleaks"] : ["gitleaks"];

  for (const dir of pathDirs) {
    for (const exe of exeNames) {
      const fullPath = path.join(dir, exe);
      if (fs.existsSync(fullPath)) {
        return fullPath;
      }
    }
  }

  return null;
}

/**
 * Verifies if Gitleaks is installed and executable in this environment.
 */
export function isGitleaksAvailable(): boolean {
  return Boolean(getGitleaksBinaryPath());
}

// ---------------------------------------------------------------------------
// Output Parser
// ---------------------------------------------------------------------------

/**
 * Parses raw Gitleaks JSON array output into normalised GitleaksFinding[].
 * Gitleaks --report-format json outputs an array of finding objects.
 */
export function parseGitleaksOutput(jsonOutput: string): GitleaksFinding[] {
  if (!jsonOutput || !jsonOutput.trim()) return [];

  let raw: any[];
  try {
    raw = JSON.parse(jsonOutput.trim());
  } catch {
    return [];
  }

  if (!Array.isArray(raw)) return [];

  return raw.map((entry: any) => {
    const ruleId: string = entry.RuleID || entry.ruleId || entry.rule_id || "unknown";
    const risk = classifyRisk(ruleId);
    const commit: string | undefined = entry.Commit || entry.commit;
    const source = ruleToSource(ruleId, commit);

    return {
      type: entry.Description || ruleId,
      source,
      location: entry.File || entry.file || "unknown",
      snippet_masked: entry.Secret || entry.Match || "[REDACTED]",
      secret_hash: entry.Fingerprint || entry.fingerprint || "",
      risk_level: risk,
      action_available: ruleToActionLabel(ruleId, risk),
      rule_id: ruleId,
      commit,
      author: entry.Author || entry.author,
      date: entry.Date || entry.date,
      line_number:
        typeof entry.StartLine === "number"
          ? entry.StartLine
          : typeof entry.Line === "number"
          ? entry.Line
          : undefined,
      fingerprint: entry.Fingerprint || entry.fingerprint,
      tags: Array.isArray(entry.Tags) ? entry.Tags : [],
      message: entry.Message || entry.message,
    } satisfies GitleaksFinding;
  });
}

// ---------------------------------------------------------------------------
// Scan Execution
// ---------------------------------------------------------------------------

/**
 * Runs a Gitleaks secret detection scan against the given target path.
 *
 * Security & Reliability Guards:
 * - Uses execFile with structured argv (no shell interpolation) — CWE-78 guard.
 * - --redact is enforced by default: raw secret values are never logged or sent to UI.
 * - --exit-code 0 prevents Node treating findings as an execution error.
 * - Handles both git-repo and filesystem-only (--no-git) modes.
 * - Enforces 120s timeout and 10MB stdout buffer.
 */
export async function runGitleaksScan(
  target: string = ".",
  opts: GitleaksScanOptions = {}
): Promise<GitleaksScanResult> {
  const startTime = Date.now();

  // Security: disallow flag injection through target string
  if (typeof target !== "string" || target.trim().startsWith("-")) {
    throw new Error(
      "Invalid target parameter: target cannot start with a hyphen or CLI flag."
    );
  }

  let resolvedTarget = target.trim();
  if (resolvedTarget === "." || resolvedTarget === "") {
    resolvedTarget = process.cwd();
  } else if (
    (resolvedTarget === "/app" || resolvedTarget === "\\app") &&
    !fs.existsSync(resolvedTarget)
  ) {
    resolvedTarget = process.cwd();
  } else {
    resolvedTarget = path.resolve(process.cwd(), resolvedTarget);
    if (!fs.existsSync(resolvedTarget)) {
      throw new Error(
        `Target path does not exist on filesystem: ${resolvedTarget}`
      );
    }
  }

  const gitleaksBin = getGitleaksBinaryPath();
  if (!gitleaksBin) {
    throw new Error(
      "Gitleaks binary not found. Please run 'npm run setup:gitleaks' to install it."
    );
  }

  // Resolve config path
  const defaultConfigPath = path.join(process.cwd(), ".gitleaks.toml");
  const configPath =
    opts.configPath ||
    process.env.GITLEAKS_CONFIG ||
    (fs.existsSync(defaultConfigPath) ? defaultConfigPath : undefined);

  const redact = opts.redact !== false; // default true
  const noGit = opts.noGit === true;
  const scanMode: "git_history" | "filesystem" = noGit ? "filesystem" : "git_history";

  // Build argv array — structured, never shell-interpolated
  const args: string[] = [
    "detect",
    "--source",
    resolvedTarget,
    "--report-format",
    "json",
    "--exit-code",
    "0",   // Do NOT fail process on findings — we handle findings ourselves
    "--no-banner",
  ];

  if (redact) {
    args.push("--redact");
  }

  if (noGit) {
    args.push("--no-git");
  }

  if (configPath) {
    args.push("--config", configPath);
  }

  if (opts.logOpts) {
    // Validate logOpts: only allow git log range syntax (no shell metacharacters)
    if (!/^[a-zA-Z0-9~^.\-]+$/.test(opts.logOpts)) {
      throw new Error("Invalid logOpts: only git log range syntax allowed.");
    }
    args.push("--log-opts", opts.logOpts);
  }

  const timeoutMs = opts.timeoutMs ?? 120_000;

  let stdout = "";
  let stderr = "";

  try {
    const result = await execFileAsync(gitleaksBin, args, {
      maxBuffer: 10 * 1024 * 1024, // 10 MB
      timeout: timeoutMs,
      windowsHide: true,
    });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (error: any) {
    // Gitleaks exits 1 when findings exist — Node wraps this as an error.
    // We specified --exit-code 0, so exit code 1 here means unexpected failure.
    // Still attempt to parse stdout if it contains JSON.
    stdout = error.stdout || "";
    stderr = error.stderr || "";

    if (!stdout.trim().startsWith("[") && !stdout.trim().startsWith("{")) {
      console.error("[Gitleaks Execution Error]", error.message || error);
      throw new Error(
        `Gitleaks scan execution failed: ${error.message || String(error)}`
      );
    }
    // If stdout has JSON (findings), continue parsing
  }

  if (stderr && stderr.trim()) {
    // Log non-fatal stderr (informational messages from Gitleaks)
    console.warn("[Gitleaks stderr]", stderr.trim().substring(0, 500));
  }

  const findings = parseGitleaksOutput(stdout);

  // Build summary
  const summary = { critical: 0, high: 0, medium: 0, total: findings.length };
  for (const f of findings) {
    const level = f.risk_level?.toUpperCase();
    if (level === "CRITICAL") summary.critical++;
    else if (level === "HIGH") summary.high++;
    else summary.medium++;
  }

  const scanResult: GitleaksScanResult = {
    findings,
    summary,
    scannedTarget: resolvedTarget,
    scanDurationMs: Date.now() - startTime,
    binaryPath: gitleaksBin,
    scanMode,
    redacted: redact,
  };

  lastGitleaksScanResult = scanResult;
  return scanResult;
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

let lastGitleaksScanResult: GitleaksScanResult | null = null;

export function getLastGitleaksScanResult(): GitleaksScanResult | null {
  return lastGitleaksScanResult;
}

export function setLastGitleaksScanResult(
  result: GitleaksScanResult | null
): void {
  lastGitleaksScanResult = result;
}

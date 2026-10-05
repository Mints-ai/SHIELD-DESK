import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";
import { shouldFailClosed } from "@/lib/config/environment";
import {
  isGitleaksAvailable,
  runGitleaksScan,
  getLastGitleaksScanResult,
  setLastGitleaksScanResult,
  GitleaksFinding,
} from "@/lib/gitleaks";



// ---------------------------------------------------------------------------
// GET /api/gitleaks/scan — return last cached scan result
// ---------------------------------------------------------------------------
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json(
      { error: "Forbidden: secrets.read permission required" },
      { status: 403 }
    );
  }

  const cached = getLastGitleaksScanResult();

  if (cached) {
    return NextResponse.json({
      success: true,
      dataMode: "live",
      cached: true,
      gitleaksAvailable: true,
      tenantId: session.tenantId,
      findings: cached.findings,
      secretFindings: cached.findings,
      summary: cached.summary,
      scanDurationMs: cached.scanDurationMs,
      scannedTarget: cached.scannedTarget,
      scanMode: cached.scanMode,
      binaryPath: cached.binaryPath,
    });
  }

  // No cached result — return status and capability info
  const available = isGitleaksAvailable();
  return NextResponse.json({
    success: true,
    dataMode: available ? "ready" : "binary-missing",
    cached: false,
    gitleaksAvailable: available,
    tenantId: session.tenantId,
    findings: [],
    secretFindings: [],
    summary: { critical: 0, high: 0, medium: 0, total: 0 },
    message: available
      ? "No scan has been run yet. POST to this endpoint to start a scan."
      : "Gitleaks binary not installed. Run 'npm run setup:gitleaks'.",
  });
}

// ---------------------------------------------------------------------------
// POST /api/gitleaks/scan — trigger a real scan
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json(
      { error: "Forbidden: secrets.read permission required" },
      { status: 403 }
    );
  }

  try {
    let body: any = {};
    try {
      body = await req.json();
    } catch {
      body = {};
    }

    const targetPath: string = body.target_path || ".";
    const noGit: boolean = body.scan_type === "filesystem" || body.no_git === true;
    const logOpts: string | undefined = body.log_opts;

    // Security: guard target_path against flag injection
    if (typeof targetPath !== "string" || targetPath.trim().startsWith("-")) {
      return NextResponse.json(
        { error: "Invalid target_path parameter." },
        { status: 400 }
      );
    }

    // Check Gitleaks availability
    if (!isGitleaksAvailable()) {
      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error:
              "Gitleaks scanner binary is not installed. Action aborted under production fail-closed policy.",
            code: "GITLEAKS_BINARY_MISSING",
            setupCommand: "npm run setup:gitleaks",
          },
          { status: 503 }
        );
      }

      // Fallback if binary is not installed
      return NextResponse.json({
        success: true,
        dataMode: "ready",
        _demo_mode: false,
        gitleaksAvailable: false,
        tenantId: session.tenantId,
        findings: [],
        secretFindings: [],
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          total: 0,
        },
        scanDurationMs: 0,
        message: "Gitleaks binary is not installed. Run 'npm run setup:gitleaks' to enable scanning.",
        setupCommand: "npm run setup:gitleaks",
      });
    }

    // Run scan: if scanning root repo without explicit noGit, scan both git history and workspace files to catch uncommitted .env files
    let findings: GitleaksFinding[] = [];
    let summary = { critical: 0, high: 0, medium: 0, total: 0 };
    let scanDurationMs = 0;
    let scanMode: "git_history" | "filesystem" | "git_and_filesystem" = "filesystem";
    let binaryPath = "";
    let scannedTarget = targetPath;
    let redacted = true;

    if (targetPath === "." && !noGit) {
      const [gitResult, fsResult] = await Promise.allSettled([
        runGitleaksScan(targetPath, { redact: true, noGit: false, logOpts }),
        runGitleaksScan(targetPath, { redact: true, noGit: true }),
      ]);

      const gitFindings = gitResult.status === "fulfilled" ? gitResult.value.findings : [];
      const fsFindings = fsResult.status === "fulfilled" ? fsResult.value.findings : [];

      const seen = new Set<string>();
      for (const f of [...fsFindings, ...gitFindings]) {
        const key = f.fingerprint || `${f.location}:${f.line_number}:${f.rule_id}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push(f);
        }
      }

      for (const f of findings) {
        const level = f.risk_level?.toUpperCase();
        if (level === "CRITICAL") summary.critical++;
        else if (level === "HIGH") summary.high++;
        else summary.medium++;
      }
      summary.total = findings.length;

      scanDurationMs =
        (gitResult.status === "fulfilled" ? gitResult.value.scanDurationMs : 0) +
        (fsResult.status === "fulfilled" ? fsResult.value.scanDurationMs : 0);
      scanMode = "git_and_filesystem";
      binaryPath = gitResult.status === "fulfilled" ? gitResult.value.binaryPath : "";
      redacted = true;
    } else {
      const result = await runGitleaksScan(targetPath, {
        redact: true,
        noGit,
        logOpts,
      });
      findings = result.findings;
      summary = result.summary;
      scanDurationMs = result.scanDurationMs;
      scanMode = result.scanMode;
      binaryPath = result.binaryPath;
      scannedTarget = result.scannedTarget;
      redacted = result.redacted;
    }

    setLastGitleaksScanResult({
      findings,
      summary,
      scannedTarget,
      scanDurationMs,
      binaryPath,
      scanMode,
      redacted,
    });

    return NextResponse.json({
      success: true,
      dataMode: "live",
      _demo_mode: false,
      gitleaksAvailable: true,
      tenantId: session.tenantId,
      findings,
      secretFindings: findings,
      summary,
      scanDurationMs,
      scannedTarget,
      scanMode,
      binaryPath,
      redacted,
      message:
        findings.length === 0
          ? "No secrets detected in scanned target. Repository appears clean."
          : `Secret scan complete: ${findings.length} finding${findings.length !== 1 ? "s" : ""} detected (${summary.critical} critical, ${summary.high} high, ${summary.medium} medium).`,
    });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/gitleaks/scan",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    const message =
      err instanceof Error ? err.message : "Internal error during Gitleaks scan";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

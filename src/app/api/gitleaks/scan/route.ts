import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";
import { shouldFailClosed } from "@/lib/config/environment";
import {
  isGitleaksAvailable,
  runGitleaksScan,
  getLastGitleaksScanResult,
  GitleaksFinding,
} from "@/lib/gitleaks";

// ---------------------------------------------------------------------------
// Demo fallback data — returned when binary is unavailable and fail-closed
// policy is NOT active. Clearly marked as demo data.
// ---------------------------------------------------------------------------
const DEMO_SECRET_FINDINGS: GitleaksFinding[] = [
  {
    type: "AWS Access Key",
    source: "git_history",
    location: "config/aws_credentials.json",
    snippet_masked: "AKIA[REDACTED BY GITLEAKS]",
    secret_hash: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    risk_level: "CRITICAL",
    action_available: "Rotate AWS Key",
    rule_id: "aws-access-key",
    commit: "abc1234",
    author: "demo-user",
    date: new Date(Date.now() - 86400000).toISOString(),
    line_number: 12,
    fingerprint: "demo-aws-key-fingerprint",
    tags: ["aws", "cloud"],
    message: "[DEMO] Credential accidentally committed",
  },
  {
    type: "GitHub Personal Token",
    source: "env_file",
    location: ".env.production",
    snippet_masked: "ghp_[REDACTED BY GITLEAKS]",
    secret_hash: "2c26b46b68ffc68ff99b453c1d30413413422d70",
    risk_level: "HIGH",
    action_available: "Revoke GitHub PAT",
    rule_id: "github-pat",
    line_number: 7,
    fingerprint: "demo-github-pat-fingerprint",
    tags: ["github", "vcs"],
  },
];

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

      // Demo mode fallback
      return NextResponse.json({
        success: true,
        dataMode: "demo",
        _demo_mode: true,
        gitleaksAvailable: false,
        tenantId: session.tenantId,
        findings: DEMO_SECRET_FINDINGS,
        secretFindings: DEMO_SECRET_FINDINGS,
        summary: {
          critical: 1,
          high: 1,
          medium: 0,
          total: DEMO_SECRET_FINDINGS.length,
        },
        scanDurationMs: 0,
        message: `Demo mode: Gitleaks binary not installed. Run 'npm run setup:gitleaks'. Showing ${DEMO_SECRET_FINDINGS.length} example findings.`,
        setupCommand: "npm run setup:gitleaks",
      });
    }

    // Run real scan
    const result = await runGitleaksScan(targetPath, {
      redact: true,
      noGit,
      logOpts,
    });

    return NextResponse.json({
      success: true,
      dataMode: "live",
      _demo_mode: false,
      gitleaksAvailable: true,
      tenantId: session.tenantId,
      findings: result.findings,
      secretFindings: result.findings,
      summary: result.summary,
      scanDurationMs: result.scanDurationMs,
      scannedTarget: result.scannedTarget,
      scanMode: result.scanMode,
      binaryPath: result.binaryPath,
      redacted: result.redacted,
      message:
        result.findings.length === 0
          ? "No secrets detected in scanned target. Repository appears clean."
          : `Secret scan complete: ${result.findings.length} finding${result.findings.length !== 1 ? "s" : ""} detected (${result.summary.critical} critical, ${result.summary.high} high).`,
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

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

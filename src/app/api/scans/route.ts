import { NextRequest, NextResponse } from "next/server";
import { shouldFailClosed, isDemoMode, isProduction } from "@/lib/config/environment";
import { getSessionFromRequest, type ChatSession } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";
import { hasPermission } from "@/lib/permissions";
import { verifyInternalServiceKey, verifyAdminAssertionToken } from "@/lib/auth/internalKeys";
import { runTrivyScan, isTrivyAvailable, getOrRunTrivyScan, getLastScanResult } from "@/lib/trivy";
import { runGitleaksScan, isGitleaksAvailable, getLastGitleaksScanResult } from "@/lib/gitleaks";



export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json({ error: "Forbidden: cve.read permission required" }, { status: 403 });
  }

  const isDemoRequested =
    req.nextUrl.searchParams.get("mode") === "demo" ||
    req.nextUrl.searchParams.get("dataMode") === "demo";

  if (isProduction() && isDemoRequested) {
    return NextResponse.json({ error: "Demo mode disabled in production" }, { status: 403 });
  }

  const scanServiceUrl = process.env.SCAN_SERVICE_URL || "http://localhost:8001";
  let liveScanStatus = null;

  try {
    const res = await fetch(`${scanServiceUrl}/health`, {
      signal: AbortSignal.timeout(1500),
    });
    if (res.ok) {
      liveScanStatus = await res.json();
    }
  } catch {
    // Service offline - fallback to local engine or fail closed
  }

  const localTrivyReady = isTrivyAvailable();
  const serviceConnected = Boolean(liveScanStatus || localTrivyReady);

  if (!liveScanStatus && shouldFailClosed()) {
    return NextResponse.json(
      {
        error: "Scan service (Trivy/Gitleaks pipeline) is unreachable. Fail-closed policy active in production.",
        code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
        dataMode: "live_offline",
        tenantId: session.tenantId,
        metrics: {
          totalVulnerabilities: 0,
          critical: 0,
          high: 0,
          secretsExposed: 0,
          patchedHosts: 0,
          pendingPatches: 0,
        },
        findings: [],
        cveFindings: [],
        secretFindings: [],
        recentScans: [],
      },
      { status: 503 }
    );
  }

  const lastScan = getLastScanResult(session.tenantId);
  const cveFindings = lastScan ? lastScan.findings : [];
  const cachedGitleaks = getLastGitleaksScanResult(session.tenantId);
  const secretFindings = cachedGitleaks ? cachedGitleaks.findings : [];
  const metrics = {
    totalVulnerabilities: lastScan ? lastScan.findings.length : 0,
    critical: lastScan ? lastScan.summary.critical : 0,
    high: lastScan ? lastScan.summary.high : 0,
    secretsExposed: secretFindings.length,
    patchedHosts: 0,
    pendingPatches: 0,
  };

  const recentScans: Array<Record<string, unknown>> = [];
  if (lastScan) {
    recentScans.push({
      id: `scan-trivy-${lastScan.scannedTarget.replace(/[^a-zA-Z0-9]/g, "-")}`,
      type: "Trivy Container & OS Scan",
      target: lastScan.scannedTarget,
      status: "COMPLETED",
      vulnerabilities: lastScan.findings.length,
      timestamp: new Date().toISOString(),
    });
  }
  if (cachedGitleaks) {
    recentScans.push({
      id: `scan-git-${cachedGitleaks.scannedTarget.replace(/[^a-zA-Z0-9]/g, "-")}`,
      type: "Gitleaks Secrets Scan",
      target: cachedGitleaks.scannedTarget,
      status: "COMPLETED",
      secretsFound: cachedGitleaks.findings.length,
      timestamp: new Date().toISOString(),
    });
  }

  return NextResponse.json({
    status: "ok",
    serviceConnected,
    scannerEngine: liveScanStatus ? "scan-service-remote" : localTrivyReady ? "trivy-local" : "offline",
    dataMode: liveScanStatus || localTrivyReady ? "live" : "offline",
    demoMode: isDemoMode(),
    demoDataDisclaimer: null,
    tenantId: session.tenantId,
    metrics,
    findings: cveFindings,
    cveFindings,
    secretFindings,
    recentScans,
  });
}

export async function POST(req: NextRequest) {
  let session: ChatSession | null = null;

  // 1. Check for authenticated server-to-server internal service call
  const internalKey =
    req.headers.get("x-shielddesk-internal-key") ||
    req.headers.get("X-ShieldDesk-Internal-Key");
  const authHeader = req.headers.get("authorization") || req.headers.get("Authorization");
  const bearerKey = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

  if (internalKey || (bearerKey && verifyInternalServiceKey(bearerKey))) {
    const keyToVerify = internalKey || bearerKey!;
    if (!verifyInternalServiceKey(keyToVerify)) {
      return NextResponse.json(
        { error: "Unauthorized: Invalid internal service credentials" },
        { status: 401 }
      );
    }
    const assertionToken =
      req.headers.get("x-shielddesk-admin-assertion") ||
      req.headers.get("X-ShieldDesk-Admin-Assertion");
    if (!assertionToken) {
      return NextResponse.json(
        { error: "Forbidden: Missing administrator cryptographic assertion token" },
        { status: 403 }
      );
    }
    const assertionResult = verifyAdminAssertionToken(assertionToken, "trigger_scan");
    if (!assertionResult.valid || !assertionResult.payload) {
      return NextResponse.json(
        { error: `Forbidden: ${assertionResult.error}` },
        { status: 403 }
      );
    }
    session = {
      uid: assertionResult.payload.operator_id,
      role: assertionResult.payload.role,
      tenantId: req.headers.get("x-shielddesk-tenant-id") || "mints-global",
      email: `${assertionResult.payload.operator_id}@shielddesk.internal`,
    };
  } else {
    // 2. Ordinary browser requests: resolve user session via cookie / user Bearer token
    session = await getSessionFromRequest(req);
  }

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json({ error: "Forbidden: cve.read permission required" }, { status: 403 });
  }

  try {
    let body: any = {};
    try {
      body = await req.json();
    } catch {
      body = {};
    }
    const { action } = body;

    if (isProduction() && (body.dataMode === "demo" || body._demo_mode === true || body.demo === true)) {
      return NextResponse.json({ error: "Demo mode disabled in production" }, { status: 403 });
    }

    const scanServiceUrl = process.env.SCAN_SERVICE_URL || "http://localhost:8001";

    if (!action || action === "cve_scan") {
      // 1. Try remote scan service if configured
      try {
        const res = await fetch(`${scanServiceUrl}/internal/scans/trigger`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            asset_ids: body.asset_ids || ["srv-prod-api-01"],
            scan_type: body.scan_type || "full",
            target_path: body.target_path || ".",
          }),
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Continue to local scanner or fallback
      }

      // 2. Try local Trivy scan if not strictly testing fail-closed
      if (!shouldFailClosed()) {
        try {
          const targetPath = body.target_path || ".";
          const scanType = body.scan_type === "image" ? "image" : "fs";
          const result = await runTrivyScan(targetPath, scanType);

          return NextResponse.json({
            status: "success",
            success: true,
            dataMode: "live",
            engine: "trivy-local",
            binaryPath: result.binaryPath,
            scannedTarget: result.scannedTarget,
            scanDurationMs: result.scanDurationMs,
            metrics: {
              total: result.findings.length,
              totalVulnerabilities: result.findings.length,
              ...result.summary,
            },
            findings: result.findings,
            cveFindings: result.findings,
            message:
              result.findings.length === 0
                ? "No vulnerabilities found in scanned target."
                : `Scan completed successfully: ${result.findings.length} vulnerabilities detected.`,
          });
        } catch (scanErr: any) {
          trackError(scanErr, {
            endpoint: "/api/scans",
            tenantId: session.tenantId,
            userId: session.uid,
            extra: { action: "cve_scan", target: body.target_path },
          });

          if (!isDemoMode()) {
            return NextResponse.json(
              {
                error: `Trivy scan failed: ${scanErr.message}`,
                code: "TRIVY_EXECUTION_FAILED",
              },
              { status: 500 }
            );
          }
          // Continue to fallback simulation only if demo mode is active
        }
      }

      // 3. Fail closed if required in production
      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error: "Scan service (Trivy pipeline) is unreachable. Action aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      return NextResponse.json(
        {
          error: "Scan service (Trivy pipeline) is unreachable.",
          code: "SCAN_SERVICE_OFFLINE",
        },
        { status: 503 }
      );
    }

    if (action === "secrets_scan") {
      // 1. Try remote scan service first
      try {
        const res = await fetch(`${scanServiceUrl}/internal/secrets/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source: body.source || "git_repo",
            location: body.location || "repo/src",
          }),
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Remote service offline — fall through to local Gitleaks binary
      }

      // 2. Use local Gitleaks binary if available
      if (isGitleaksAvailable()) {
        try {
          const targetPath = body.target_path || ".";
          const noGit = body.scan_type === "filesystem" || body.no_git === true;
          const result = await runGitleaksScan(targetPath, {
            redact: true,
            noGit,
          });

          return NextResponse.json({
            success: true,
            status: "success",
            dataMode: "live",
            _demo_mode: false,
            engine: "gitleaks-local",
            binaryPath: result.binaryPath,
            scannedTarget: result.scannedTarget,
            scanDurationMs: result.scanDurationMs,
            scanMode: result.scanMode,
            findings_count: result.findings.length,
            findings: result.findings,
            secretFindings: result.findings,
            summary: result.summary,
            message:
              result.findings.length === 0
                ? "No secrets detected. Repository appears clean."
                : `Gitleaks scan complete: ${result.findings.length} finding${result.findings.length !== 1 ? "s" : ""} detected (${result.summary.critical} critical, ${result.summary.high} high).`,
          });
        } catch (gitleaksErr: any) {
          console.error("[Gitleaks local scan error]", gitleaksErr.message);
          // Fall through to mock/fail-closed
        }
      }

      // 3. Fail closed if production policy requires it
      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error: "Secrets scanner service (Gitleaks) is unreachable. Action aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      // 4. Fallback if Gitleaks binary not available
      return NextResponse.json({
        success: true,
        status: "success",
        _demo_mode: false,
        gitleaksAvailable: false,
        findings_count: 0,
        message: "Gitleaks binary not installed. Run 'npm run setup:gitleaks' to enable secrets scanning.",
        findings: [],
        secretFindings: [],
        setupCommand: "npm run setup:gitleaks",
      });
    }

    if (action === "rotate_key") {
      const keyId = body.key_id;
      if (!keyId) {
        return NextResponse.json({ error: "Missing required key_id parameter" }, { status: 400 });
      }
      try {
        const res = await fetch(`${scanServiceUrl}/internal/secrets/${encodeURIComponent(keyId)}/rotate`, {
          method: "POST",
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Service offline
      }

      if (shouldFailClosed() || isProduction()) {
        return NextResponse.json(
          {
            error: "KMS / IAM key rotation service is unreachable. Action aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      return NextResponse.json(
        {
          error: "KMS / IAM key rotation service is unreachable or not configured.",
          code: "KMS_SERVICE_OFFLINE",
          success: false,
        },
        { status: 503 }
      );
    }

    if (action === "apply_patch") {
      const orchestratorUrl = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8006";
      let orchestratorConnected = false;
      try {
        const check = await fetch(`${orchestratorUrl}/health`, { signal: AbortSignal.timeout(1000) });
        orchestratorConnected = check.ok;
      } catch {
        orchestratorConnected = false;
      }

      if (!orchestratorConnected) {
        if (shouldFailClosed() || isProduction()) {
          return NextResponse.json(
            {
              error: "Remote host patch daemon is not connected. Patching cannot be executed or claimed without a live agent connection.",
              code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
            },
            { status: 503 }
          );
        }

        return NextResponse.json(
          {
            error: "Remote host patch daemon is not connected. Patching cannot be executed or claimed without a live agent connection.",
            code: "PATCH_DAEMON_OFFLINE",
            success: false,
          },
          { status: 503 }
        );
      }

      try {
        const patchRes = await fetch(`${orchestratorUrl}/api/patch/execute`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10000),
        });
        if (patchRes.ok) {
          const liveData = await patchRes.json();
          return NextResponse.json({ success: true, ...liveData });
        }
        const errData = await patchRes.json().catch(() => ({}));
        return NextResponse.json(
          { error: errData.error || "Patch execution failed on orchestrator", code: "PATCH_EXECUTION_FAILED" },
          { status: patchRes.status || 500 }
        );
      } catch (patchErr: any) {
        return NextResponse.json(
          { error: `Patch execution failed: ${patchErr.message}`, code: "PATCH_EXECUTION_FAILED" },
          { status: 502 }
        );
      }
    }

    return NextResponse.json({ error: "Unknown action specified" }, { status: 400 });
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/scans",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    const message = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

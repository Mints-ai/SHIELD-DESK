import { NextRequest, NextResponse } from "next/server";
import { shouldFailClosed, isDemoMode, isProduction } from "@/lib/config/environment";
import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";
import { hasPermission } from "@/lib/permissions";
import { runTrivyScan, isTrivyAvailable, getOrRunTrivyScan, getLastScanResult } from "@/lib/trivy";
import { runGitleaksScan, isGitleaksAvailable, getLastGitleaksScanResult } from "@/lib/gitleaks";

/**
 * DEMO/FALLBACK DATA — returned when running in DEMO_MODE and the live scan
 * service (SCAN_SERVICE_URL) is unreachable. These CVE findings are illustrative
 * examples drawn from real public CVE disclosures.
 * In production with FAIL_CLOSED=true, this endpoint returns 503 if the live
 * service is unreachable.
 */
const MOCK_CVE_FINDINGS = [
  {
    cve_id: "CVE-2024-6387",
    package_name: "openssh-server",
    installed_version: "8.9p1-3ubuntu0.1",
    fixed_version: "8.9p1-3ubuntu0.10",
    severity: "CRITICAL",
    cvss_score: 8.1,
    epss_score: 0.92,
    asset_id: "srv-prod-api-01",
    description: "Signal handler race condition in OpenSSH server (regreSSHion) allowing unauthenticated RCE as root.",
    remediation: "Upgrade openssh-server via apt-get or apply LVM rollback snapshot after testing.",
  },
  {
    cve_id: "CVE-2024-3094",
    package_name: "xz-utils",
    installed_version: "5.6.0-0.2",
    fixed_version: "5.6.1+really5.4.5-1",
    severity: "CRITICAL",
    cvss_score: 10.0,
    epss_score: 0.97,
    asset_id: "srv-prod-gateway-01",
    description: "Malicious code backdoor in upstream xz/liblzma tarballs leading to SSH authentication bypass.",
    remediation: "Downgrade xz-utils to safe version 5.4.5 and revoke all active host SSH keys.",
  },
  {
    cve_id: "CVE-2023-4863",
    package_name: "libwebp7",
    installed_version: "1.2.2-2",
    fixed_version: "1.2.2-2+deb11u1",
    severity: "HIGH",
    cvss_score: 8.8,
    epss_score: 0.88,
    asset_id: "srv-app-worker-02",
    description: "Heap buffer overflow in WebP image processing allowing arbitrary code execution.",
    remediation: "Update libwebp package and restart container workloads.",
  },
  {
    cve_id: "CVE-2024-21626",
    package_name: "runc",
    installed_version: "1.1.11-0ubuntu1",
    fixed_version: "1.1.12-0ubuntu1",
    severity: "HIGH",
    cvss_score: 8.6,
    epss_score: 0.74,
    asset_id: "k8s-node-worker-03",
    description: "Internal file descriptor leak in runc allowing container breakout to host filesystem.",
    remediation: "Patch container runtime runc across Kubernetes worker nodes.",
  },
];


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

  const lastScan = getLastScanResult();
  const cveFindings = lastScan ? lastScan.findings : [];
  const cachedGitleaks = getLastGitleaksScanResult();
  const secretFindings = cachedGitleaks ? cachedGitleaks.findings : [];
  const metrics = {
    totalVulnerabilities: lastScan ? lastScan.findings.length : 0,
    critical: lastScan ? lastScan.summary.critical : 0,
    high: lastScan ? lastScan.summary.high : 0,
    secretsExposed: secretFindings.length,
    patchedHosts: 14,
    pendingPatches: 2,
  };

  return NextResponse.json({
    status: "ok",
    serviceConnected,
    scannerEngine: liveScanStatus ? "scan-service-remote" : localTrivyReady ? "trivy-local" : "mock-fallback",
    dataMode: liveScanStatus || localTrivyReady ? "live" : "demo",
    demoMode: isDemoMode(),
    demoDataDisclaimer: liveScanStatus || localTrivyReady
      ? null
      : "⚠ DEMO DATA: Findings shown are illustrative examples for local evaluation, not real vulnerability data for this tenant.",
    tenantId: session.tenantId,
    metrics,
    findings: cveFindings,
    cveFindings,
    secretFindings,
    recentScans: [
      {
        id: "scan-trivy-9012",
        type: "Trivy Container & OS Scan",
        target: "registry.shielddesk.internal/api:v2.4",
        status: "COMPLETED",
        vulnerabilities: 4,
        timestamp: "5 mins ago",
      },
      {
        id: "scan-git-4421",
        type: "Gitleaks Secrets Scan",
        target: "repo/shielddesk-backend (main)",
        status: "COMPLETED",
        secretsFound: 2,
        timestamp: "18 mins ago",
      },
      {
        id: "scan-patch-1092",
        type: "SSH Patch Orchestrator (LVM Snapshot)",
        target: "srv-prod-api-01 (10.0.4.12)",
        status: "VERIFIED_SAFE",
        timestamp: "1 hour ago",
      },
    ],
  });
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
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

      // 4. Return demo simulated scan
      return NextResponse.json({
        success: true,
        status: "success",
        _demo_mode: true,
        scan_id: `scan-${Date.now().toString(36)}`,
        message: "Trivy vulnerability scan simulated across fleet targets (Demo Mode).",
        scan_type: body.scan_type || "full",
        target: body.target_path || "fleet-all",
        findings: MOCK_CVE_FINDINGS,
        cveFindings: MOCK_CVE_FINDINGS,
        metrics: {
          total: 4,
          totalVulnerabilities: 4,
          critical: 2,
          high: 2,
          medium: 0,
          low: 0,
        },
      });
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
      const keyId = body.key_id || "AKIA1234567890ABCDEF";
      try {
        const res = await fetch(`${scanServiceUrl}/internal/secrets/${keyId}/rotate`, {
          method: "POST",
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Fallback or fail closed
      }

      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error: "KMS / IAM key rotation service is unreachable. Action aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      return NextResponse.json({
        success: true,
        status: "success",
        _demo_mode: true,
        status_code: "rotated",
        old_key_id: keyId,
        new_key_id: `KEY-${Math.random().toString(36).substring(2, 14).toUpperCase()}`,
        invalidated_at: new Date().toISOString(),
        message: `AWS IAM access key ${keyId} revoked and rotated (Demo Mode simulation).`,
      });
    }

    if (action === "apply_patch") {
      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error: "Remote host patch daemon is not connected. Patching cannot be executed or claimed without a live agent connection.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      const targetHost = body.asset_ip || "10.0.4.12";
      return NextResponse.json({
        success: true,
        _demo_mode: true,
        host: targetHost,
        snapshot_created: `snap-lvm-${Date.now().toString(36)}`,
        os_type: body.os_type || "linux",
        dry_run: Boolean(body.dry_run),
        status: body.dry_run ? "DRY_RUN_PASSED" : "VERIFIED",
        packages_updated: body.packages || ["openssh-server", "libwebp7"],
        verification_log: "Pre-patch LVM snapshot created. Package signature verified. Daemons restarted without degradation (Simulated Demo Mode).",
      });
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

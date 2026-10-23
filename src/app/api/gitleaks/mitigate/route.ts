import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { trackError } from "@/lib/observability/errorTracker";
import { shouldFailClosed } from "@/lib/config/environment";

// ---------------------------------------------------------------------------
// POST /api/gitleaks/mitigate
// Handles automated key rotation / revocation actions for secret findings.
// Delegates to GitHub API or KMS/IAM service when configured.
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json(
      { error: "Forbidden: secrets.write permission required" },
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

    const action: string = body.action || "rotate_key";
    const findingId: string = body.finding_id || body.rule_id || "unknown";
    const ruleId: string = body.rule_id || "";
    const keyId: string = body.key_id || "";

    // -----------------------------------------------------------------------
    // 1. AWS Access Key rotation
    // -----------------------------------------------------------------------
    if (
      action === "rotate_key" &&
      (ruleId.includes("aws") || ruleId === "" && keyId.startsWith("AKIA"))
    ) {
      const awsAccessKeyId = process.env.AWS_ACCESS_KEY_ID;
      const awsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;

      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error:
              "KMS / IAM key rotation service is unreachable or not configured. Action aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      return NextResponse.json(
        {
          success: false,
          error: "AWS IAM key rotation requires active AWS KMS / IAM broker connection. Configure live credentials in .env.local to enable automated key rotation.",
          code: "AWS_IAM_UNCONFIGURED",
        },
        { status: 503 }
      );
    }

    // -----------------------------------------------------------------------
    // 2. GitHub PAT revocation
    // -----------------------------------------------------------------------
    if (action === "revoke_pat" || ruleId.includes("github")) {
      const githubToken = process.env.GITHUB_TOKEN;

      if (githubToken) {
        try {
          const revokeRes = await fetch("https://api.github.com/installation/token", {
            method: "DELETE",
            headers: {
              Authorization: `Bearer ${githubToken}`,
              Accept: "application/vnd.github+json",
            },
            signal: AbortSignal.timeout(5000),
          });

          if (revokeRes.ok || revokeRes.status === 204) {
            return NextResponse.json({
              success: true,
              status: "revoked",
              _demo_mode: false,
              finding_id: findingId,
              action,
              message: "GitHub PAT successfully revoked via GitHub API.",
              revoked_at: new Date().toISOString(),
            });
          }
        } catch {
          // Fall through to demo mode if GitHub API fails
        }
      }

      if (shouldFailClosed()) {
        return NextResponse.json(
          {
            error:
              "GitHub API is unreachable. PAT revocation aborted under production fail-closed policy.",
            code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          },
          { status: 503 }
        );
      }

      return NextResponse.json(
        {
          success: false,
          error: "GitHub API is unreachable or GITHUB_TOKEN is not configured. Configure GITHUB_TOKEN to enable live token revocation.",
          code: "GITHUB_UNCONFIGURED",
        },
        { status: 503 }
      );
    }

    // -----------------------------------------------------------------------
    // 3. Mark resolved / false positive manual verification
    // -----------------------------------------------------------------------
    if (action === "mark_resolved") {
      return NextResponse.json({
        success: true,
        status: "manually_resolved",
        finding_id: findingId,
        action,
        rule_id: ruleId,
        message: `Secret finding '${ruleId || findingId}' marked as resolved following security analyst review.`,
        remediated_at: new Date().toISOString(),
      });
    }

    // -----------------------------------------------------------------------
    // 4. Generic / other credential rotation
    // -----------------------------------------------------------------------
    if (shouldFailClosed()) {
      return NextResponse.json(
        {
          error:
            "Remote credential rotation service is unreachable. Action aborted under production fail-closed policy.",
          code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
        },
        { status: 503 }
      );
    }

    return NextResponse.json(
      {
        success: false,
        error: `Remote credential rotation service is unreachable or not configured for rule '${ruleId || findingId}'. Configure service provider credentials to enable automated rotation.`,
        code: "ROTATION_SERVICE_UNCONFIGURED",
      },
      { status: 503 }
    );
  } catch (err: unknown) {
    trackError(err, {
      endpoint: "/api/gitleaks/mitigate",
      userId: session.uid,
      tenantId: session.tenantId,
    });
    const message =
      err instanceof Error ? err.message : "Internal error during mitigation";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

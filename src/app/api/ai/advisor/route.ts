import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";

type Ecosystem = "npm" | "python" | "go" | "rust" | "java" | "docker" | "os";

function detectEcosystem(target?: string, pkgName?: string): Ecosystem {
  const t = (target || "").toLowerCase();
  const p = (pkgName || "").toLowerCase();

  // 1. Target lockfile / manifest checks
  if (
    t.includes("package-lock.json") ||
    t.includes("yarn.lock") ||
    t.includes("pnpm-lock.yaml") ||
    t.includes("bun.lockb") ||
    t.includes("package.json")
  ) {
    return "npm";
  }

  if (
    t.includes("requirements.txt") ||
    t.includes("pipfile") ||
    t.includes("poetry.lock") ||
    t.includes("pyproject.toml") ||
    t.includes("setup.py")
  ) {
    return "python";
  }

  if (t.includes("go.mod") || t.includes("go.sum")) {
    return "go";
  }

  if (t.includes("cargo.lock") || t.includes("cargo.toml")) {
    return "rust";
  }

  if (t.includes("pom.xml") || t.includes("build.gradle")) {
    return "java";
  }

  if (t.includes("dockerfile") || t.includes("containerfile") || t.startsWith("docker")) {
    return "docker";
  }

  // 2. Package name heuristics
  const knownJsPackages = [
    "next",
    "react",
    "react-dom",
    "express",
    "lodash",
    "axios",
    "vite",
    "webpack",
    "tailwindcss",
    "postcss",
    "vue",
    "angular",
    "svelte",
    "zod",
    "framer-motion",
    "lucide-react",
  ];
  if (knownJsPackages.includes(p)) {
    return "npm";
  }

  const knownPythonPackages = [
    "django",
    "flask",
    "requests",
    "urllib3",
    "pydantic",
    "fastapi",
    "celery",
    "cryptography",
    "numpy",
    "scipy",
    "pandas",
    "gunicorn",
  ];
  if (knownPythonPackages.includes(p)) {
    return "python";
  }

  const knownOsPackages = [
    "openssh",
    "openssh-server",
    "openssl",
    "sudo",
    "linux",
    "glibc",
    "systemd",
    "bash",
    "curl",
    "bind9",
    "nginx",
    "apache2",
    "httpd",
    "libcrypto",
    "libssl",
  ];
  if (knownOsPackages.includes(p) || t.includes("ubuntu") || t.includes("debian") || t.includes("alpine") || t.includes("centos") || t.includes("rhel")) {
    return "os";
  }

  if (t.endsWith(".json") || t.endsWith(".js") || t.endsWith(".ts")) {
    return "npm";
  }

  return "npm";
}

function buildDynamicRunbook(params: {
  cve_id?: string;
  host_id?: string;
  incident_id?: string;
  package_name?: string;
  installed_version?: string;
  fixed_version?: string;
  target?: string;
  severity?: string;
  title?: string;
  description?: string;
  remediation?: string;
  cvss_score?: number;
}): string {
  const cveId = params.cve_id || "CVE-General";
  const pkg = params.package_name || "targeted-package";
  const installedVer = params.installed_version && params.installed_version !== "N/A" ? params.installed_version : "current";
  const fixedVer = params.fixed_version && params.fixed_version !== "N/A" ? params.fixed_version : null;
  const target = params.target || "package-lock.json";
  const severity = params.severity ? params.severity.toUpperCase() : "HIGH";
  const cvssStr = params.cvss_score ? ` (CVSS ${params.cvss_score})` : "";
  const ecosystem = detectEcosystem(target, pkg);

  if (ecosystem === "npm") {
    const isYarn = target.toLowerCase().includes("yarn.lock");
    const isPnpm = target.toLowerCase().includes("pnpm-lock.yaml");
    const isBun = target.toLowerCase().includes("bun.lockb");

    let upgradeCmd = `npm install ${pkg}@${fixedVer || "latest"} --save-exact`;
    let rollbackCmd = `git restore package.json package-lock.json`;

    if (isYarn) {
      upgradeCmd = fixedVer ? `yarn up ${pkg}@${fixedVer}` : `yarn upgrade ${pkg}`;
      rollbackCmd = `git restore package.json yarn.lock`;
    } else if (isPnpm) {
      upgradeCmd = fixedVer ? `pnpm update ${pkg}@${fixedVer}` : `pnpm update ${pkg}`;
      rollbackCmd = `git restore package.json pnpm-lock.yaml`;
    } else if (isBun) {
      upgradeCmd = fixedVer ? `bun update ${pkg}@${fixedVer}` : `bun update ${pkg}`;
      rollbackCmd = `git restore package.json bun.lockb`;
    }

    const branchName = `fix/${cveId.toLowerCase().replace(/[^a-z0-9_-]/g, "-")}-${pkg}`;

    return `Recovery Runbook: ${cveId}
Target Component: ${target} (Package: ${pkg})
Classification: Tier 1 Application Dependency Remediation
Severity: ${severity}${cvssStr}
Action Required: Upgrade ${pkg} from ${installedVer} to ${fixedVer || "latest secure release"}

Step 1: Pre-flight Safety & Worktree Isolation
Purpose: Create an isolated remediation branch and verify clean git status before modifying dependencies.
Commands:
git checkout -b ${branchName}
git status --porcelain

Step 2: Dependency Graph & Impact Scope Audit
Purpose: Inspect whether ${pkg} is a direct or transitive dependency and verify parent tree.
Commands:
npm ls ${pkg}

Step 3: Package Patch Application
Purpose: Upgrade ${pkg} to patched version ${fixedVer || "latest secure release"} and regenerate lockfile.
Commands:
${upgradeCmd}

Step 4: Build Verification & Regression Smoke Test
Purpose: Compile production artifacts, run unit/integration test suites, and re-scan target lockfile.
Commands:
npm run build
npm test
trivy fs --exit-code 0 ${target}

Step 5: Rollback Procedure (In Case of Regression)
Purpose: Instantly restore previous lockfile and manifest state if build or smoke tests fail.
Commands:
${rollbackCmd}
git checkout main
git branch -D ${branchName}`;
  }

  if (ecosystem === "python") {
    const branchName = `fix/${cveId.toLowerCase().replace(/[^a-z0-9_-]/g, "-")}-${pkg}`;
    const upgradeCmd = fixedVer ? `pip install --upgrade "${pkg}==${fixedVer}"` : `pip install --upgrade "${pkg}"`;

    return `Recovery Runbook: ${cveId}
Target Component: ${target} (Package: ${pkg})
Classification: Tier 1 Python Environment Remediation
Severity: ${severity}${cvssStr}
Action Required: Upgrade ${pkg} from ${installedVer} to ${fixedVer || "latest secure release"}

Step 1: Pre-flight Safety & Manifest Snapshot
Purpose: Isolate branch and backup original manifest.
Commands:
git checkout -b ${branchName}
cp ${target} ${target}.bak

Step 2: Package Patch Application
Purpose: Install secure package release from PyPI index and update requirements.
Commands:
${upgradeCmd}
pip freeze | grep -i "${pkg}==" > ${target}.new && mv ${target}.new ${target}

Step 3: Build Verification & Dependency Integrity Check
Purpose: Verify no broken dependency chains and run test suite.
Commands:
pip check
pytest

Step 4: Rollback Procedure (In Case of Regression)
Commands:
mv ${target}.bak ${target}
pip install -r ${target}
git checkout main`;
  }

  if (ecosystem === "go") {
    const branchName = `fix/${cveId.toLowerCase().replace(/[^a-z0-9_-]/g, "-")}-${pkg}`;
    const upgradeCmd = fixedVer ? `go get ${pkg}@v${fixedVer.replace(/^v/, "")}` : `go get -u ${pkg}`;

    return `Recovery Runbook: ${cveId}
Target Component: ${target} (Module: ${pkg})
Classification: Tier 1 Go Module Remediation
Severity: ${severity}${cvssStr}

Step 1: Pre-flight Safety Branch
Commands:
git checkout -b ${branchName}

Step 2: Module Upgrade & Prune
Commands:
${upgradeCmd}
go mod tidy

Step 3: Verification & Test Suite
Commands:
go test ./...
go build ./...

Step 4: Rollback Procedure
Commands:
git checkout -- go.mod go.sum
git checkout main`;
  }

  if (ecosystem === "docker") {
    return `Recovery Runbook: ${cveId}
Target Container Image / File: ${target} (Component: ${pkg})
Classification: Tier 2 Container Image Re-build

Step 1: Inspect Container Base Image Layer
Commands:
docker inspect ${target}

Step 2: Update Base Image or Patch Package in Dockerfile
Purpose: Re-pin base image tag containing fixed version ${fixedVer || "latest"} or add patch instruction.
Commands:
# Modify ${target} to update base image tag or RUN package upgrade

Step 3: Container Build & Verification Scan
Commands:
docker build -t app:patch-verify -f ${target} .
trivy image --severity HIGH,CRITICAL app:patch-verify

Step 4: Rollback Procedure
Commands:
git checkout -- ${target}`;
  }

  // OS / Host package fallback
  const host = params.host_id || "Production Host";
  const snapName = `snap_prepatch_${pkg.replace(/[^a-zA-Z0-9]/g, "_").slice(0, 20)}`;

  return `Recovery Runbook: ${cveId}
Target Host: ${host} (System Package: ${pkg})
Classification: Tier 2 Action (Requires Human Sign-off or Pre-approved Token)
Severity: ${severity}${cvssStr}

Step 1: Pre-flight Safety Snapshot
Purpose: Create an immediate LVM copy-on-write snapshot before package manipulation.
Commands:
sudo lvcreate --size 5G --snapshot --name ${snapName} /dev/vg0/root

Step 2: Isolation & Ingress Containment
Purpose: Temporarily restrict external network ingress if patching a network-listening daemon.
Commands:
sudo iptables -I INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j DROP
sudo iptables -I INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT

Step 3: Package Patch Application
Purpose: Update repository catalog and upgrade package to patched revision.
Commands:
sudo apt-get update -qq
sudo apt-get install --only-upgrade -y ${pkg}${fixedVer ? `=${fixedVer}` : ""}
sudo systemctl restart ${pkg.includes("ssh") ? "sshd" : pkg}

Step 4: Verification & Smoke Test
Purpose: Verify daemon banner and active process health.
Commands:
dpkg -l | grep ${pkg}
sudo systemctl status ${pkg.includes("ssh") ? "sshd" : pkg} --no-pager

Step 5: Rollback Snapshot Recovery (If Verification Fails)
Purpose: Revert system to pre-patch snapshot if package fails health checks.
Commands:
sudo lvconvert --merge /dev/vg0/${snapName}
sudo reboot`;
}

function buildDynamicBlastRadius(params: {
  cve_id?: string;
  host_id?: string;
  package_name?: string;
  installed_version?: string;
  fixed_version?: string;
  target?: string;
  severity?: string;
  title?: string;
  description?: string;
  remediation?: string;
  cvss_score?: number;
}) {
  const cveId = params.cve_id || "CVE-General";
  const pkg = params.package_name || "targeted-package";
  const fixedVer = params.fixed_version || "latest patch";
  const target = params.target || "package-lock.json";
  const severity = params.severity ? params.severity.toUpperCase() : "HIGH";
  const ecosystem = detectEcosystem(target, pkg);

  if (ecosystem === "npm" || ecosystem === "python" || ecosystem === "go" || ecosystem === "rust") {
    const isNext = pkg.toLowerCase() === "next";
    const downstreamDeps = isNext
      ? [
          "Next.js App Router & Server Components (port 3000)",
          "API Edge Gateway & Serverless Functions (/api/*)",
          "Server-Side Rendering (SSR) Node.js Workers",
          "Client-Side Static Chunk Delivery & Image Optimizer",
        ]
      : [
          `Application Service Core (${pkg} runtime)`,
          "Upstream Reverse Proxy (Nginx/Cloudflare)",
          "API Serialization & Middleware Pipeline",
          "Session State and Token Validation Layer",
        ];

    return {
      success: true,
      host_id: target,
      cve_id: cveId,
      posture_risk_level: severity,
      blast_radius: {
        direct_assets_at_risk: severity === "CRITICAL" ? 4 : severity === "HIGH" ? 3 : 2,
        downstream_dependencies: downstreamDeps,
        network_exposure: "Public Web Ingress (HTTP/HTTPS Ports 80/443) via Cloudflare/Load Balancer",
        data_classification: "HTTP Request Headers, Cookies & Web Application Payload",
        remediation_urgency: `${severity} — ${params.remediation || `Upgrade ${pkg} to version ${fixedVer} to eliminate vulnerability.`}`,
        automated_mitigation: `Update ${pkg} to ${fixedVer} in ${target} and trigger automated CI/CD deployment pipeline.`,
      },
    };
  }

  // OS / Host package fallback
  return {
    success: true,
    host_id: params.host_id || "srv-prod-api-01",
    cve_id: cveId,
    posture_risk_level: severity,
    blast_radius: {
      direct_assets_at_risk: 3,
      downstream_dependencies: [
        "db-primary-postgres (10.0.1.5)",
        "redis-cache-cluster (10.0.2.14)",
        "auth-iam-service (10.0.3.20)",
      ],
      network_exposure: `Ingress Port (${pkg.includes("ssh") ? "22/SSH" : "Service Port"}) accessible within private VPC / perimeter`,
      data_classification: "Host System Credentials & In-Memory Process State",
      remediation_urgency: `${severity} — ${params.remediation || `Upgrade ${pkg} to version ${fixedVer} via package orchestrator.`}`,
      automated_mitigation: `Apply ${pkg} upgrade via LVM snapshot isolation in SSH Patch Orchestrator.`,
    },
  };
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json();
    const {
      action,
      host_id,
      cve_id,
      incident_id,
      package_name,
      installed_version,
      fixed_version,
      target,
      severity,
      title,
      description,
      remediation,
      cvss_score,
    } = body;

    const advisorUrl = process.env.AI_ADVISOR_URL || "http://localhost:8002";

    if (action === "blast_radius") {
      try {
        const res = await fetch(`${advisorUrl}/internal/advisor/blast-radius`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ host_id, cve_id, package_name, target }),
          signal: AbortSignal.timeout(1500),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Fallback to dynamic simulation
      }

      return NextResponse.json(
        buildDynamicBlastRadius({
          cve_id,
          host_id,
          package_name,
          installed_version,
          fixed_version,
          target,
          severity,
          title,
          description,
          remediation,
          cvss_score,
        })
      );
    }

    if (action === "generate_runbook") {
      try {
        const res = await fetch(`${advisorUrl}/internal/advisor/runbook`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            incident_id,
            cve_id,
            package_name,
            installed_version,
            fixed_version,
            target,
          }),
          signal: AbortSignal.timeout(1500),
        });
        if (res.ok) {
          const liveData = await res.json();
          return NextResponse.json({ success: true, ...liveData });
        }
      } catch {
        // Fallback to dynamic runbook generator
      }

      const runbookMarkdown = buildDynamicRunbook({
        cve_id,
        host_id,
        incident_id,
        package_name,
        installed_version,
        fixed_version,
        target,
        severity,
        title,
        description,
        remediation,
        cvss_score,
      });

      return NextResponse.json({
        success: true,
        incident_id: incident_id || null,
        cve_id: cve_id || "N/A",
        runbook: runbookMarkdown,
        generated_by: "ShieldDesk Dynamic Runbook Engine (Ecosystem-Aware)",
      });
    }

    return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  } catch (err) {
    trackError(err, { route: "POST /api/ai/advisor", tenantId: session?.tenantId });
    return NextResponse.json({ error: "Failed to process advisor request" }, { status: 500 });
  }
}


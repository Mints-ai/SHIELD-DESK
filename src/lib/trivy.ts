import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";

const execFileAsync = promisify(execFile);

export interface CveFinding {
  id: string;
  cve_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  pkgName: string;
  package_name: string;
  installedVersion: string;
  installed_version: string;
  fixedVersion?: string;
  fixed_version?: string;
  title: string;
  description: string;
  target?: string;
  primaryUrl?: string;
  cvss_score?: number;
  epss_score?: number;
  remediation: string;
}

export interface ScanResult {
  findings: CveFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  scannedTarget: string;
  scanDurationMs: number;
  binaryPath: string;
}

/**
 * Searches for a usable Trivy executable across established paths and PATH.
 */
export function getTrivyBinaryPath(): string | null {
  const candidates: string[] = [];

  if (process.env.TRIVY_PATH) {
    candidates.push(process.env.TRIVY_PATH);
  }

  const cwd = process.cwd();
  candidates.push(
    path.join(cwd, "tools", "trivy", "trivy.exe"),
    path.join(cwd, "tools", "trivy", "trivy_0.74.0_windows-64bit", "trivy.exe"),
    "C:\\trivy\\trivy.exe",
    path.join(cwd, "tools", "trivy", "trivy"),
    "/usr/local/bin/trivy",
    "/usr/bin/trivy"
  );

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Check system PATH
  const pathEnv = process.env.PATH || "";
  const pathDirs = pathEnv.split(path.delimiter);
  const exeNames = process.platform === "win32" ? ["trivy.exe", "trivy.cmd", "trivy"] : ["trivy"];

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
 * Verifies if Trivy is installed and executable in this environment.
 */
export function isTrivyAvailable(): boolean {
  return Boolean(getTrivyBinaryPath());
}

/**
 * Runs a Trivy vulnerability scan against a filesystem path or container image.
 *
 * Security & Reliability Guards:
 * - Uses execFile with structured argv array (no shell interpolation) to prevent CWE-78 command injection.
 * - Validates input parameters and guards against CLI argument injection.
 * - Handles Windows and non-container path resolution (e.g. converting non-existent '/app' to root).
 * - Enforces maxBuffer of 30MB to prevent crashes on large dependency trees.
 * - Extracts and normalizes CVSS, target metadata, and remediation advice.
 */
export async function runTrivyScan(
  target: string = ".",
  type: "fs" | "image" = "fs"
): Promise<ScanResult> {
  const startTime = Date.now();
  const trivyBin = getTrivyBinaryPath();

  if (!trivyBin) {
    throw new Error(
      "Trivy scanner binary not found on host. Please run 'npm run setup:trivy' or install Trivy into tools/trivy/ or PATH."
    );
  }

  // Security guard: disallow flags passed in target string (CLI option injection prevention)
  if (typeof target !== "string" || target.trim().startsWith("-")) {
    throw new Error("Invalid target parameter: target cannot start with a hyphen or CLI flag.");
  }

  let resolvedTarget = target.trim();
  if (type === "fs") {
    // If frontend sent container-oriented '/app' but host does not have '/app', fallback safely to project root
    if ((resolvedTarget === "/app" || resolvedTarget === "\\app") && !fs.existsSync(resolvedTarget)) {
      resolvedTarget = process.cwd();
    } else if (resolvedTarget === "." || resolvedTarget === "") {
      resolvedTarget = process.cwd();
    } else {
      resolvedTarget = path.resolve(process.cwd(), resolvedTarget);
      if (!fs.existsSync(resolvedTarget)) {
        throw new Error(`Target path does not exist on filesystem: ${resolvedTarget}`);
      }
    }
  }

  const args: string[] = [
    type,
    "--format",
    "json",
    "--quiet",
    "--scanners",
    "vuln",
  ];

  if (type === "fs") {
    args.push(
      "--skip-dirs",
      ".next,node_modules,tools,pgdata,.git,dist,build,coverage",
      resolvedTarget
    );
  } else {
    args.push(resolvedTarget);
  }

  try {
    const { stdout } = await execFileAsync(trivyBin, args, {
      maxBuffer: 30 * 1024 * 1024, // 30 MB buffer limit
      timeout: 180000, // 3 minutes timeout
      windowsHide: true,
    });

    const parsed = stdout.trim() ? JSON.parse(stdout) : {};
    const findings: CveFinding[] = [];
    const seenFindingKeys = new Set<string>();

    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };

    if (Array.isArray(parsed.Results)) {
      for (const result of parsed.Results) {
        const targetComponent = result.Target || "filesystem";
        if (Array.isArray(result.Vulnerabilities)) {
          for (const v of result.Vulnerabilities) {
            const cveId = v.VulnerabilityID || "UNKNOWN-CVE";
            const pkgName = v.PkgName || "unknown";
            const installedVersion = v.InstalledVersion || "unknown";
            const dedupKey = `${cveId}:${pkgName}:${installedVersion}:${targetComponent}`;

            if (seenFindingKeys.has(dedupKey)) {
              continue;
            }
            seenFindingKeys.add(dedupKey);

            const rawSeverity = (v.Severity || "UNKNOWN").toUpperCase();
            const severity: CveFinding["severity"] =
              rawSeverity === "CRITICAL"
                ? "CRITICAL"
                : rawSeverity === "HIGH"
                ? "HIGH"
                : rawSeverity === "MEDIUM"
                ? "MEDIUM"
                : rawSeverity === "LOW"
                ? "LOW"
                : "UNKNOWN";

            const fixedVersion = v.FixedVersion || undefined;
            const title = v.Title || v.Description || "No CVE description available";
            const description = v.Description || v.Title || "";

            // Extract CVSS score if present (check NVD or vendor scores)
            let cvssScore: number | undefined;
            if (v.CVSS) {
              for (const vendor of Object.keys(v.CVSS)) {
                const vendorScore = v.CVSS[vendor]?.V3Score || v.CVSS[vendor]?.V2Score;
                if (typeof vendorScore === "number") {
                  cvssScore = vendorScore;
                  break;
                }
              }
            }

            const remediation = fixedVersion
              ? `Upgrade ${pkgName} to version ${fixedVersion} or later.`
              : `No official fix available yet for ${pkgName} ${installedVersion}. Monitor upstream advisory.`;

            findings.push({
              id: cveId,
              cve_id: cveId,
              severity,
              pkgName,
              package_name: pkgName,
              installedVersion,
              installed_version: installedVersion,
              fixedVersion,
              fixed_version: fixedVersion || "N/A",
              title,
              description,
              target: targetComponent,
              primaryUrl: v.PrimaryURL,
              cvss_score: cvssScore,
              remediation,
            });

            const sevLower = severity.toLowerCase() as keyof typeof summary;
            if (typeof summary[sevLower] === "number") {
              summary[sevLower]++;
            } else {
              summary.unknown++;
            }
          }
        }
      }
    }

    const scanOutput: ScanResult = {
      findings,
      summary,
      scannedTarget: resolvedTarget,
      scanDurationMs: Date.now() - startTime,
      binaryPath: trivyBin,
    };

    lastScanResult = scanOutput;
    return scanOutput;
  } catch (error: any) {
    console.error("[Trivy Execution Error]", error.message || error);
    throw new Error(`Trivy scan execution failed: ${error.message || String(error)}`);
  }
}

let lastScanResult: ScanResult | null = null;

export function getLastScanResult(): ScanResult | null {
  return lastScanResult;
}

export function setLastScanResult(result: ScanResult | null): void {
  lastScanResult = result;
}

/**
 * Returns the cached scan result if available, or initiates a fresh scan.
 */
export async function getOrRunTrivyScan(
  target: string = ".",
  type: "fs" | "image" = "fs"
): Promise<ScanResult> {
  if (lastScanResult && lastScanResult.findings.length > 0) {
    return lastScanResult;
  }
  return await runTrivyScan(target, type);
}

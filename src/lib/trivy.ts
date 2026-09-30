import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";

const execPromise = promisify(exec);

export interface CveFinding {
  id: string;
  severity: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion?: string;
  title: string;
}

export interface ScanResult {
  findings: CveFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export async function runTrivyScan(target: string = ".", type: "fs" | "image" = "fs"): Promise<ScanResult> {
  const localExe = path.join(process.cwd(), "tools", "trivy", "trivy.exe");
  const trivyBin = fs.existsSync(localExe) ? `"${localExe}"` : "trivy";

  try {
    const command =
      type === "fs"
        ? `${trivyBin} fs --format json --skip-dirs .next,node_modules "${target}"`
        : `${trivyBin} image --format json "${target}"`;

    const { stdout } = await execPromise(command);
    const data = JSON.parse(stdout);

    const findings: CveFinding[] = [];
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };

    if (data.Results) {
      for (const result of data.Results) {
        if (result.Vulnerabilities) {
          for (const v of result.Vulnerabilities) {
            findings.push({
              id: v.VulnerabilityID,
              severity: v.Severity,
              pkgName: v.PkgName,
              installedVersion: v.InstalledVersion,
              fixedVersion: v.FixedVersion,
              title: v.Title || "No title provided",
            });

            const sev = v.Severity.toLowerCase();
            if (summary.hasOwnProperty(sev)) {
              summary[sev as keyof typeof summary]++;
            }
          }
        }
      }
    }

    return { findings, summary };
  } catch (error: any) {
    console.error("Trivy Execution Error:", error);
    throw new Error(`Trivy scan failed: ${error.message}`);
  }
}

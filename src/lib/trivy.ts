import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';

const execPromise = promisify(exec);

// Use a path relative to the project root
const TRIVY_PATH = path.join(process.cwd(), 'tools', 'trivy', 'trivy.exe');

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

export async function runTrivyScan(target: string = '.', type: 'fs' | 'image' = 'fs'): Promise<ScanResult> {
  try {
    // Use the absolute path to the trivy binary
    // Use --skip-dirs instead of --skip-dir for newer Trivy versions
    const command = type === 'fs' 
      ? `"${TRIVY_PATH}" fs --format json --skip-dirs .next,node_modules ${target}` 
      : `"${TRIVY_PATH}" image --format json ${target}`;

    const { stdout } = await execPromise(command);
    const data = JSON.parse(stdout);

    const findings: CveFinding[] = [];
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };

    // Trivy JSON structure: Results is an array of targets
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
              title: v.Title || 'No title provided',
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
    console.error('Trivy Execution Error:', error);
    throw new Error(`Trivy scan failed: ${error.message}`);
  }
}

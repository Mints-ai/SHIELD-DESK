# ShieldDesk Gitleaks Secret Scanner

> **Automated regex and high-entropy secret detection engine scanning Git repository history and commits for exposed credentials, API keys, and sensitive tokens.**

---

## 1. Overview & Purpose

**Gitleaks** is integrated into ShieldDesk as the core secret detection engine. It continuously audits source code repositories for exposed credentials before and after they reach production.

### Why Git Repository Scanning (vs. Filesystem Scanning)?
* **Git Repository History**: Every commit made in Git creates an immutable snapshot. If a developer accidentally commits an API key and then deletes it in a subsequent commit, the key remains exposed forever in `.git` history. ShieldDesk scans the full Git commit log to detect these exposed secrets.
* **Filesystem / System Files**: Local configuration files (such as `.env.local`) are kept locally by developers and ignored via `.gitignore`. ShieldDesk restricts Gitleaks to **Git repository objects** so local developer configurations are not flagged as repository leaks.

---

## 2. Quick Start & Installation

ShieldDesk bundles an automated installation script for Windows:

### Installation
Run the npm script from the project root:
```powershell
npm run setup:gitleaks
```
Or execute the PowerShell script directly:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_gitleaks.ps1
```

### What the Setup Script Does:
1. Downloads the verified Gitleaks release binary (`v8.30.1`) from official GitHub releases.
2. Extracts `gitleaks.exe` into the `tools/gitleaks/` directory.
3. Verifies binary integrity and execution permissions.
4. Ensures `.gitleaks.toml` configuration exists at the project root.

### Verification
```powershell
.\tools\gitleaks\gitleaks.exe version
# Output: 8.30.1
```

---

## 3. Architecture & Data Flow

```
┌────────────────────────────────────────────────────────┐
│             ShieldDesk Web Dashboard                   │
│         (/dashboard/scanner -> Secret Tab)             │
└──────────────────────────┬─────────────────────────────┘
                           │ 1. User clicks "Scan Repository Now"
                           ▼
┌────────────────────────────────────────────────────────┐
│           Next.js API: POST /api/gitleaks/scan         │
│         - RBAC Check (cve.read / secrets.read)         │
│         - Session Validation                           │
└──────────────────────────┬─────────────────────────────┘
                           │ 2. Calls runGitleaksScan(".", { noGit: false })
                           ▼
┌────────────────────────────────────────────────────────┐
│       ShieldDesk Core Wrapper: src/lib/gitleaks.ts     │
│       - Resolves binary path                           │
│       - Enforces Structured execFile (CWE-78 safe)     │
│       - Enforces --redact, 120s timeout, 10MB buffer   │
└──────────────────────────┬─────────────────────────────┘
                           │ 3. Executes CLI
                           ▼
┌────────────────────────────────────────────────────────┐
│             tools/gitleaks/gitleaks.exe                │
│    detect --source . --report-format json --redact     │
└─────────────┬────────────────────────────┬─────────────┘
              │                            │
   Scans Git Commits              Filters False Positives
              ▼                            ▼
┌───────────────────────────┐ ┌──────────────────────────┐
│   .git Commit Database    │ │     .gitleaks.toml       │
│  (Commits, Authors, Dates)│ │ (Allowlists & Stopwords) │
└─────────────┬─────────────┘ └──────────────────────────┘
              │
              ▼ JSON Stream Output (stdout)
┌────────────────────────────────────────────────────────┐
│       parseGitleaksOutput() & classifyRisk()           │
│       - Risk: CRITICAL | HIGH | MEDIUM                 │
│       - Formats Commit SHA, Author, Line Number        │
│       - Normalizes relative file paths                 │
└──────────────────────────┬─────────────────────────────┘
                           │ 4. JSON Payload
                           ▼
┌────────────────────────────────────────────────────────┐
│        Frontend Table & Remediation Modal              │
│        - Displays finding card with commit metadata    │
│        - Provides git filter-repo purge command        │
│        - Automated key revocation / mark resolved      │
└────────────────────────────────────────────────────────┘
```

---

## 4. Key Files in ShieldDesk

| File | Purpose |
| :--- | :--- |
| [`tools/gitleaks/gitleaks.exe`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/tools/gitleaks/gitleaks.exe) | The compiled Gitleaks binary executable. |
| [`scripts/setup_gitleaks.ps1`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/scripts/setup_gitleaks.ps1) | Automated download, extraction, and verification script. |
| [`.gitleaks.toml`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/.gitleaks.toml) | Rule allowlist, path exclusions, regex suppressions, and stop words. |
| [`src/lib/gitleaks.ts`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/src/lib/gitleaks.ts) | Core TypeScript wrapper, process runner, risk classification, and cache. |
| [`src/app/api/gitleaks/scan/route.ts`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/src/app/api/gitleaks/scan/route.ts) | API endpoint (`GET` for cached findings, `POST` to trigger a new scan). |
| [`src/app/api/gitleaks/mitigate/route.ts`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/src/app/api/gitleaks/mitigate/route.ts) | Remediation orchestrator (key rotation, PAT revocation, resolution). |
| [`src/app/dashboard/scanner/page.tsx`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/src/app/dashboard/scanner/page.tsx) | UI tab for secret detection, finding inspection, and remediation dialogs. |

---

## 5. Configuration & Allowlisting (`.gitleaks.toml`)

ShieldDesk uses a root-level [`.gitleaks.toml`](file:///c:/Users/DELL/OneDrive/Desktop/Sheild%20desk/SHIELD-DESK/.gitleaks.toml) extending default rules:

### Path Exclusions
Paths containing test fixtures, mock data, or build artifacts are ignored:
```toml
[allowlist]
paths = [
  '''.*test.*''',
  '''.*mock.*''',
  '''.*node_modules.*''',
  '''.*\.next.*''',
  '''.*tools/gitleaks.*''',
  '''.*tools/trivy.*''',
  '''.*README\.md'''
]
```

### Stop Words & Safe Patterns
Safe placeholders and redaction tokens are suppressed:
```toml
stopwords = [
  "REDACTED",
  "DEMO",
  "PLACEHOLDER",
  "EXAMPLE"
]
```

---

## 6. Scanning Modes

| Parameter | Mode | Description |
| :--- | :--- | :--- |
| `noGit: false` | **Git Repository Mode** *(ShieldDesk Standard)* | Scans Git commits and history. Extracts commit SHA, author, date, and commit message. Untracked files like `.env.local` are ignored. |
| `noGit: true` | **Filesystem Mode** | Bypasses Git and walks raw disk folders. (Not used for repository scanning). |

---

## 7. Remediation Workflow

When a secret is detected in Git history, ShieldDesk offers three remediation paths:

### 1. Scrub Secret from Git Repository History
Because Git is an immutable ledger, simply deleting the sensitive line in a new commit **leaves the secret exposed in historical commits**. To completely purge the secret from Git history, use `git-filter-repo`:

```bash
# Scrub the affected file from all historical commits:
git filter-repo --path "path/to/file" --invert-paths
```
*Note: After rewriting history, force push with `git push origin --force --all`.*

### 2. Automated Credential Revocation & Rotation
Clicking **"Revoke / Rotate Key"** in the ShieldDesk UI triggers `/api/gitleaks/mitigate`:
* **AWS Keys (`AKIA...`)**: Flags key in AWS IAM and issues a rotated access key.
* **GitHub Tokens (`ghp_...`)**: Dispatches token revocation request to the GitHub API.
* **Generic API Keys**: Dispatches token invalidation events to downstream microservices.

### 3. Mark as Resolved / False Positive
If an analyst verifies that the finding is an inactive test string or non-sensitive token, clicking **"Mark as Resolved"** stores the finding hash as resolved in the audit trail.

---

## 8. CLI Usage Reference

You can also run Gitleaks directly from your terminal:

```powershell
# Scan repository history with redacted output
.\tools\gitleaks\gitleaks.exe detect --source . --redact -v

# Scan only the last 20 commits
.\tools\gitleaks\gitleaks.exe detect --source . --log-opts "HEAD~20..HEAD" --redact

# Generate a SARIF or JSON report
.\tools\gitleaks\gitleaks.exe detect --source . --report-format json --report-path report.json
```

---

## 9. Security Guards Implemented in ShieldDesk

1. **No Flag/Command Injection (CWE-78)**: Target paths and log options are strictly sanitized and executed via structured `execFile` argument vectors rather than shell interpolation.
2. **Mandatory Redaction**: `--redact` is enforced by default; plaintext secret values are never rendered in logs, API responses, or the user interface.
3. **Fail-Closed Policy**: If running in production with `FAIL_CLOSED=true` and the Gitleaks scanner is unavailable, requests abort safely to prevent unmonitored deployments.

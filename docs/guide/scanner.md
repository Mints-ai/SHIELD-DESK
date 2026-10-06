# Security Scanner

**URL:** `/dashboard/scanner`

Runs on-demand vulnerability assessments against your fleet.

## Running a Scan

1. Select a **scan profile** (Quick Scan, Full CVE Scan, Compliance Check)
2. Choose a **target scope** — all agents, a group, or individual hosts
3. Click **Start Scan**

## Reading Results

Each finding shows:

- **CVE ID** — standard vulnerability reference
- **CVSS severity** — 0-10 score
- **Affected package** and current installed version
- **Recommended action** with a direct link to generate a mitigation plan

## Severity Colour Coding

| Colour | Severity | Action |
|--------|----------|--------|
| 🔴 Red | **Critical** | Patch immediately — likely actively exploited |
| 🟠 Orange | **High** | Patch within 7 days per your SLA |
| 🟡 Yellow | **Medium** | Patch in next maintenance window |
| 🟢 Green | **Low / Info** | Monitor; patch at your discretion |

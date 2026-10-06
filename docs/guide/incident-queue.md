# Incident Queue

**URL:** `/` (main dashboard)

This is your primary workspace. It shows every active security incident for your organisation.

## Layout

The screen is split into two panels:

- **Right sidebar** — Incident Queue: scrollable list of all active incidents for your tenant
- **Left panel** — Incident Detail: full investigation view for the selected incident

## The Incident Queue Sidebar

Each card shows:

- **Incident Code** (e.g. `INC-1042`) — unique reference ID
- **Severity badge** — CRITICAL (red), HIGH (amber), MEDIUM (grey), LOW (green)
- **Title** — one-line summary of the threat
- **Status** — `open`, `investigating`, `resolved`, or `closed`
- **Detection time**

**Filtering:** Use the pill buttons (`ALL` / `CRITICAL` / `HIGH` / `MEDIUM`) to filter instantly.

**Selecting:** Click any card to load its full detail. The active card gets a green border.

## Incident Detail Panel

### Header Strip

- Incident Code, Severity Badge, and current Status
- Action buttons:
  - **Investigate with AI** — opens the AI chat pre-loaded with this incident
  - **Plan Mitigation** — asks AI to generate a full remediation plan
  - **View Plans** — jumps to the Mitigation Plans page
  - **Inspect Mitigation Plan** — direct link to an existing plan (when one exists)

### Incident Description

Plain-English summary of what happened, which systems were involved, and initial attack indicators.

### Impacted Assets

Every host within the blast radius. Shows hostname and asset type (e.g. `edge-router-01` / `network_device`).

### Attack Timeline

Chronological event log, oldest to newest, so you can trace the full kill chain. Each entry shows a precise timestamp and what was observed.

### Linked Threat Intelligence

When a CVE is correlated with the incident:

| Field | Description |
|-------|-------------|
| **CVSS Score** | Severity (e.g. 7.5 / HIGH) |
| **Autonomy Gate** | Required approval tier before containment |
| **CWE Classification** | Root vulnerability class (e.g. CWE-400) |
| **Remediation SLA** | Your organisation's time limit for this severity |

Click **Deep Threat Analysis** to have the AI explain the CVE in plain English.

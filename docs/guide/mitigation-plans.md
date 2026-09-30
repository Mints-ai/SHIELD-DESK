# Mitigation Plans

**URL:** `/dashboard/plans`

When the AI generates a remediation plan for an incident, it appears here.

## The 3-Horizon Framework

All plans are structured in three horizons:

| Horizon | Timeframe | Focus |
|---------|-----------|-------|
| **H1 — Containment** | Hours | Isolate hosts, revoke sessions, block IPs |
| **H2 — Eradication** | Days | Patch systems, rotate credentials, scan for persistence |
| **H3 — Recovery** | Weeks | Restore operations, harden defences, update runbooks |

## Plan List

The index shows all plans for your tenant:

- Linked incident code and title
- Plan status (`in_progress`, `approved`, `completed`)
- Number of tasks
- Search and filter by severity

Click any plan to view individual task assignments, approval requirements, and progress.

## Creating a Plan

Click **"Plan Mitigation"** from the Incident Queue. The AI generates a structured 3-horizon plan automatically. You review and approve each task before it executes.

> You do not need to write plans manually.

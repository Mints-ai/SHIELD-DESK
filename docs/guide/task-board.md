# Task Board

**URL:** `/dashboard/tasks`

Tracks every individual action item across all mitigation plans.

## Task Lifecycle

```
Draft  →  Pending Approval  →  Approved  →  In Progress  →  Completed
                           ↘  Rejected
```

## Creating a Task

Analysts and above can create tasks:

1. Click **New Task**
2. Select a tier (Tier 1 / 2 / 3) based on the action's risk
3. Describe the action and assign it to a team member
4. Submit — Tier 2 and 3 tasks enter the approval queue automatically

> **Viewers cannot create tasks.** If "New Task" is absent or greyed out, your role is Viewer.

## Task Tiers

| Tier | Risk Level | Who Must Approve |
|------|------------|-----------------|
| **Tier 1** | Low-risk, reversible | Analyst or above |
| **Tier 2** | Host isolation, patching | Responder or above |
| **Tier 3** | Break-glass / destructive | Super Admin or above |

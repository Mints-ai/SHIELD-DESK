# Approval Workflow

ShieldDesk enforces **human-in-the-loop** for all consequential actions. No command, isolation, or network change executes without a qualified human approving it first.

## How It Works

```
1. Action proposed (AI, analyst, or automated rule)
2. Approval token created — nothing executes yet
3. Red badge appears on Approvals button
4. Reviewer opens the Approval modal
5. Reviewer approves or rejects with justification
6. Decision written to immutable audit trail
```

## Who Can Approve What

| Token Tier | Minimum Role Required |
|------------|----------------------|
| **Tier 1** — Low-risk, reversible | Analyst |
| **Tier 2** — Host isolation, patching | Responder |
| **Tier 3** — Break-glass, destructive | Super Admin |

## The Approval Modal

When you click the Approvals button you see:

- **Action type** and the targeted agent or host
- **Proposed by** — analyst or AI agent that raised the action
- **Tier** and justification text
- **JSON payload** — the exact command that will be sent to the fleet agent
- **Approve** and **Reject** buttons

Every decision (who acted, when, what was decided) is written to an immutable audit trail.

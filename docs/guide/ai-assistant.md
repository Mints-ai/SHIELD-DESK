# AI Assistant

The AI assistant is available as a floating chat panel on every page in the platform.

## Opening the Chat

- Click the **chat icon** in the bottom-right corner of any page, or
- Click **"Investigate with AI"** or **"Plan Mitigation"** from an incident — these open the chat pre-loaded with context

## What You Can Ask

The AI understands natural language. Examples:

```
Investigate INC-1042 and tell me what happened
Generate a mitigation plan for the VPN exploitation
Analyze CVE-2024-3400 and explain the risk to our environment
What is the blast radius if CVE-2020-6240 hits our fleet?
Show me all critical incidents from this week
```

## Autonomy Tiers

When the AI recommends an action, it assigns a tier that controls the approval gate:

| Tier | Label | What happens |
|------|-------|--------------|
| **Tier 1** | Auto-Containment | Queued for execution after Analyst confirmation |
| **Tier 2** | Human Sign-off Required | Sent to Approvals; a Responder or above must approve |
| **Tier 3** | Break-Glass | Super Admin must explicitly approve before execution |

## AI Guardrails

The AI is hardened against manipulation:

- Refuses prompt injection and role-override attempts
- Will not output credentials, private keys, or PII
- All AI-generated actions require human approval before affecting real systems

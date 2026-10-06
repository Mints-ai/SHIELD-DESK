# Navigating the Platform

After logging in you land on the **Incident Queue** — the main SOC dashboard.

## Top Navigation Bar

```
ShieldDesk | Incident Queue | Mitigation Plans | Task Board | Fleet & Host
           | Security Scanner | Threat Engine | ISO 27001 Audit | Risk Scorecard
                                              [Approvals Badge]  [Health Dots]
```

## Health Indicators

Live status dots in the top-right show the state of backend services:

| Indicator | What it means |
|-----------|---------------|
| **DB** | PostgreSQL database connected |
| **Supabase** | Cloud auth and storage reachable |
| **Ollama** | Local AI language model loaded and responding |
| **AI Engine** | Python threat-analysis service online |

A grey dot means that service is temporarily unreachable. ShieldDesk continues in degraded mode with a visible warning on the affected feature.

## Approvals Button

Shows a **red badge** when security actions are pending human sign-off. Click it to review and approve or reject. See [Approval Workflow](approval-workflow.md) for full details.

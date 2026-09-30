# Getting Help & Troubleshooting

## In-App AI

The fastest way to get help is to ask the **AI assistant**. It has full context about your environment and can explain any concept, investigate any incident, or guide you through any workflow.

## Common Issues

| Issue | Solution |
|-------|---------|
| **Login fails** | Check credentials; MFA codes refresh every 30 seconds — wait for the next one |
| **Approvals badge not showing** | Your role may not be in the approval chain; contact your Super Admin |
| **Incident queue is empty** | All incidents may be resolved, or a severity filter is active — reset to ALL |
| **Agent shows as "offline"** | The host may be powered off; check the machine directly |
| **403 Forbidden error** | Your role lacks permission for that action; contact your Super Admin |
| **AI chat unresponsive** | Ollama or AI Engine health dot may be grey; contact your administrator |
| **Compliance export fails** | Ensure `DATABASE_URL` is set correctly in your server environment |

## Reporting a Security Vulnerability

Report platform security issues directly to your system administrator or the **Mints Global security team**.

{% hint style="danger" %}
Do **not** post security issues in public channels, community forums, or GitHub issues.
{% endhint %}

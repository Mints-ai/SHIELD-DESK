# ISO 27001 Compliance Audit

**URL:** `/dashboard/compliance`

Tracks your compliance posture against ISO/IEC 27001:2022 controls.

## Reading the Dashboard

Controls are grouped by clause (A.5 Organisational Controls, A.8 Technological Controls, etc.):

| Status | Meaning |
|--------|---------|
| ✅ **Compliant** | Evidence collected; control implemented |
| ⚠️ **Partial** | Some evidence; gaps remain |
| ❌ **Non-Compliant** | Control not yet implemented |
| ⏳ **Pending Review** | Awaiting auditor sign-off |

## Filtering by Horizon

Use the **horizon filter** to view controls relevant to your current remediation phase:
- **H1** — immediate containment controls
- **H2** — eradication and patching controls
- **H3** — recovery and hardening controls

## Exporting Evidence

Click **"Export Audit Evidence"** to download a structured JSON evidence package.

**Filename format:** `shielddesk-audit-evidence-{tenantId}-{timestamp}.json`

This file is suitable for external auditors or GRC platforms (Vanta, Drata, Sprinto, etc.).

{% hint style="tip" %}
Export before every quarterly audit review to capture a point-in-time snapshot.
{% endhint %}

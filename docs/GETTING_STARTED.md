# ShieldDesk — Getting Started Guide

Welcome to **ShieldDesk**, the AI-assisted Security Operations Platform for continuous telemetry correlation, deterministic incident triage, and cryptographically governed endpoint response.

---

## 1. Quick Onboarding in 4 Steps

### Step 1: Create Organization & Setup MFA
1. Sign in to your ShieldDesk dashboard.
2. Navigate to **Settings > Security & MFA**.
3. Scan the TOTP QR code using Google Authenticator, 1Password, or Authy.
4. Enter the 6-digit confirmation code. *(Mandatory for administrators and containment approvers).*

### Step 2: Generate an Endpoint Enrollment Token
1. Go to **Fleet Management > Deploy Agent**.
2. Click **Generate Enrollment Token**.
3. Set token expiry (e.g. 24 hours) and max uses.
4. Copy your token (prefixed with `sdt_...`).

### Step 3: Install the Universal Endpoint Agent

#### On Windows (PowerShell Administrator):
```powershell
powershell -ExecutionPolicy Bypass -File .\agent\scripts\install-windows.ps1 `
    -ControlPlane "https://your-shielddesk-instance.com" `
    -EnrollToken "sdt_your_enrollment_token"
```

#### On Linux (Ubuntu / Debian / RHEL / CentOS):
```bash
sudo bash ./agent/scripts/install-linux.sh \
    --control-plane "https://your-shielddesk-instance.com" \
    --token "sdt_your_enrollment_token"
```

### Step 4: Verify Live Telemetry
1. Open the **Fleet** tab in your dashboard.
2. Verify that your machine displays status `CONNECTED` with live CPU, memory, and events-per-second (EPS) metrics.
3. Check the **Incidents** tab to see real-time alert triage and Sigma rule correlations.

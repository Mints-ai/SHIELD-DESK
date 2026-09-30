# Getting Started

## Signing In

Navigate to your ShieldDesk URL (e.g. `https://yourdomain.shielddesk.io`) and you will see the login screen.

You have three ways to authenticate:

| Method | When to use |
|--------|-------------|
| **Email and Password** | Standard login with your organisation's credentials |
| **Supabase / OAuth** | SSO via Google Workspace, Azure AD, etc. |
| **Register** | Create a new operator account for your organisation |

### Multi-Factor Authentication (MFA)

If MFA is enabled, you will be prompted for a 6-digit code from your authenticator app (Google Authenticator, Authy, 1Password) after entering your password.

> MFA codes refresh every 30 seconds. If your login fails, wait for the next code.

### Redirect After Login

If you were sent a direct link to an incident or page, ShieldDesk will redirect you there automatically after login.

---

## First-Time Onboarding

Click **"Setting up a new SOC team? Follow Guided Fleet Onboarding"** on the login screen.

| Step | What Happens |
|------|--------------|
| **1. Org Setup** | Name your organisation and choose your compliance baseline |
| **2. Enrol Endpoints** | Run the ShieldDesk agent on your servers, workstations, and VMs |
| **3. MFA Setup** | Scan a QR code to enable MFA for your admin account |
| **4. Launch** | Confirm setup is live and open the SOC dashboard |

### Enrolling an Endpoint

**Linux / macOS:**

```bash
curl -sSL https://control.shielddesk.io/install.sh | sudo bash -s -- \
  --control-plane "https://control.shielddesk.io" --token "YOUR_ENROL_TOKEN"
```

**Windows (PowerShell):**

```powershell
Invoke-WebRequest -Uri "https://control.shielddesk.io/install-windows.ps1" `
  -OutFile "install.ps1"; .\install.ps1 -EnrollToken "YOUR_ENROL_TOKEN"
```

The agent appears in your **Fleet and Host** dashboard within a few minutes.

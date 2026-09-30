# Account & Session Security

## Session Management

- Sessions are stored in a cryptographically signed, `HttpOnly` cookie (`shielddesk_session`)
- Tampered tokens are immediately rejected — sessions cannot be forged
- Default idle timeout: 8 hours
- Use **Sign Out** from the user menu to invalidate your session server-side

## Multi-Factor Authentication (MFA)

MFA is strongly recommended for all accounts and required for Responder roles and above.

**To set up MFA:**
1. Request setup via your administrator
2. Scan the QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)
3. Enter the 6-digit code to confirm setup

## Password Requirements

- Minimum 12 characters
- Must include uppercase, lowercase, a number, and a special character
- Stored using `scrypt` (memory-hard hash) — your plaintext password is never stored or logged

## Logging Out

Use **Sign Out** from the user menu. This invalidates your session on the server, preventing reuse even if someone has your cookie value.

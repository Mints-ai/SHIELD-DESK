# ShieldDesk IAM Service

The Identity & Access Management (IAM) service handles multi-tenant authentication, session lifecycle, Role-Based Access Control (RBAC), and agent token validation for the ShieldDesk platform.

---

## Capabilities

- **JWT Authentication**: HS256-signed access tokens (1h expiry) carrying `{ sub, tenant_id, role, mfa }`.
- **Sliding Refresh Tokens**: Stored as bcrypt hashes in PostgreSQL with 30-day expiry.
- **Two-Factor Authentication (TOTP)**: Standard RFC 6238 TOTP via `otplib` with QR code provisioning.
- **Agent Token Provisioning**: Issues time-limited agent tokens (`agt_...`) cached in Redis (5 min TTL) for gRPC mTLS handshakes.
- **Rate Limiting**: Sliding-window IP-based rate limiting (120 req/min) backed by Redis.
- **Single Sign-On (SSO)**: Google OAuth2 and Okta SAML callback endpoints.

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | HTTP port | `4000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://postgres:postgres@localhost:5432/shielddesk` |
| `REDIS_URL` | Redis cache connection string | `redis://localhost:6379` |
| `JWT_SECRET` | Secret key for signing access tokens | `shielddesk_super_secure_jwt_secret_dev_key_2026` |

---

## API Reference

### Authentication
- `POST /v1/auth/login` — Email + password credentials login
- `POST /v1/auth/mfa/verify` — Complete TOTP challenge and upgrade session
- `POST /v1/auth/refresh` — Issue new access token using refresh token
- `DELETE /v1/auth/session` — Revoke active session / logout

### User Management
- `GET /v1/users` — List users within caller's tenant
- `POST /v1/users/invite` — Invite new team member (`admin`, `member`, `viewer`)
- `PATCH /v1/users/:id/role` — Update user's RBAC role (owner only)

### Agent Fleet Auth
- `POST /v1/agent/token` — Generate 5-minute agent enrollment token
- `GET /v1/agent/token/validate` — Validate token (called by Ingest Service)

---

## Local Development

```bash
cd services/iam
npm install
npm run dev
```

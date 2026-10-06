# External penetration test: scope of work

**Status: BLOCKED-ON-HUMAN.** A qualified independent security firm, approved rules of engagement, and a representative isolated test environment are required. No external test is claimed as completed.

## In-scope surfaces

- Web console: authentication, session lifecycle, CSRF, XSS, SSRF, file upload, authorization boundaries, administrative operations.
- API: object-level authorization, tenant IDOR, rate limits, schema validation, error handling, webhook ingress, pagination and export.
- Multi-tenant controls: RLS, tenant switching, cross-tenant identifiers, background jobs, cache keys, exports, support/admin access.
- Endpoint agent: enrollment, update, command parser, OS privilege boundaries, local secrets, TLS validation, signed result handling, offline/reconnect behavior.
- PKI and command protocol: certificate issuance, identity binding, expiry/revocation/rotation, signature and nonce enforcement, replay, stale results, kill-switch races.
- AI features: prompt injection, data leakage, unsafe tool selection, authorization confusion, retrieval poisoning, output validation, model/provider failure.
- Billing and licensing: webhook authenticity/idempotency, entitlement bypass, plan changes, cancellation/refund, tenant binding, quota enforcement.
- Infrastructure: deployment configuration, secret handling, database exposure/RLS, object storage, CI/CD permissions, dependency and container exposure.

## Rules and deliverables

1. Agree on dates, test accounts, allowed source IPs, rate limits, data handling, emergency contacts, prohibited actions, and a stop-work process.
2. Use synthetic tenants and data; prohibit testing against customer production systems without separate written authorization.
3. Request evidence for exploitable findings, severity rationale, affected versions, reproduction steps, and remediation guidance.
4. Require a retest of critical/high findings and a signed final report. Track all findings to closure or formally accepted risk.
5. Review the report with product/security owners; publish no “passed” or certification claim unless the report supports it.

**Human owner:** Security lead to procure the assessor and approve rules of engagement. **Exit evidence:** final report, finding disposition, retest evidence, and risk acceptance records.

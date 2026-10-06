# ShieldDesk Legal & Trust Center

**Last Updated:** September 30, 2026  
**Security Inquiries:** security@shielddesk.io  
**Legal Notices:** legal@shielddesk.io  

---

## 1. Data Processing Addendum (DPA) Summary

- **Customer Data Ownership:** Customers retain all rights, title, and interest in their security telemetry and incident data.
- **Data Residency:** All tenant telemetry, database records, and logs are stored exclusively in the designated customer region (e.g., US-East, EU-Central).
- **Encryption Standards:** Data in transit is encrypted using TLS 1.3 with forward secrecy. Data at rest is encrypted with AES-256 (PostgreSQL transparent data encryption and KMS-wrapped volume encryption).
- **Subprocessor Transparency:** ShieldDesk maintains an up-to-date list of third-party subprocessors (Cloudflare, Supabase/AWS, Sentry) and provides 30-day advance notice before onboarding new subprocessors.

---

## 2. Privacy & Telemetry Minimization Policy

- **No Keylogging or Screen Scraping:** The Universal Endpoint Agent collects exclusively security metadata (process hashes, network socket tuples, and command-line execution parameters). User keystrokes, browser contents, and document contents are strictly out of scope and never harvested.
- **Secret Redaction:** Command-line parameters are sanitized on-host prior to transmission to redact API keys, passwords, and bearer tokens.
- **Retention Schedule:**
  - Streaming hot telemetry: 30 days.
  - Correlated security incidents and evidence: 365 days.
  - Cryptographic hash-chain audit logs: 7 years immutable retention.

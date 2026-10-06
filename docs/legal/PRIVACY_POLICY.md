# ShieldDesk — Privacy Policy & Telemetry Handling

**Last Updated:** September 30, 2026  

## 1. Scope & Telemetry Collection
ShieldDesk collects security and endpoint telemetry strictly required to identify vulnerabilities, detect intrusions, calculate blast radius, and execute governed remediations:
- System process metadata (PID, hash, command-line arguments, parent process).
- Network socket metadata (IP addresses, ports, protocol headers).
- Security event logs (Windows Security/Sysmon events, Linux auditd/eBPF logs).
- Endpoint configuration and patch levels.

## 2. Redaction & Data Minimization
- ShieldDesk automatically redacts detected credentials, passwords, session tokens, and private keys at the ingestion gateway before persistence.
- Full memory dumps or keystroke logs are strictly prohibited and never transmitted or retained.

## 3. Data Ownership & Tenant Protection
- Customer retains 100% intellectual property and ownership rights over all customer telemetry.
- Telemetry from Customer Tenant A is never used to train generalized third-party LLMs or shared with Tenant B.
- Data is encrypted in transit via TLS 1.3 and at rest with AES-256-GCM.

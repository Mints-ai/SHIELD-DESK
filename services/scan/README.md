# ShieldDesk Scan Service (Python 3.12 + FastAPI)

The Scan Service orchestrates vulnerability scanning (Trivy), secrets leak detection (Gitleaks), automated SSH patching with pre-patch rollback snapshots, and external Attack Surface Management (Shodan & HIBP).

---

## Endpoints

### Vulnerability & CVE Scanning
- `POST /internal/scans/trigger` — Trigger full or partial CVE scan across asset list
- `GET  /internal/scans/{scan_id}` — Fetch background scan progress and structured findings

### Secrets Detection & Key Rotation
- `POST /internal/secrets/scan` — Scan repos or `.env` files; hashes secret values with SHA-256
- `POST /internal/secrets/{key_id}/rotate` — Trigger automated AWS IAM access key rotation

### Automated Patching
- `POST /internal/patches/apply` — Execute remote SSH patching (`apt-get`/`yum`) with pre-patch LVM/AMI safety snapshots

### Attack Surface & Threat Intelligence
- `GET /internal/attack-surface?ip=...` — Query open ports and exposed services via Shodan
- `GET /internal/intel/breaches?email=...` — Query employee credential leaks via HaveIBeenPwned

---

## Local Development

```bash
cd services/scan
pip install -r requirements.txt
pytest test_scan.py -v
uvicorn main:app --port 8001 --reload
```

import uuid
import time
import os
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel, Field

from cve_scanner import CveScanner
from secrets_scanner import SecretsScanner
from patch_orchestrator import PatchOrchestrator
from external_intel import ExternalIntelClient

app = FastAPI(
    title="ShieldDesk Scan Service",
    description="Automated CVE scanning (Trivy), Secrets detection (Gitleaks), Patch orchestration & ASM (Shodan)",
    version="1.0.0",
)

cve_scanner = CveScanner()
secrets_scanner = SecretsScanner()
patch_orchestrator = PatchOrchestrator()
intel_client = ExternalIntelClient(
    shodan_key=os.getenv("SHODAN_API_KEY", ""),
    hibp_key=os.getenv("HIBP_API_KEY", "")
)

# In-memory scan jobs cache (for job status tracking)
scan_jobs: Dict[str, Dict[str, Any]] = {}

# --- Schemas ---

class ScanTriggerRequest(BaseModel):
    asset_ids: List[str]
    scan_type: str = Field("full", description="full | quick | cve | secrets")
    target_path: Optional[str] = "/app"

class SecretsScanRequest(BaseModel):
    source: str = Field("git_repo", description="git_repo | env_file | docker_config")
    content: str
    location: Optional[str] = "root"

class PatchApplyRequest(BaseModel):
    asset_ip: str
    os_type: str = "linux"
    packages: List[str]
    cvss_threshold: float = 7.0

# --- Endpoints ---

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "shielddesk-scan-service",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

# 1. Trigger CVE / Asset Scan
@app.post("/internal/scans/trigger")
def trigger_scan(req: ScanTriggerRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "scan_type": req.scan_type,
        "asset_ids": req.asset_ids,
        "findings": [],
        "created_at": time.time(),
    }

    def run_scan_job():
        time.sleep(0.1)
        findings = cve_scanner.scan_target(req.target_path or ".", target_type="fs")
        scan_jobs[scan_id]["status"] = "completed"
        scan_jobs[scan_id]["findings"] = findings
        scan_jobs[scan_id]["completed_at"] = time.time()

    background_tasks.add_task(run_scan_job)
    return {"scan_id": scan_id, "status": "queued", "message": "Vulnerability scan initiated."}

# 2. Get Scan Status & Findings
@app.get("/internal/scans/{scan_id}")
def get_scan_status(scan_id: str):
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job

# 3. Secrets Detection (Gitleaks pattern)
@app.post("/internal/secrets/scan")
def scan_secrets(req: SecretsScanRequest):
    findings = secrets_scanner.scan_content(
        content=req.content,
        source=req.source,
        location=req.location or "unknown"
    )
    return {
        "findings_count": len(findings),
        "findings": findings,
    }

# 4. Trigger AWS IAM Key Rotation
@app.post("/internal/secrets/{key_id}/rotate")
def rotate_secret_key(key_id: str):
    res = secrets_scanner.rotate_aws_key(key_id)
    return res

# 5. Patch Orchestrator (SSH + apt/yum + Rollback Snapshot)
@app.post("/internal/patches/apply")
def apply_patches(req: PatchApplyRequest):
    result = patch_orchestrator.apply_patches(
        asset_ip=req.asset_ip,
        os_type=req.os_type,
        packages=req.packages,
        cvss_threshold=req.cvss_threshold,
    )
    return result

# 6. External Attack Surface Scan (Shodan)
@app.get("/internal/attack-surface")
def scan_attack_surface(ip: str):
    results = intel_client.scan_shodan_ip(ip)
    return results

# 7. Employee Breach Check (HIBP)
@app.get("/internal/intel/breaches")
def check_employee_breaches(email: str):
    breaches = intel_client.check_hibp_breach(email)
    return {"email": email, "breaches": breaches}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)

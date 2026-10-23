"""
CVE AI Engine Web Server & REST API.
Serves interactive dashboard and prediction API on localhost:8000.
"""

import os
import json
import time
import urllib.parse
import requests
import importlib
from typing import Any
from http.server import HTTPServer, SimpleHTTPRequestHandler
from cve_ai_engine import CVEAIEngine

# Initialize Sentry error reporting if SENTRY_DSN is configured
sentry_sdk: Any = None
sentry_dsn = os.getenv("SENTRY_DSN")
if sentry_dsn:
    try:
        sentry_sdk = importlib.import_module("sentry_sdk")
        sentry_sdk.init(
            dsn=sentry_dsn,
            traces_sample_rate=1.0,
            profiles_sample_rate=1.0,
            environment=os.getenv("NODE_ENV", "production")
        )
        print("[Sentry] Python CVE AI Engine error tracking initialized.")
    except (ImportError, ModuleNotFoundError):
        sentry_sdk = None
        print("[Sentry] sentry-sdk not installed, continuing without cloud error reporting.")
    except Exception as init_err:
        print(f"[Sentry] Initialization warning: {init_err}")

PORT = 8000
from models.registry import ModelRegistry
from pipeline.feed_sync import CVEFeedSynchronizer
import threading
from datetime import datetime, timezone

registry = ModelRegistry()
engine = CVEAIEngine()
challenger_engine = None

def get_challenger_engine():
    global challenger_engine
    status = registry.get_status()
    if status.get("shadow_evaluation_enabled") and status.get("active_challenger"):
        chall_info = status.get("challenger_details") or {}
        path = chall_info.get("artifact_path")
        if path and os.path.exists(path):
            if challenger_engine is None or getattr(challenger_engine, "model_path", None) != path:
                try:
                    challenger_engine = CVEAIEngine(model_path=path)
                except Exception as e:
                    print(f"[Shadow] Failed to load challenger model: {e}")
            return challenger_engine
    return None

class CVEAPIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), "static"), **kwargs)

    def do_POST(self):
        global engine, challenger_engine
        url = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8")
        
        try:
            data = json.loads(post_body) if post_body else {}
        except Exception:
            data = {}

        if url.path == "/api/predict":
            description = data.get("description", "")
            category = data.get("category", "General")
            cwe_id = data.get("cwe_id", "Unknown")
            epss_score = data.get("epss_score", None)
            kev_listed = data.get("kev_listed", None)
            context = data.get("context", {})

            if not description:
                self._send_json({"error": "Description is required."}, status=400)
                return

            try:
                result = engine.analyze_vulnerability(
                    description=description,
                    category=category,
                    cwe_id=cwe_id,
                    epss_score=epss_score,
                    kev_listed=kev_listed,
                    context=context
                )
                self._send_json(result)

                # Asynchronous Shadow Evaluation
                chall_eng = get_challenger_engine()
                if chall_eng is not None:
                    def _run_shadow():
                        try:
                            chall_res = chall_eng.analyze_vulnerability(
                                description=description,
                                category=category,
                                cwe_id=cwe_id,
                                epss_score=epss_score,
                                kev_listed=kev_listed,
                                context=context
                            )
                            champ_tier = result.get("predictions", {}).get("assigned_tier")
                            chall_tier = chall_res.get("predictions", {}).get("assigned_tier")
                            champ_sev = result.get("predictions", {}).get("cvss_severity")
                            chall_sev = chall_res.get("predictions", {}).get("cvss_severity")
                            
                            is_divergent = (champ_tier != chall_tier) or (champ_sev != chall_sev)
                            audit_entry = {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "champion_tier": champ_tier,
                                "challenger_tier": chall_tier,
                                "champion_sev": champ_sev,
                                "challenger_sev": chall_sev,
                                "is_divergent": is_divergent,
                                "description_snippet": description[:100]
                            }
                            audit_path = os.path.join(os.path.dirname(__file__), "models", "shadow_audit.jsonl")
                            with open(audit_path, "a", encoding="utf-8") as af:
                                af.write(json.dumps(audit_entry) + "\n")

                            manifest = registry.load_manifest()
                            manifest["total_shadow_inferences"] = manifest.get("total_shadow_inferences", 0) + 1
                            if is_divergent:
                                manifest["shadow_divergences"] = manifest.get("shadow_divergences", 0) + 1
                            registry.save_manifest(manifest)
                        except Exception as shadow_err:
                            print(f"[Shadow] Shadow inference error: {shadow_err}")

                    threading.Thread(target=_run_shadow, daemon=True).start()

            except Exception as e:
                if sentry_sdk is not None:
                    try:
                        sentry_sdk.capture_exception(e)
                    except Exception:
                        pass
                self._send_json({"error": str(e)}, status=500)
            return

        elif url.path == "/api/model/promote":
            try:
                promoted_id = registry.promote_challenger_to_champion()
                status = registry.get_status()
                champ_details = status.get("champion_details") or {}
                champ_path = champ_details.get("artifact_path")
                if champ_path and os.path.exists(champ_path):
                    engine = CVEAIEngine(model_path=champ_path)
                challenger_engine = None
                self._send_json({"success": True, "promoted_version": promoted_id, "status": "active_champion"})
            except Exception as err:
                self._send_json({"error": str(err)}, status=400)
            return

        elif url.path == "/api/model/rollback":
            try:
                reverted_id = registry.rollback_to_previous()
                status = registry.get_status()
                champ_details = status.get("champion_details") or {}
                champ_path = champ_details.get("artifact_path")
                if champ_path and os.path.exists(champ_path):
                    engine = CVEAIEngine(model_path=champ_path)
                challenger_engine = None
                self._send_json({"success": True, "active_version": reverted_id, "status": "rolled_back"})
            except Exception as err:
                self._send_json({"error": str(err)}, status=400)
            return

        elif url.path == "/api/trigger_scan":
            try:
                # Call the Next.js API which runs Trivy locally with dev user identity
                user_id = data.get("user_id") if isinstance(data, dict) else "dev-admin"
                scan_url = "http://localhost:3000/api/scans"
                headers = {
                    "Content-Type": "application/json",
                    "X-ShieldDesk-User": user_id or "dev-admin",
                }
                payload = {
                    "action": "cve_scan",
                    "target_path": data.get("target_path", ".") if isinstance(data, dict) else ".",
                    "scan_type": data.get("scan_type", "fs") if isinstance(data, dict) else "fs",
                }
                response = requests.post(scan_url, json=payload, headers=headers, timeout=180)
                
                if response.ok:
                    data_res = response.json()
                    findings = data_res.get("findings", [])
                    if findings and len(findings) > 0:
                        self._send_json({
                            "success": True, 
                            "message": f"Scan completed: {len(findings)} vulnerabilities found.", 
                            "findings": findings,
                            "metrics": data_res.get("metrics", {}),
                        })
                    else:
                        self._send_json({
                            "success": True, 
                            "message": data_res.get("message") or "No vulnerabilities detected.",
                            "findings": [],
                        })
                else:
                    self._send_json({"error": f"Scan service returned error: {response.status_code}"}, status=response.status_code)
            except Exception as e:
                self._send_json({"error": f"Failed to trigger scan: {str(e)}"}, status=500)
            return

        elif url.path == "/api/batch":
            items = data.get("items", [])
            results = []
            for it in items[:20]:
                desc = it.get("description", "")
                if desc:
                    res = engine.analyze_vulnerability(
                        description=desc,
                        category=it.get("category", "General"),
                        cwe_id=it.get("cwe_id", "Unknown"),
                        epss_score=it.get("epss_score", None),
                        kev_listed=it.get("kev_listed", None)
                    )
                    results.append(res)
            self._send_json({"results": results})
            return

        elif url.path == "/api/intel/sync":
            try:
                sync = CVEFeedSynchronizer()
                cisa_items = sync.sync_cisa_kev()
                total_records = sync.initialize_or_update_lookup_store(cisa_items=cisa_items)
                self._send_json({
                    "success": True,
                    "synced_cisa_items": len(cisa_items),
                    "total_lookup_store_records": total_records,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                self._send_json({"error": f"Intel sync failed: {str(e)}"}, status=500)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)

        if url.path in ("/health", "/api/health"):
            self._send_json({"status": "ok", "service": "cve-ai-engine"})
            return

        if url.path == "/api/model/status":
            self._send_json(registry.get_status())
            return

        if url.path == "/api/lookup":
            cve_id = query.get("cve", [""])[0]
            if not cve_id:
                self._send_json({"error": "cve query parameter required"}, status=400)
                return
            record = engine.search_cve_by_id(cve_id)
            if not record:
                self._send_json({"error": f"CVE {cve_id} not found"}, status=404)
                return
            self._send_json({"record": record})
            return

        elif url.path == "/api/metrics":
            metrics_path = os.path.join("models", "evaluation_report.json")
            if os.path.exists(metrics_path):
                with open(metrics_path, "r") as f:
                    metrics_data = json.load(f)
                self._send_json(metrics_data)
            else:
                self._send_json({"error": "Metrics not found"}, status=404)
            return

        elif url.path == "/api/samples":
            samples = [
                {
                    "title": "Linux Kernel Netfilter RCE (Heap Overflow)",
                    "category": "Linux (General/Kernel)",
                    "cwe_id": "CWE-122",
                    "epss_score": 0.89,
                    "kev_listed": 1,
                    "description": "A heap out-of-bounds write vulnerability was discovered in the Linux kernel netfilter subsystem nftables module. A remote or local unprivileged attacker could trigger memory corruption to achieve root privilege escalation or remote code execution."
                },
                {
                    "title": "SAP NetWeaver AS Java Unauthorized Admin Access",
                    "category": "SAP",
                    "cwe_id": "CWE-306",
                    "epss_score": 0.94,
                    "kev_listed": 1,
                    "description": "Missing authentication check in SAP NetWeaver AS Java LM Configuration Wizard enables remote unauthenticated attackers to create admin accounts and execute arbitrary OS commands via web interface."
                },
                {
                    "title": "Windows RPC Runtime Remote Code Execution",
                    "category": "Windows",
                    "cwe_id": "CWE-787",
                    "epss_score": 0.72,
                    "kev_listed": 0,
                    "description": "Windows Remote Procedure Call (RPC) Runtime contains an out-of-bounds write flaw that allows an unauthenticated network attacker to send a specially crafted RPC packet to execute arbitrary code on the server with elevated privileges."
                },
                {
                    "title": "Oracle E-Business Suite SQL Injection",
                    "category": "Oracle E-Business Suite",
                    "cwe_id": "CWE-89",
                    "epss_score": 0.45,
                    "kev_listed": 0,
                    "description": "Vulnerability in the Oracle Marketing product of Oracle E-Business Suite allows unauthenticated network attacker with HTTP access to compromise database integrity via SQL injection in campaign management parameters."
                },
                {
                    "title": "Microsoft Defender Malware Protection Engine DoS",
                    "category": "Endpoint Defender",
                    "cwe_id": "CWE-400",
                    "epss_score": 0.12,
                    "kev_listed": 0,
                    "description": "Denial of service vulnerability in Microsoft Malware Protection Engine when scanning specially crafted compressed zip archive causing high CPU utilization and scan process crash."
                }
            ]
            self._send_json({"samples": samples})
            return

        elif url.path == "/api/browse":
            page = int(query.get("page", [1])[0])
            limit = int(query.get("limit", [25])[0])
            search = query.get("q", [""])[0].lower()
            platform = query.get("platform", ["all"])[0]

            kb = engine.mit_kb
            filtered = kb
            if platform != "all":
                filtered = filtered[filtered["domain"].str.contains(platform, case=False, na=False) | filtered["category"].str.contains(platform, case=False, na=False)]
            if search:
                filtered = filtered[
                    filtered["cve_id"].str.lower().str.contains(search, na=False) |
                    filtered["description"].str.lower().str.contains(search, na=False) |
                    filtered["mitigation_plan"].str.lower().str.contains(search, na=False)
                ]

            total = len(filtered)
            start = (page - 1) * limit
            end = start + limit
            rows = filtered.iloc[start:end].to_dict(orient="records")

            self._send_json({
                "total": total,
                "page": page,
                "limit": limit,
                "records": rows
            })
            return

        super().do_GET()

    def _send_json(self, data: Any, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

def start_daily_scheduler(interval_hours: int = 24):
    """Background daemon thread that periodically runs CISA KEV and EPSS sync."""
    def _scheduler_loop():
        # Allow server to initialize first
        time.sleep(5)
        print(f"[Scheduler] Daily vulnerability intelligence sync daemon started (Interval: {interval_hours}h).")
        while True:
            try:
                print("[Scheduler] Running automated periodic threat intelligence sync...")
                from pipeline.feed_sync import CVEFeedSynchronizer
                syncer = CVEFeedSynchronizer()
                items = syncer.sync_cisa_kev()
                total = syncer.initialize_or_update_lookup_store(cisa_items=items)
                print(f"[Scheduler] Daily sync completed: {len(items)} KEV items checked, {total} active records.")
            except Exception as e:
                print(f"[Scheduler] Warning: Error during automated sync: {e}")
            time.sleep(interval_hours * 3600)

    sched_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    sched_thread.start()

def run_server(port=PORT):
    os.makedirs("static", exist_ok=True)
    server_address = ("", port)
    httpd = HTTPServer(server_address, CVEAPIHandler)
    print(f"\n=======================================================")
    print(f"[*] CVE AI Intelligence Server running on http://localhost:{port}")
    print(f"=======================================================\n")
    # Launch background automated daily scheduler daemon
    start_daily_scheduler(interval_hours=24)
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()

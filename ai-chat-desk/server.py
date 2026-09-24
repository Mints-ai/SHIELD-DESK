"""
CVE AI Engine Web Server & REST API.
Serves interactive dashboard and prediction API on localhost:8000.
"""

import os
import json
import urllib.parse
from typing import Any
from http.server import HTTPServer, SimpleHTTPRequestHandler
from cve_ai_engine import CVEAIEngine

PORT = 8000
engine = CVEAIEngine()

class CVEAPIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), "static"), **kwargs)

    def do_POST(self):
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

            if not description:
                self._send_json({"error": "Description is required."}, status=400)
                return

            try:
                result = engine.analyze_vulnerability(
                    description=description,
                    category=category,
                    cwe_id=cwe_id,
                    epss_score=epss_score,
                    kev_listed=kev_listed
                )
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
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

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)

        if url.path in ("/health", "/api/health"):
            self._send_json({"status": "ok", "service": "cve-ai-engine"})
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

def run_server(port=PORT):
    os.makedirs("static", exist_ok=True)
    server_address = ("", port)
    httpd = HTTPServer(server_address, CVEAPIHandler)
    print(f"\n=======================================================")
    print(f"[*] CVE AI Intelligence Server running on http://localhost:{port}")
    print(f"=======================================================\n")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()

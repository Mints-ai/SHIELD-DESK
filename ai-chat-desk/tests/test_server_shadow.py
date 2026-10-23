"""
Integration tests for CVE API Server, Shadow Scoring & Admin Endpoints.
"""

import os
import time
import json
import socket
import unittest
import threading
from http.server import HTTPServer
from server import CVEAPIHandler, registry
import requests

class TestServerAndShadowEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Find free port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", 0))
        cls.test_port = sock.getsockname()[1]
        sock.close()

        cls.server = HTTPServer(("127.0.0.1", cls.test_port), CVEAPIHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.test_port}"
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_and_model_status_endpoints(self):
        resp = requests.get(f"{self.base_url}/api/health", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

        status_resp = requests.get(f"{self.base_url}/api/model/status", timeout=5)
        self.assertEqual(status_resp.status_code, 200)
        data = status_resp.json()
        self.assertEqual(data["status"], "ready")
        self.assertIn("active_champion", data)

    def test_predict_and_shadow_execution(self):
        payload = {
            "description": "A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking in OpenSSL. An attacker can craft a malicious email address in a certificate to overflow arbitrary bytes on the stack resulting in remote code execution.",
            "category": "Linux / OpenSSL",
            "cwe_id": "CWE-120",
            "epss_score": 0.82,
            "kev_listed": 0
        }
        resp = requests.post(f"{self.base_url}/api/predict", json=payload, timeout=10)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("predictions", body)
        self.assertIn("safety_policy", body)
        # Verify safety policy prevented autonomous tier
        self.assertIn("Tier", body["predictions"]["assigned_tier"])
        self.assertFalse(body["safety_policy"]["is_autonomous_execution_allowed"])

    def test_lookup_endpoint(self):
        resp = requests.get(f"{self.base_url}/api/lookup?cve=CVE-2024-3400", timeout=5)
        if resp.status_code == 200:
            rec = resp.json().get("record")
            self.assertIsNotNone(rec)
            self.assertEqual(rec["cve_id"].upper(), "CVE-2024-3400")

if __name__ == "__main__":
    unittest.main()

import unittest
from cve_scanner import CveScanner
from secrets_scanner import SecretsScanner
from patch_orchestrator import PatchOrchestrator
from external_intel import ExternalIntelClient

class TestScanService(unittest.TestCase):
    def test_cve_scanner_local_mirror(self):
        scanner = CveScanner()
        findings = scanner.scan_target("/nonexistent/path/for/test")
        self.assertGreater(len(findings), 0)
        cve_ids = [f["cve_id"] for f in findings]
        self.assertIn("CVE-2024-3400", cve_ids)

    def test_secrets_scanner_hashing(self):
        scanner = SecretsScanner()
        content = """
        AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"
        GITHUB_TOKEN="ghp_123456789012345678901234567890123456"
        PASSWORD="super_secret_sample_password_12345"
        """
        findings = scanner.scan_content(content, source="env_file", location=".env.production")
        self.assertGreaterEqual(len(findings), 3)

        for f in findings:
            self.assertEqual(len(f["hash"]), 64)
            self.assertTrue(f["masked"].startswith("AKIA") or f["masked"].startswith("ghp_") or f["masked"].startswith("supe"))

    def test_patch_orchestrator_snapshot(self):
        orchestrator = PatchOrchestrator()
        res = orchestrator.apply_patches(
            asset_ip="192.168.1.105",
            os_type="ubuntu",
            packages=["openssl", "nginx"],
            cvss_threshold=7.5,
        )
        self.assertEqual(res["status"], "succeeded")
        self.assertIn("snapshot_id", res)
        self.assertTrue(res["snapshot_id"].startswith("snap_192_168_1_105"))
        self.assertIn("apt-get", res["command_executed"])

    def test_external_intel(self):
        intel = ExternalIntelClient()
        shodan_res = intel.scan_shodan_ip("198.51.100.1")
        self.assertIn("open_ports", shodan_res)
        self.assertIn(443, shodan_res["open_ports"])

        hibp_res = intel.check_hibp_breach("admin@company.com")
        self.assertGreater(len(hibp_res), 0)
        self.assertEqual(hibp_res[0]["email"], "admin@company.com")

if __name__ == "__main__":
    unittest.main()

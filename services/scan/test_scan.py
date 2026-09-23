import pytest
from cve_scanner import CveScanner
from secrets_scanner import SecretsScanner
from patch_orchestrator import PatchOrchestrator
from external_intel import ExternalIntelClient

def test_cve_scanner_local_mirror():
    scanner = CveScanner()
    findings = scanner.scan_target("/nonexistent/path/for/test")
    assert len(findings) > 0, "Should return advisory findings from local mirror"
    cve_ids = [f["cve_id"] for f in findings]
    assert "CVE-2024-3400" in cve_ids, "PAN-OS CVE should be present"

def test_secrets_scanner_hashing():
    scanner = SecretsScanner()
    content = """
    AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"
    GITHUB_TOKEN="ghp_123456789012345678901234567890123456"
    PASSWORD="super_secret_sample_password_12345"
    """
    findings = scanner.scan_content(content, source="env_file", location=".env.production")
    assert len(findings) >= 3, f"Expected at least 3 secrets found, got {len(findings)}"

    for f in findings:
        assert len(f["hash"]) == 64, "Secret must be hashed as 64-char SHA-256 hex"
        assert f["masked"].startswith("AKIA") or f["masked"].startswith("ghp_") or f["masked"].startswith("supe")

def test_patch_orchestrator_snapshot():
    orchestrator = PatchOrchestrator()
    res = orchestrator.apply_patches(
        asset_ip="192.168.1.105",
        os_type="ubuntu",
        packages=["openssl", "nginx"],
        cvss_threshold=7.5,
    )
    assert res["status"] == "succeeded"
    assert "snapshot_id" in res
    assert res["snapshot_id"].startswith("snap_192_168_1_105")
    assert "apt-get" in res["command_executed"]

def test_external_intel():
    intel = ExternalIntelClient()
    shodan_res = intel.scan_shodan_ip("198.51.100.1")
    assert "open_ports" in shodan_res
    assert 443 in shodan_res["open_ports"]

    hibp_res = intel.check_hibp_breach("admin@company.com")
    assert len(hibp_res) > 0
    assert hibp_res[0]["email"] == "admin@company.com"

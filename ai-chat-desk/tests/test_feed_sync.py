"""
Tests for Vulnerability Schemas & Feed Synchronizer using real CVE threat data and live feeds.
"""

import os
import unittest
from schemas import VulnerabilityInferenceRequest, CISAKEVItem, EPSSRecord
from pipeline.feed_sync import CVEFeedSynchronizer
from cve_ai_engine import CVEAIEngine

class TestRealSchemasAndFeedSync(unittest.TestCase):

    def test_schema_valid_real_cve_inference_request(self):
        """Validates real CVE-2024-21413 (Microsoft Outlook Moniker Link RCE)."""
        req = VulnerabilityInferenceRequest(
            description=(
                "Microsoft Outlook Remote Code Execution Vulnerability (Moniker Link Bug) allows an "
                "unauthenticated remote attacker to bypass Protected View and trigger NTLM credential-leaking "
                "and arbitrary code execution via crafted file:// URI links."
            ),
            category="Windows / Microsoft Outlook",
            cwe_id="CWE-20",
            epss_score=0.97,
            kev_listed=1
        )
        self.assertIn("Moniker Link", req.description)
        self.assertEqual(req.epss_score, 0.97)
        self.assertEqual(req.kev_listed, 1)

    def test_schema_rejects_empty_description(self):
        """Verifies schema rejects empty descriptions without using mock values."""
        with self.assertRaises(ValueError):
            VulnerabilityInferenceRequest(description="   ")

    def test_schema_rejects_out_of_bounds_epss(self):
        """Verifies schema enforces valid EPSS probability bounds [0.0, 1.0]."""
        with self.assertRaises(ValueError):
            VulnerabilityInferenceRequest(
                description="Apache Log4j2 JNDI Remote Code Execution vulnerability in log lookup.",
                epss_score=1.05
            )

    def test_cisa_item_validation_real_record(self):
        """Validates real CISA KEV record for PAN-OS CVE-2024-3400."""
        item = CISAKEVItem(
            cveID="cve-2024-3400",
            vendorProject="Palo Alto Networks",
            product="PAN-OS",
            vulnerabilityName="Palo Alto Networks PAN-OS Command Injection Vulnerability",
            dateAdded="2024-04-12",
            shortDescription="Palo Alto Networks PAN-OS contains an OS command injection vulnerability in GlobalProtect.",
            requiredAction="Apply mitigations per vendor advisory or replace software versions.",
            dueDate="2024-04-19",
            knownRansomwareCampaignUse="Known"
        )
        self.assertEqual(item.cveID, "CVE-2024-3400")
        self.assertEqual(item.vendorProject, "Palo Alto Networks")

    def test_cisa_item_rejects_malformed_cve_id(self):
        """Verifies schema rejects non-standard CVE formats."""
        with self.assertRaises(ValueError):
            CISAKEVItem(cveID="NOT-A-REAL-CVE")

    def test_epss_record_validation_real_data(self):
        """Validates EPSS payload for real-world Log4Shell (CVE-2021-44228)."""
        rec = EPSSRecord(cve="CVE-2021-44228", epss=0.9754, percentile=0.999)
        self.assertEqual(rec.cve, "CVE-2021-44228")
        self.assertGreater(rec.epss, 0.9)

    def test_live_epss_api_batch_query(self):
        """Performs live network query against FIRST.org API for real CVE-2021-44228 score."""
        syncer = CVEFeedSynchronizer(timeout=10)
        scores = syncer.fetch_epss_scores_batch(["CVE-2021-44228"])
        self.assertIn("CVE-2021-44228", scores)
        self.assertGreater(scores["CVE-2021-44228"], 0.90)

    def test_lookup_store_query_real_cve(self):
        """Queries the standalone lookup store for real CISA KEV record CVE-2024-3400."""
        engine = CVEAIEngine()
        record = engine.search_cve_by_id("CVE-2024-3400")
        self.assertIsNotNone(record, "CVE-2024-3400 must exist in the synchronized lookup store")
        self.assertEqual(record["cve_id"].upper(), "CVE-2024-3400")
        self.assertEqual(record["kev_listed"], 1)
        self.assertEqual(record["category"], "Palo Alto Networks")

if __name__ == "__main__":
    unittest.main()

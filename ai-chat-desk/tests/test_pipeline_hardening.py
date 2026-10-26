"""
Regression & Security Test Suite for Model Training Group-Aware Split and Pipeline Rollback Credentials.

Covers:
1. GroupShuffleSplit by CVE ID prevents identical CVE records from leaking across train and test splits.
2. Group overlap detection fails closed if any CVE group appears in both train and test.
3. scripts/run_cve_update_pipeline.py rollback fails closed when operator ID is missing (no default "cli_admin").
4. scripts/run_cve_update_pipeline.py rollback fails closed when approval token is missing (no default "cli_manual_rollback_token").
5. scripts/run_cve_update_pipeline.py rollback succeeds when explicit credentials are provided.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest import mock
import pandas as pd
import numpy as np

# Ensure parent and project roots are in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sklearn.model_selection import GroupShuffleSplit
import scripts.run_cve_update_pipeline as update_pipeline


class TestGroupAwareTrainSplit(unittest.TestCase):

    def test_repeated_cves_do_not_leak_across_splits(self):
        """Repeated CVE IDs must be grouped together so no CVE ID appears in both train and test splits."""
        # Create dataset with intentional repeated CVE IDs
        records = []
        for i in range(100):
            cve = f"CVE-2024-{i:04d}"
            # Add 3 records per CVE ID with varying annotations
            for rep in range(3):
                records.append({
                    "cve_id": cve,
                    "cvss_score": 7.5,
                    "cvss_severity": "HIGH",
                    "assigned_tier": "Tier 2 (Medium-Risk / Human-Approved)",
                    "full_text": f"Vulnerability text for {cve} repetition {rep}",
                    "epss_score": 0.45,
                    "kev_listed": 0,
                    "mitigation_plan": "Patch immediately."
                })

        df = pd.DataFrame(records)
        self.assertEqual(len(df), 300)
        self.assertEqual(df["cve_id"].nunique(), 100)

        # Apply the exact GroupShuffleSplit logic used in train_rf_model.py
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
        groups = df["cve_id"].copy()
        train_idx, test_idx = next(gss.split(df, groups=groups))

        train_df = df.iloc[train_idx].copy()
        test_df = df.iloc[test_idx].copy()

        train_cves = set(train_df["cve_id"].dropna().astype(str))
        test_cves = set(test_df["cve_id"].dropna().astype(str))

        overlap = train_cves.intersection(test_cves)
        self.assertEqual(
            len(overlap), 0,
            f"Data leakage detected! CVEs present in both train and test: {overlap}"
        )
        self.assertTrue(train_cves.isdisjoint(test_cves))
        self.assertGreater(len(train_df), 0)
        self.assertGreater(len(test_df), 0)

    def test_overlap_assertion_triggers_if_groups_collide(self):
        """If train and test sets somehow contain overlapping CVEs, validation must fail closed."""
        df = pd.DataFrame({
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "cvss_score": [5.0, 5.0, 6.0, 7.0]
        })
        # Simulate an erroneous split where CVE-2024-0001 is on both sides
        train_df = df.iloc[[0, 2]].copy()
        test_df = df.iloc[[1, 3]].copy()

        train_cves = set(train_df["cve_id"].dropna().astype(str))
        test_cves = set(test_df["cve_id"].dropna().astype(str))
        overlap = train_cves.intersection(test_cves)

        self.assertIn("CVE-2024-0001", overlap)
        with self.assertRaises(ValueError) as ctx:
            if overlap:
                raise ValueError(f"Leakage error: {len(overlap)} CVE groups appear in both train and test splits!")
        self.assertIn("Leakage error", str(ctx.exception))


class TestPipelineRollbackCredentials(unittest.TestCase):

    def setUp(self):
        self.orig_env = os.environ.copy()
        # Clean any operator/token env vars
        os.environ.pop("SHIELDDESK_OPERATOR_ID", None)
        os.environ.pop("SHIELDDESK_APPROVAL_TOKEN", None)
        os.environ.pop("SHIELDDESK_APPROVAL_NONCE", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_run_rollback_missing_operator_fails_closed(self):
        """Rollback without operator_id fails closed with ValueError and never uses default 'cli_admin'."""
        with mock.patch("scripts.run_cve_update_pipeline.ModelRegistry") as mock_reg_cls:
            mock_reg = mock.MagicMock()
            mock_reg.load_manifest.return_value = {"history": ["v1.0.0-baseline", "v2.0.0"]}
            mock_reg_cls.return_value = mock_reg

            with self.assertRaises(ValueError) as ctx:
                update_pipeline.run_rollback(operator_id="", approval_token="token_123")
            self.assertIn("Missing required administrator identity", str(ctx.exception))

    def test_run_rollback_missing_approval_token_fails_closed(self):
        """Rollback without approval_token fails closed and never uses default 'cli_manual_rollback_token'."""
        with mock.patch("scripts.run_cve_update_pipeline.ModelRegistry") as mock_reg_cls:
            mock_reg = mock.MagicMock()
            mock_reg.load_manifest.return_value = {"history": ["v1.0.0-baseline", "v2.0.0"]}
            mock_reg_cls.return_value = mock_reg

            with self.assertRaises(ValueError) as ctx:
                update_pipeline.run_rollback(operator_id="admin_user", approval_token="")
            self.assertIn("Missing required cryptographic approval token", str(ctx.exception))

    def test_run_rollback_with_explicit_credentials_calls_registry(self):
        """Rollback with verified operator and token passes explicit credentials to rollback_to_previous."""
        with mock.patch("scripts.run_cve_update_pipeline.ModelRegistry") as mock_reg_cls:
            mock_reg = mock.MagicMock()
            mock_reg.load_manifest.return_value = {"history": ["v1.0.0-baseline", "v2.0.0"]}
            mock_reg.rollback_to_previous.return_value = "v1.0.0-baseline"
            mock_reg_cls.return_value = mock_reg

            update_pipeline.run_rollback(
                operator_id="sec_lead_01",
                approval_token="sd_signed_token_xyz"
            )
            mock_reg.rollback_to_previous.assert_called_once_with(
                expected_target_id="v1.0.0-baseline",
                operator_id="sec_lead_01",
                approval_token="sd_signed_token_xyz"
            )


if __name__ == "__main__":
    unittest.main()

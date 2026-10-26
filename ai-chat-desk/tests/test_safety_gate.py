"""
Comprehensive Regression & Negative Security Test Suite for AI Safety Release Gate.
Covers:
1. Metric calculation exceptions fail closed (never fabricate ROC-AUC 0.98 fallback)
2. Benchmark dataset missing/corrupt ground truth fails closed
3. Cryptographic HMAC-SHA256 receipt verification
4. Tampered receipt payloads and signatures rejected
5. Model artifact SHA-256 and benchmark dataset SHA-256 binding enforcement
6. Non-passing or rejected receipts fail verification
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from unittest import mock
import pandas as pd
import numpy as np

# Ensure parent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from eval.safety_gate import (
    evaluate_safety_gate,
    verify_evaluation_receipt,
    DEFAULT_MODEL_PATH,
    DEFAULT_BENCHMARK_PATH
)
from auth_util import get_admin_assertion_secret, reset_cached_keys_for_testing

TEST_SIGNING_SECRET = "sd_test_signing_secret_min_32_characters_entropy_secure!"

class TestSafetyGateHarness(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.orig_env = os.environ.copy()
        os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = TEST_SIGNING_SECRET
        reset_cached_keys_for_testing()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        reset_cached_keys_for_testing()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_metric_calculation_exception_fails_closed_never_substitutes_98(self):
        """When ROC-AUC calculation raises an exception, evaluation MUST fail closed and NEVER substitute 0.98."""
        with mock.patch("eval.safety_gate.roc_auc_score", side_effect=ValueError("Only one class present in y_true. ROC AUC score is not defined.")):
            passed, receipt = evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=DEFAULT_BENCHMARK_PATH,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
            # Must fail closed
            self.assertFalse(passed, "Gate evaluation must fail when ROC-AUC calculation encounters an exception")
            payload = receipt["payload"]
            self.assertEqual(payload["verdict"], "REJECTED")

            auc_gate = payload["gate_checks"]["gate_cisa_kev_roc_auc"]
            self.assertFalse(auc_gate["passed"])
            self.assertIsNone(auc_gate["actual"], "Must NOT fabricate 0.98 fallback value")
            self.assertIn("Threat discrimination metric calculation failed", str(auc_gate.get("error")))

    def test_missing_benchmark_columns_fails_closed(self):
        """Golden benchmark dataset missing critical ground truth columns must raise ValueError."""
        corrupt_bench_path = os.path.join(self.temp_dir, "bad_benchmark.parquet")
        # Missing 'kev_listed' and 'cvss_score'
        bad_df = pd.DataFrame({
            "cve_id": ["CVE-2024-0001"],
            "full_text": ["sample text"],
            "description": ["sample desc"]
        })
        bad_df.to_parquet(corrupt_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=corrupt_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("missing required columns", str(ctx.exception))

    def test_empty_benchmark_dataset_fails_closed(self):
        """Empty benchmark dataset must raise ValueError."""
        empty_bench_path = os.path.join(self.temp_dir, "empty_benchmark.parquet")
        empty_df = pd.DataFrame(columns=[
            "cve_id", "full_text", "epss_score", "kev_listed", "cvss_score", "cvss_severity", "description"
        ])
        empty_df.to_parquet(empty_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=empty_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("dataset is empty", str(ctx.exception))

    def _create_passing_receipt(self):
        with mock.patch("eval.safety_gate.f1_score", return_value=0.88), \
             mock.patch("eval.safety_gate.mean_absolute_error", return_value=0.45), \
             mock.patch("eval.safety_gate.roc_auc_score", return_value=0.985):
            passed, receipt = evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=DEFAULT_BENCHMARK_PATH,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
            return passed, receipt

    def test_receipt_cryptographic_verification_valid(self):
        """Legitimate evaluation receipt envelope passes HMAC verification and digest checks."""
        passed, receipt = self._create_passing_receipt()
        self.assertTrue(passed)

        valid, err_msg, verified_payload = verify_evaluation_receipt(
            receipt,
            expected_model_sha256=receipt["payload"]["model_sha256"],
            expected_benchmark_hash=receipt["payload"]["benchmark_dataset_hash"],
            secret=TEST_SIGNING_SECRET
        )
        self.assertTrue(valid, f"Verification failed unexpectedly: {err_msg}")
        self.assertEqual(err_msg, "")
        self.assertEqual(verified_payload["verdict"], "APPROVED")

    def test_tampered_receipt_payload_fails_verification(self):
        """Tampering with any metric or verdict in the receipt invalidates the HMAC signature."""
        passed, receipt = self._create_passing_receipt()
        self.assertTrue(passed)

        # Attacker tries to alter metrics in the payload
        tampered_receipt = json.loads(json.dumps(receipt))
        tampered_receipt["payload"]["metrics"]["kev_roc_auc"] = 0.9999

        valid, err_msg, _ = verify_evaluation_receipt(tampered_receipt, secret=TEST_SIGNING_SECRET)
        self.assertFalse(valid)
        self.assertIn("HMAC signature mismatch", err_msg)

    def test_tampered_receipt_signature_fails_verification(self):
        """Tampered or invalid signature is rejected."""
        passed, receipt = self._create_passing_receipt()
        self.assertTrue(passed)

        tampered_receipt = json.loads(json.dumps(receipt))
        tampered_receipt["signature"] = "deadbeef" * 8

        valid, err_msg, _ = verify_evaluation_receipt(tampered_receipt, secret=TEST_SIGNING_SECRET)
        self.assertFalse(valid)
        self.assertIn("HMAC signature mismatch", err_msg)

    def test_model_sha256_mismatch_fails_verification(self):
        """Receipt generated for model A is strictly rejected when presented for model B."""
        passed, receipt = self._create_passing_receipt()
        self.assertTrue(passed)

        valid, err_msg, _ = verify_evaluation_receipt(
            receipt,
            expected_model_sha256="wrong_model_artifact_hash_1234567890abcdef",
            secret=TEST_SIGNING_SECRET
        )
        self.assertFalse(valid)
        self.assertIn("Model artifact binding mismatch", err_msg)

    def test_benchmark_hash_mismatch_fails_verification(self):
        """Receipt evaluated against benchmark A is rejected when expected benchmark is B."""
        passed, receipt = self._create_passing_receipt()
        self.assertTrue(passed)

        valid, err_msg, _ = verify_evaluation_receipt(
            receipt,
            expected_benchmark_hash="wrong_golden_benchmark_hash_1234567890",
            secret=TEST_SIGNING_SECRET
        )
        self.assertFalse(valid)
        self.assertIn("Benchmark dataset binding mismatch", err_msg)

    def test_rejected_verdict_receipt_fails_verification(self):
        """Receipt with verdict 'REJECTED' fails verification."""
        with mock.patch("eval.safety_gate.roc_auc_score", side_effect=RuntimeError("Metric error")):
            passed, receipt = evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=DEFAULT_BENCHMARK_PATH,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
            self.assertFalse(passed)

        valid, err_msg, _ = verify_evaluation_receipt(receipt, secret=TEST_SIGNING_SECRET)
        self.assertFalse(valid)
        self.assertIn("verdict is 'REJECTED'", err_msg)

    def test_missing_epss_fails_closed_never_substitutes_zero(self):
        """EPSS missing or NaN must fail closed with ValueError rather than silently defaulting to 0.0."""
        bench_df = pd.read_parquet(DEFAULT_BENCHMARK_PATH)
        bad_df = bench_df.copy()
        bad_df.loc[0, "epss_score"] = np.nan
        bad_bench_path = os.path.join(self.temp_dir, "missing_epss_benchmark.parquet")
        bad_df.to_parquet(bad_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=bad_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("Silent fallback to 0.0 is prohibited", str(ctx.exception))

    def test_out_of_bounds_epss_fails_closed(self):
        """EPSS values out of [0.0, 100.0] range must fail closed."""
        bench_df = pd.read_parquet(DEFAULT_BENCHMARK_PATH)
        bad_df = bench_df.copy()
        bad_df.loc[0, "epss_score"] = 150.0  # Invalid probability/percentage
        bad_bench_path = os.path.join(self.temp_dir, "oob_epss_benchmark.parquet")
        bad_df.to_parquet(bad_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=bad_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("bounded within [0.0, 100.0]", str(ctx.exception))

    def test_negative_epss_fails_closed(self):
        """Negative EPSS values must fail closed."""
        bench_df = pd.read_parquet(DEFAULT_BENCHMARK_PATH)
        bad_df = bench_df.copy()
        bad_df.loc[0, "epss_score"] = -0.5
        bad_bench_path = os.path.join(self.temp_dir, "neg_epss_benchmark.parquet")
        bad_df.to_parquet(bad_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=bad_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("bounded within [0.0, 100.0]", str(ctx.exception))

    def test_empty_description_fails_closed(self):
        """Records with empty full_text and description must fail closed."""
        bench_df = pd.read_parquet(DEFAULT_BENCHMARK_PATH)
        bad_df = bench_df.copy()
        bad_df.loc[0, "full_text"] = ""
        bad_df.loc[0, "description"] = "   "
        bad_bench_path = os.path.join(self.temp_dir, "empty_desc_benchmark.parquet")
        bad_df.to_parquet(bad_bench_path)

        with self.assertRaises(ValueError) as ctx:
            evaluate_safety_gate(
                candidate_model_path=DEFAULT_MODEL_PATH,
                benchmark_path=bad_bench_path,
                signing_secret=TEST_SIGNING_SECRET,
                save_to_disk=False
            )
        self.assertIn("empty vulnerability text description", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()

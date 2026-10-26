"""
Unit & Security Test Suite for Hardened Model Registry.

Covers:
1. Manifest initialization and baseline provenance
2. Lifecycle circuit breaker (ENABLE_MODEL_LIFECYCLE disabled by default fails closed)
3. Mandatory candidate and rollback target binding
4. Administrative approver ID and cryptographic approval token enforcement
5. Artifact provenance and digest verification (tampered model artifact on disk rejected)
6. Evaluation receipt requirement and cryptographic verification (tampered receipt rejected)
7. Shadow evaluation divergence rate gating
8. Full authorized promotion and rollback cycle
9. Concurrent multi-thread atomic updates and manifest integrity
"""

import os
import sys
import json
import hmac
import time
import shutil
import hashlib
import tempfile
import threading
import unittest
from datetime import datetime, timezone

# Ensure ai-chat-desk is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from models.registry import ModelRegistry, DEFAULT_CHAMPION_PATH, is_model_lifecycle_enabled
from auth_util import get_admin_assertion_secret, reset_cached_keys_for_testing

TEST_SECRET = "sd_test_signing_secret_min_32_characters_entropy_secure!"


def _generate_valid_mock_receipt(
    model_path: str,
    secret: str = TEST_SECRET,
    benchmark_dataset_hash: str = None
) -> dict:
    """Helper to generate a cryptographically valid APPROVED receipt envelope for a model."""
    with open(model_path, "rb") as f:
        m_hash = hashlib.sha256(f.read()).hexdigest()

    if benchmark_dataset_hash is None:
        bench_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "golden_safety_benchmark.parquet"))
        if os.path.exists(bench_path):
            with open(bench_path, "rb") as f:
                benchmark_dataset_hash = hashlib.sha256(f.read()).hexdigest()
        else:
            benchmark_dataset_hash = "deadbeef" * 8

    payload = {
        "version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_path": model_path,
        "model_sha256": m_hash,
        "benchmark_path": "test_benchmark.parquet",
        "benchmark_dataset_hash": benchmark_dataset_hash,
        "benchmark_cases_count": 250,
        "verdict": "APPROVED",
        "gate_checks": {
            "gate_zero_tier_regressions": {"passed": True, "actual": 0, "threshold": "0"},
            "gate_cisa_kev_roc_auc": {"passed": True, "actual": 0.985, "threshold": ">= 0.970"},
            "gate_cvss_score_mae": {"passed": True, "actual": 0.450, "threshold": "<= 0.650"},
            "gate_cvss_severity_f1": {"passed": True, "actual": 0.880, "threshold": ">= 0.800"}
        },
        "metrics": {
            "severity_accuracy": 0.90,
            "severity_weighted_f1": 0.88,
            "cvss_score_mae": 0.45,
            "kev_roc_auc": 0.985,
            "safety_policy_violations": 0
        },
        "violations": []
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    receipt_hash = hashlib.sha256(canonical_bytes).hexdigest()

    return {
        "payload": payload,
        "signature": sig,
        "signature_algorithm": "HMAC-SHA256",
        "receipt_hash": receipt_hash
    }


class TestHardenedModelRegistry(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_env = os.environ.copy()
        os.environ["SHIELDDESK_ADMIN_ASSERTION_SECRET"] = TEST_SECRET
        # Explicitly ensure lifecycle is disabled by default
        os.environ.pop("ENABLE_MODEL_LIFECYCLE", None)
        reset_cached_keys_for_testing()

        # Create dummy candidate model artifact for tests
        self.dummy_model_path = os.path.join(self.test_dir, "test_candidate.joblib")
        with open(self.dummy_model_path, "wb") as f:
            f.write(b"SHIELDDESK_TEST_MODEL_ARTIFACT_BINARY_DATA_V1")

        self.registry = ModelRegistry(models_dir=self.test_dir)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        reset_cached_keys_for_testing()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_registry_initialization_and_provenance(self):
        """Initial manifest is created with active baseline champion and status ready."""
        status = self.registry.get_status()
        self.assertEqual(status["active_champion"], "v1.0.0-baseline")
        self.assertIsNone(status["active_challenger"])
        self.assertFalse(status["shadow_evaluation_enabled"])
        self.assertEqual(status["total_registered_versions"], 1)

    def test_lifecycle_disabled_by_default_fails_closed(self):
        """Registry promotion and rollback must fail closed with RuntimeError when lifecycle is disabled."""
        self.assertFalse(is_model_lifecycle_enabled())

        cand_id = self.registry.register_candidate(self.dummy_model_path)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(RuntimeError) as ctx_promo:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-sec-ops",
                approval_token="sd_test_approval_token_123"
            )
        self.assertIn("Model lifecycle operations are disabled", str(ctx_promo.exception))

        with self.assertRaises(RuntimeError) as ctx_roll:
            self.registry.rollback_to_previous(
                expected_target_id="v1.0.0-baseline",
                operator_id="admin-sec-ops",
                approval_token="sd_test_approval_token_123"
            )
        self.assertIn("Model lifecycle operations are disabled", str(ctx_roll.exception))

    def test_promote_without_approver_or_token_fails(self):
        """Promotion requires verified approver_id and cryptographic approval_token."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        # Missing approver_id
        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="",
                approval_token="sd_token_123"
            )
        self.assertIn("approver_id", str(ctx.exception))

        # Missing approval_token
        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token=""
            )
        self.assertIn("approval_token", str(ctx.exception))

    def test_promote_without_candidate_binding_fails(self):
        """Promotion fails if expected candidate does not match staged challenger."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id="v_bogus_mismatched",
                approver_id="admin-ops",
                approval_token="sd_token_123"
            )
        self.assertIn("Candidate mismatch", str(ctx.exception))

    def test_promote_without_receipt_fails(self):
        """Promotion is strictly blocked if candidate lacks an evaluation receipt."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        # Register candidate with NO receipt
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=None)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123"
            )
        self.assertIn("no evaluation receipt", str(ctx.exception))

    def test_promote_with_tampered_receipt_fails(self):
        """Promotion is strictly blocked if evaluation receipt signature or content is tampered."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        # Attacker attempts to forge metrics inside receipt
        receipt["payload"]["metrics"]["kev_roc_auc"] = 0.9999
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123",
                signing_secret=TEST_SECRET
            )
        self.assertIn("verification failed", str(ctx.exception))

    def test_promote_with_benchmark_hash_mismatch_fails(self):
        """Promotion fails if candidate evaluation receipt was evaluated against a different benchmark."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(
            self.dummy_model_path,
            benchmark_dataset_hash="wrong_bench_hash_" + "0" * 48
        )
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123",
                signing_secret=TEST_SECRET
            )
        self.assertIn("Benchmark dataset binding mismatch", str(ctx.exception))

    def test_promote_with_explicit_expected_benchmark_hash_mismatch_fails(self):
        """Promotion fails if explicitly specified expected_benchmark_hash does not match."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123",
                expected_benchmark_hash="different_expected_benchmark_hash_00000000",
                signing_secret=TEST_SECRET
            )
        self.assertIn("Benchmark dataset binding mismatch", str(ctx.exception))

    def test_promote_artifact_tampering_on_disk_fails_provenance(self):
        """If staged model file on disk is modified after registration, promotion fails artifact provenance check."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        # Attacker overwrites staged artifact file on disk
        manifest = self.registry.load_manifest()
        staged_path = manifest["versions"][cand_id]["artifact_path"]
        with open(staged_path, "wb") as f:
            f.write(b"MALICIOUS_BACKDOORED_MODEL_CONTENT")

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123",
                signing_secret=TEST_SECRET
            )
        self.assertIn("Artifact provenance failure", str(ctx.exception))

    def test_shadow_divergence_exceeded_blocks_promotion(self):
        """If shadow evaluation records excessive divergences, promotion is rejected."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        os.environ["MAX_SHADOW_DIVERGENCE_RATE"] = "0.05"  # 5% max allowed
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        # Record 100 shadow inferences with 20 divergences (20% divergence rate)
        for _ in range(80):
            self.registry.record_shadow_inference(diverged=False)
        for _ in range(20):
            self.registry.record_shadow_inference(diverged=True)

        with self.assertRaises(ValueError) as ctx:
            self.registry.promote_challenger_to_champion(
                expected_candidate_id=cand_id,
                approver_id="admin-ops",
                approval_token="sd_token_123",
                signing_secret=TEST_SECRET
            )
        self.assertIn("Shadow divergence rate (20.00%) exceeds maximum allowed", str(ctx.exception))

    def test_authorized_promote_and_rollback_cycle_succeeds(self):
        """Full authorized lifecycle cycle with verified receipt, provenance, and tokens."""
        os.environ["ENABLE_MODEL_LIFECYCLE"] = "true"
        receipt = _generate_valid_mock_receipt(self.dummy_model_path)
        cand_id = self.registry.register_candidate(self.dummy_model_path, receipt_data=receipt)
        self.registry.stage_challenger(cand_id, enable_shadow=True)

        # 1. Promote to Champion
        promoted = self.registry.promote_challenger_to_champion(
            expected_candidate_id=cand_id,
            approver_id="super_admin_security_lead",
            approval_token="sd_cryptographic_nonce_777",
            signing_secret=TEST_SECRET
        )
        self.assertEqual(promoted, cand_id)

        status = self.registry.get_status()
        self.assertEqual(status["active_champion"], cand_id)
        self.assertIsNone(status["active_challenger"])
        self.assertFalse(status["shadow_evaluation_enabled"])

        # Check recorded provenance in manifest
        champ_record = status["champion_details"]
        self.assertEqual(champ_record["status"], "CHAMPION")
        self.assertEqual(champ_record["promoted_by"], "super_admin_security_lead")
        self.assertEqual(champ_record["approval_token_nonce"], "sd_cryptographic_nonce_777")
        self.assertIsNotNone(champ_record.get("receipt_hash"))

        # 2. Rollback to baseline Champion
        reverted = self.registry.rollback_to_previous(
            expected_target_id="v1.0.0-baseline",
            operator_id="sec_ops_incident_responder",
            approval_token="sd_rollback_nonce_888"
        )
        self.assertEqual(reverted, "v1.0.0-baseline")

        status_after_rollback = self.registry.get_status()
        self.assertEqual(status_after_rollback["active_champion"], "v1.0.0-baseline")
        baseline_record = status_after_rollback["champion_details"]
        self.assertEqual(baseline_record["status"], "CHAMPION")
        self.assertEqual(baseline_record["rolled_back_by"], "sec_ops_incident_responder")
        self.assertEqual(baseline_record["rollback_approval_token_nonce"], "sd_rollback_nonce_888")

    def test_concurrent_manifest_updates_atomic(self):
        """Concurrent threads updating registry simultaneously preserve valid JSON and manifest state."""
        errors = []

        def worker(thread_idx: int):
            try:
                for i in range(10):
                    self.registry.record_shadow_inference(diverged=(i % 3 == 0))
                    manifest = self.registry.load_manifest()
                    self.assertIn("active_champion", manifest)
            except Exception as e:
                errors.append(f"Thread {thread_idx} error: {e}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Concurrent thread errors occurred: {errors}")
        status = self.registry.get_status()
        self.assertEqual(status["total_shadow_inferences"], 50)
        self.assertEqual(status["shadow_divergences"], 20)


if __name__ == "__main__":
    unittest.main()

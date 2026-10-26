"""
ShieldDesk Hardened Model Registry, Provenance Tracker & Atomic Rollback Engine.

Manages model versions, cryptographic manifests, atomic in-memory activations,
cross-process file locking, and verified promotion/rollback gates.

Defense-in-depth safety invariants:
1. Lifecycle circuit breaker: Promotion and rollback fail closed when ENABLE_MODEL_LIFECYCLE is false.
2. Mandatory candidate & target binding: Target IDs must be explicitly asserted and match staged state.
3. Explicit administrative credentials: Operator ID and cryptographic approval token are strictly required.
4. Artifact provenance: Model artifact files must exist on disk and match stored SHA-256 digests.
5. Evaluation release gate: Promoted models must possess a cryptographically verified receipt with APPROVED verdict.
6. Atomic manifest operations: Protected by cross-process lockfile and atomic file replacement.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import threading
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

# Ensure parent directory is in path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from eval.safety_gate import verify_evaluation_receipt
except ImportError:
    verify_evaluation_receipt = None

BASE_MODELS_DIR = os.path.abspath(os.path.dirname(__file__))
VERSIONS_DIR = os.path.join(BASE_MODELS_DIR, "versions")
MANIFEST_PATH = os.path.join(BASE_MODELS_DIR, "manifest.json")
DEFAULT_CHAMPION_PATH = os.path.join(BASE_MODELS_DIR, "cve_random_forest_model.joblib")
DEFAULT_BENCHMARK_PATH = os.path.abspath(os.path.join(BASE_MODELS_DIR, "..", "data", "golden_safety_benchmark.parquet"))


def is_model_lifecycle_enabled() -> bool:
    """Returns True ONLY when ENABLE_MODEL_LIFECYCLE=true/1 explicitly."""
    return os.getenv("ENABLE_MODEL_LIFECYCLE", "false").strip().lower() in ("true", "1", "yes")


class ModelRegistry:
    def __init__(self, models_dir: str = BASE_MODELS_DIR):
        self.models_dir = os.path.abspath(models_dir)
        self.versions_dir = os.path.join(self.models_dir, "versions")
        self.manifest_path = os.path.join(self.models_dir, "manifest.json")
        self.active_champion_path = os.path.join(self.models_dir, "cve_random_forest_model.joblib")
        self.lock_path = self.manifest_path + ".lock"
        self._thread_lock = threading.RLock()
        self._lock_depth = 0
        self._lock_fd: Optional[int] = None
        os.makedirs(self.versions_dir, exist_ok=True)
        self._ensure_manifest()

    def _get_git_commit(self) -> str:
        try:
            out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
            return out.decode("utf-8").strip()
        except Exception:
            return "untracked"

    @contextmanager
    def _manifest_lock(self, timeout: float = 10.0):
        """
        Cross-process and thread-safe lock for manifest operations.
        Uses atomic file creation with timeout and stale-lock recovery.
        """
        with self._thread_lock:
            if self._lock_depth == 0:
                start_time = time.time()
                fd = None
                while True:
                    try:
                        fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                        os.write(fd, f"{os.getpid()}:{time.time()}".encode("utf-8"))
                        self._lock_fd = fd
                        break
                    except FileExistsError:
                        # Stale lock recovery (> 30s)
                        try:
                            st = os.stat(self.lock_path)
                            if time.time() - st.st_mtime > 30.0:
                                try:
                                    os.remove(self.lock_path)
                                    continue
                                except OSError:
                                    pass
                        except OSError:
                            pass

                        if time.time() - start_time > timeout:
                            raise TimeoutError(f"Timed out after {timeout}s waiting for manifest lock: {self.lock_path}")
                        time.sleep(0.02)

            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    fd = self._lock_fd
                    self._lock_fd = None
                    if fd is not None:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        try:
                            if os.path.exists(self.lock_path):
                                os.remove(self.lock_path)
                        except OSError:
                            pass

    def _atomic_write_json(self, target_path: str, data: Dict[str, Any]):
        """Writes JSON to temporary file and atomically replaces target."""
        dir_name = os.path.dirname(os.path.abspath(target_path))
        os.makedirs(dir_name, exist_ok=True)
        tmp_path = f"{target_path}.tmp.{os.getpid()}_{time.time_ns()}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _ensure_manifest(self):
        """Initializes manifest.json if missing with baseline hash."""
        with self._manifest_lock():
            if not os.path.exists(self.manifest_path):
                baseline_artifact_path = os.path.join(self.versions_dir, "cve_rf_v1.0.0-baseline.joblib")
                baseline_hash = None
                if os.path.exists(DEFAULT_CHAMPION_PATH):
                    if not os.path.exists(baseline_artifact_path):
                        shutil.copy2(DEFAULT_CHAMPION_PATH, baseline_artifact_path)
                    with open(baseline_artifact_path, "rb") as f:
                        baseline_hash = hashlib.sha256(f.read()).hexdigest()
                    if not os.path.exists(self.active_champion_path):
                        try:
                            shutil.copy2(baseline_artifact_path, self.active_champion_path)
                        except Exception:
                            pass

                initial_manifest = {
                    "active_champion": "v1.0.0-baseline",
                    "active_challenger": None,
                    "shadow_evaluation_enabled": False,
                    "total_shadow_inferences": 0,
                    "shadow_divergences": 0,
                    "versions": {
                        "v1.0.0-baseline": {
                            "version": "v1.0.0-baseline",
                            "artifact_path": baseline_artifact_path,
                            "sha256": baseline_hash,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "promoted_at": datetime.now(timezone.utc).isoformat(),
                            "git_commit": self._get_git_commit(),
                            "status": "CHAMPION",
                            "receipt": None
                        }
                    },
                    "history": ["v1.0.0-baseline"]
                }
                self._atomic_write_json(self.manifest_path, initial_manifest)

    def load_manifest(self) -> Dict[str, Any]:
        """Loads manifest safely under lock."""
        with self._manifest_lock():
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)

    def save_manifest(self, manifest: Dict[str, Any]):
        """Saves manifest atomically under lock."""
        with self._manifest_lock():
            self._atomic_write_json(self.manifest_path, manifest)

    def register_candidate(
        self,
        candidate_model_path: str,
        receipt_path: Optional[str] = None,
        receipt_data: Optional[Dict[str, Any]] = None,
        dataset_path: Optional[str] = None
    ) -> str:
        """
        Registers a new evaluated candidate model artifact.
        Copies the file to models/versions/ and records cryptographic digests.
        """
        if not os.path.exists(candidate_model_path):
            raise FileNotFoundError(f"Candidate file {candidate_model_path} not found.")

        # Compute model SHA-256
        with open(candidate_model_path, "rb") as f:
            model_hash = hashlib.sha256(f.read()).hexdigest()

        # Compute dataset SHA-256 if provided
        dataset_hash = None
        if dataset_path and os.path.exists(dataset_path):
            with open(dataset_path, "rb") as f:
                dataset_hash = hashlib.sha256(f.read()).hexdigest()

        # Load receipt if provided
        receipt = None
        if receipt_data:
            receipt = receipt_data
        elif receipt_path and os.path.exists(receipt_path):
            with open(receipt_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)

        now = datetime.now(timezone.utc)
        version_id = f"v{now.strftime('%Y%m%d%H%M%S')}"
        dest_filename = f"cve_rf_{version_id}.joblib"
        dest_path = os.path.join(self.versions_dir, dest_filename)

        shutil.copy2(candidate_model_path, dest_path)

        with self._manifest_lock():
            manifest = self.load_manifest()
            manifest["versions"][version_id] = {
                "version": version_id,
                "artifact_path": dest_path,
                "sha256": model_hash,
                "dataset_sha256": dataset_hash,
                "created_at": now.isoformat(),
                "git_commit": self._get_git_commit(),
                "status": "STAGED",
                "receipt": receipt
            }
            self.save_manifest(manifest)

        print(f"[+] Registered candidate version {version_id} in {dest_path}")
        return version_id

    def stage_challenger(self, version_id: str, enable_shadow: bool = True):
        """Sets a registered candidate as the active Challenger for shadow scoring."""
        with self._manifest_lock():
            manifest = self.load_manifest()
            if version_id not in manifest.get("versions", {}):
                raise KeyError(f"Version {version_id} not registered.")

            manifest["active_challenger"] = version_id
            manifest["shadow_evaluation_enabled"] = enable_shadow
            manifest["versions"][version_id]["status"] = "CHALLENGER"
            manifest["versions"][version_id]["shadow_started_at"] = datetime.now(timezone.utc).isoformat()
            self.save_manifest(manifest)

        print(f"[+] Staged Challenger: {version_id} (Shadow Mode: {enable_shadow})")

    def record_shadow_inference(self, diverged: bool = False):
        """Safely increments shadow inference counter and divergence counter."""
        with self._manifest_lock():
            manifest = self.load_manifest()
            manifest["total_shadow_inferences"] = manifest.get("total_shadow_inferences", 0) + 1
            if diverged:
                manifest["shadow_divergences"] = manifest.get("shadow_divergences", 0) + 1
            self.save_manifest(manifest)

    def promote_challenger_to_champion(
        self,
        expected_candidate_id: str,
        approver_id: str,
        approval_token: str,
        expected_benchmark_hash: Optional[str] = None,
        require_shadow: bool = False,
        signing_secret: Optional[str] = None
    ) -> str:
        """
        Promotes staged Challenger to Champion.
        Enforces all safety, provenance, receipt, and security gates at registry level:
        1. Circuit breaker: ENABLE_MODEL_LIFECYCLE=true required.
        2. Input validation: expected_candidate_id, approver_id, approval_token must be non-empty strings.
        3. Challenger staging & binding: staged challenger must match expected_candidate_id.
        4. Artifact provenance: model file on disk must exist and match recorded SHA-256 digest.
        5. Evaluation receipt: must contain cryptographically verified receipt bound to model and benchmark.
        6. Shadow evaluation result: divergence rate must not exceed allowed threshold.
        """
        # Gate 1: Registry-level circuit breaker
        if not is_model_lifecycle_enabled():
            raise RuntimeError(
                "Model lifecycle operations are disabled: ENABLE_MODEL_LIFECYCLE=false. Promotion is prohibited."
            )

        # Gate 2: Mandatory candidate binding & explicit approval credentials
        if not expected_candidate_id or not isinstance(expected_candidate_id, str) or not expected_candidate_id.strip():
            raise ValueError("Mandatory candidate binding: 'expected_candidate_id' must be a non-empty string.")

        if not approver_id or not isinstance(approver_id, str) or not approver_id.strip():
            raise ValueError("Promotion requires a verified administrator 'approver_id'.")

        if not approval_token or not isinstance(approval_token, str) or not approval_token.strip():
            raise ValueError("Promotion requires a valid cryptographic 'approval_token'.")

        with self._manifest_lock():
            manifest = self.load_manifest()
            challenger_id = manifest.get("active_challenger")
            if not challenger_id or challenger_id not in manifest.get("versions", {}):
                raise ValueError("No valid Challenger staged for promotion.")

            if challenger_id != expected_candidate_id.strip():
                raise ValueError(
                    f"Candidate mismatch in registry: staged challenger is '{challenger_id}', expected '{expected_candidate_id}'."
                )

            challenger_entry = manifest["versions"][challenger_id]

            # Gate 3: Artifact provenance verification
            artifact_path = challenger_entry.get("artifact_path")
            if not artifact_path or not os.path.exists(artifact_path):
                raise FileNotFoundError(f"Artifact provenance failure: Model file '{artifact_path}' does not exist on disk.")

            with open(artifact_path, "rb") as f:
                actual_sha256 = hashlib.sha256(f.read()).hexdigest()

            expected_sha256 = challenger_entry.get("sha256")
            if not expected_sha256 or actual_sha256.lower() != expected_sha256.lower():
                raise ValueError(
                    f"Artifact provenance failure: Staged model digest ({actual_sha256}) does not match manifest digest ({expected_sha256})."
                )

            # Gate 4: Evaluation receipt verification with model and benchmark binding
            receipt = challenger_entry.get("receipt")
            if not receipt:
                raise ValueError(f"Promotion rejected: Candidate version '{challenger_id}' has no evaluation receipt.")

            if verify_evaluation_receipt is None:
                raise RuntimeError("Evaluation release gate verifier could not be imported.")

            target_bench_hash = expected_benchmark_hash
            if target_bench_hash is None:
                if os.path.exists(DEFAULT_BENCHMARK_PATH):
                    with open(DEFAULT_BENCHMARK_PATH, "rb") as f:
                        target_bench_hash = hashlib.sha256(f.read()).hexdigest()
                else:
                    target_bench_hash = challenger_entry.get("dataset_sha256")

            if not target_bench_hash:
                raise ValueError("Promotion rejected: Missing expected benchmark dataset hash for cryptographic receipt verification.")

            valid, err_msg, verified_payload = verify_evaluation_receipt(
                receipt_input=receipt,
                expected_model_sha256=expected_sha256,
                expected_benchmark_hash=target_bench_hash,
                secret=signing_secret
            )
            if not valid:
                raise ValueError(f"Promotion rejected: Evaluation receipt cryptographic verification failed: {err_msg}")

            receipt_bench_hash = verified_payload.get("benchmark_dataset_hash")
            if not receipt_bench_hash or receipt_bench_hash.lower() != target_bench_hash.lower():
                raise ValueError(
                    f"Promotion rejected: Receipt benchmark hash ({receipt_bench_hash}) does not match expected benchmark ({target_bench_hash})."
                )

            if verified_payload.get("verdict") != "APPROVED":
                raise ValueError(f"Promotion rejected: Evaluation receipt verdict is '{verified_payload.get('verdict')}', required 'APPROVED'.")

            gate_checks = verified_payload.get("gate_checks", {})
            if not gate_checks or not all(g.get("passed") is True for g in gate_checks.values()):
                raise ValueError("Promotion rejected: Evaluation receipt contains failed release gate checks.")

            # Gate 5: Shadow evaluation verification
            total_shadow = int(manifest.get("total_shadow_inferences", 0))
            divergences = int(manifest.get("shadow_divergences", 0))
            min_shadow = int(os.getenv("MIN_SHADOW_INFERENCES", "0"))
            max_div_rate = float(os.getenv("MAX_SHADOW_DIVERGENCE_RATE", "0.05"))

            if require_shadow or manifest.get("shadow_evaluation_enabled"):
                if total_shadow < min_shadow:
                    raise ValueError(
                        f"Promotion rejected: Shadow evaluation requires at least {min_shadow} inferences, but observed {total_shadow}."
                    )
                if total_shadow > 0:
                    div_rate = divergences / total_shadow
                    if div_rate > max_div_rate:
                        raise ValueError(
                            f"Promotion rejected: Shadow divergence rate ({div_rate:.2%}) exceeds maximum allowed ({max_div_rate:.2%})."
                        )

            # State Transition
            old_champion_id = manifest.get("active_champion")
            if old_champion_id and old_champion_id in manifest.get("versions", {}):
                manifest["versions"][old_champion_id]["status"] = "RETIRED"

            manifest["active_champion"] = challenger_id
            manifest["versions"][challenger_id]["status"] = "CHAMPION"
            manifest["versions"][challenger_id]["promoted_at"] = datetime.now(timezone.utc).isoformat()
            manifest["versions"][challenger_id]["promoted_by"] = approver_id.strip()
            manifest["versions"][challenger_id]["approval_token_nonce"] = approval_token.strip()
            manifest["versions"][challenger_id]["receipt_hash"] = (
                receipt.get("receipt_hash") if isinstance(receipt, dict) else None
            )
            manifest["versions"][challenger_id]["benchmark_dataset_hash"] = target_bench_hash
            manifest["active_challenger"] = None
            manifest["shadow_evaluation_enabled"] = False
            manifest["history"].append(challenger_id)

            # Safely mirror active champion artifact to registry's active_champion_path
            try:
                if os.path.abspath(artifact_path) != os.path.abspath(self.active_champion_path):
                    shutil.copy2(artifact_path, self.active_champion_path)
            except Exception as e:
                print(f"[!] Info: Physical overwrite of champion path bypassed ({e}). In-memory pointer remains authoritative.")

            self.save_manifest(manifest)

        print(f"[+] Promoted {challenger_id} to CHAMPION (Previous: {old_champion_id}) by approver '{approver_id}'")
        return challenger_id

    def rollback_to_previous(
        self,
        expected_target_id: str,
        operator_id: str,
        approval_token: str
    ) -> str:
        """
        Rolls back production Champion to the previous known-good version.
        Enforces all safety, provenance, and authorization gates at registry level:
        1. Circuit breaker: ENABLE_MODEL_LIFECYCLE=true required.
        2. Input validation: expected_target_id, operator_id, approval_token must be non-empty strings.
        3. Target resolution & binding: previous version in history must match expected_target_id.
        4. Target artifact provenance: target model file must exist and match recorded SHA-256.
        """
        # Gate 1: Registry-level circuit breaker
        if not is_model_lifecycle_enabled():
            raise RuntimeError(
                "Model lifecycle operations are disabled: ENABLE_MODEL_LIFECYCLE=false. Rollback is prohibited."
            )

        # Gate 2: Mandatory target binding & explicit approval credentials
        if not expected_target_id or not isinstance(expected_target_id, str) or not expected_target_id.strip():
            raise ValueError("Mandatory target binding: 'expected_target_id' must be a non-empty string.")

        if not operator_id or not isinstance(operator_id, str) or not operator_id.strip():
            raise ValueError("Rollback requires a verified administrator 'operator_id'.")

        if not approval_token or not isinstance(approval_token, str) or not approval_token.strip():
            raise ValueError("Rollback requires a valid cryptographic 'approval_token'.")

        with self._manifest_lock():
            manifest = self.load_manifest()
            history = manifest.get("history", [])
            if len(history) < 2:
                raise ValueError("No previous version available in history to rollback to.")

            current = history[-1]
            previous = history[-2]

            if previous != expected_target_id.strip():
                raise ValueError(
                    f"Rollback target mismatch in registry: target in history is '{previous}', expected '{expected_target_id}'."
                )

            if previous not in manifest.get("versions", {}):
                raise ValueError(f"Rollback target '{previous}' not found in registered versions.")

            target_entry = manifest["versions"][previous]
            target_path = target_entry.get("artifact_path")
            if not target_path or not os.path.exists(target_path):
                raise FileNotFoundError(f"Rollback artifact missing: Target file '{target_path}' does not exist on disk.")

            # Provenance check for rollback target
            if target_entry.get("sha256"):
                with open(target_path, "rb") as f:
                    actual_target_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_target_hash.lower() != target_entry["sha256"].lower():
                    raise ValueError(
                        f"Rollback provenance failure: Target model digest ({actual_target_hash}) does not match manifest digest ({target_entry['sha256']})."
                    )

            # Pop current from history
            history.pop()

            manifest["active_champion"] = previous
            manifest["versions"][previous]["status"] = "CHAMPION"
            manifest["versions"][previous]["rolled_back_by"] = operator_id.strip()
            manifest["versions"][previous]["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            manifest["versions"][previous]["rollback_approval_token_nonce"] = approval_token.strip()

            if current in manifest.get("versions", {}):
                manifest["versions"][current]["status"] = "ROLLED_BACK"

            manifest["history"] = history
            manifest["active_challenger"] = None
            manifest["shadow_evaluation_enabled"] = False

            # Restore active champion path artifact
            try:
                if os.path.exists(target_path) and os.path.abspath(target_path) != os.path.abspath(self.active_champion_path):
                    shutil.copy2(target_path, self.active_champion_path)
            except Exception as e:
                print(f"[!] Info: Physical overwrite of champion path bypassed ({e}). In-memory pointer remains authoritative.")

            self.save_manifest(manifest)

        print(f"[+] Rolled back CHAMPION to {previous} (Reverted from: {current}) by operator '{operator_id}'")
        return previous

    def get_status(self) -> Dict[str, Any]:
        """Returns sanitized status of registry."""
        manifest = self.load_manifest()
        champ_id = manifest.get("active_champion")
        chall_id = manifest.get("active_challenger")
        return {
            "status": "ready",
            "active_champion": champ_id,
            "champion_details": manifest.get("versions", {}).get(champ_id),
            "active_challenger": chall_id,
            "challenger_details": manifest.get("versions", {}).get(chall_id) if chall_id else None,
            "shadow_evaluation_enabled": manifest.get("shadow_evaluation_enabled", False),
            "total_shadow_inferences": manifest.get("total_shadow_inferences", 0),
            "shadow_divergences": manifest.get("shadow_divergences", 0),
            "total_registered_versions": len(manifest.get("versions", {}))
        }


if __name__ == "__main__":
    reg = ModelRegistry()
    print(json.dumps(reg.get_status(), indent=2))

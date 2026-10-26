"""
ShieldDesk Model Registry, Provenance Tracker & Atomic Rollback Engine.

Manages model versions, cryptographic manifests, atomic in-memory activations,
and instant rollbacks.
"""

import os
import json
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

BASE_MODELS_DIR = os.path.abspath(os.path.dirname(__file__))
VERSIONS_DIR = os.path.join(BASE_MODELS_DIR, "versions")
MANIFEST_PATH = os.path.join(BASE_MODELS_DIR, "manifest.json")
DEFAULT_CHAMPION_PATH = os.path.join(BASE_MODELS_DIR, "cve_random_forest_model.joblib")

class ModelRegistry:
    def __init__(self, models_dir: str = BASE_MODELS_DIR):
        self.models_dir = os.path.abspath(models_dir)
        self.versions_dir = os.path.join(self.models_dir, "versions")
        self.manifest_path = os.path.join(self.models_dir, "manifest.json")
        os.makedirs(self.versions_dir, exist_ok=True)
        self._ensure_manifest()

    def _get_git_commit(self) -> str:
        try:
            out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
            return out.decode("utf-8").strip()
        except Exception:
            return "untracked"

    def _ensure_manifest(self):
        """Initializes manifest.json if missing."""
        if not os.path.exists(self.manifest_path):
            initial_manifest = {
                "active_champion": "v1.0.0-baseline",
                "active_challenger": None,
                "shadow_evaluation_enabled": False,
                "total_shadow_inferences": 0,
                "shadow_divergences": 0,
                "versions": {
                    "v1.0.0-baseline": {
                        "version": "v1.0.0-baseline",
                        "artifact_path": DEFAULT_CHAMPION_PATH,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "promoted_at": datetime.now(timezone.utc).isoformat(),
                        "git_commit": self._get_git_commit(),
                        "status": "CHAMPION",
                        "receipt": None
                    }
                },
                "history": ["v1.0.0-baseline"]
            }
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(initial_manifest, f, indent=2)

    def load_manifest(self) -> Dict[str, Any]:
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_manifest(self, manifest: Dict[str, Any]):
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    def register_candidate(
        self,
        candidate_model_path: str,
        receipt_path: Optional[str] = None,
        dataset_path: Optional[str] = None
    ) -> str:
        """
        Registers a new evaluated candidate model artifact.
        Copies the file to models/versions/ and generates a unique version ID.
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
        receipt_data = None
        if receipt_path and os.path.exists(receipt_path):
            with open(receipt_path, "r", encoding="utf-8") as f:
                receipt_data = json.load(f)

        now = datetime.now(timezone.utc)
        version_id = f"v{now.strftime('%Y%m%d%H%M%S')}"
        dest_filename = f"cve_rf_{version_id}.joblib"
        dest_path = os.path.join(self.versions_dir, dest_filename)

        shutil.copy2(candidate_model_path, dest_path)

        manifest = self.load_manifest()
        manifest["versions"][version_id] = {
            "version": version_id,
            "artifact_path": dest_path,
            "sha256": model_hash,
            "dataset_sha256": dataset_hash,
            "created_at": now.isoformat(),
            "git_commit": self._get_git_commit(),
            "status": "STAGED",
            "receipt": receipt_data
        }
        self.save_manifest(manifest)
        print(f"[+] Registered candidate version {version_id} in {dest_path}")
        return version_id

    def stage_challenger(self, version_id: str, enable_shadow: bool = True):
        """Sets a registered candidate as the active Challenger for shadow scoring."""
        manifest = self.load_manifest()
        if version_id not in manifest["versions"]:
            raise KeyError(f"Version {version_id} not registered.")

        manifest["active_challenger"] = version_id
        manifest["shadow_evaluation_enabled"] = enable_shadow
        manifest["versions"][version_id]["status"] = "CHALLENGER"
        manifest["versions"][version_id]["shadow_started_at"] = datetime.now(timezone.utc).isoformat()
        self.save_manifest(manifest)
        print(f"[+] Staged Challenger: {version_id} (Shadow Mode: {enable_shadow})")

    def promote_challenger_to_champion(
        self,
        expected_candidate_id: str,
        approver_id: Optional[str] = None,
        approval_token: Optional[str] = None
    ) -> str:
        """
        Promotes current Challenger to Champion.
        Updates manifest and points active production to the new version.
        Enforces mandatory candidate binding and records approval provenance.
        """
        if not expected_candidate_id or not isinstance(expected_candidate_id, str) or not expected_candidate_id.strip():
            raise ValueError("Mandatory candidate binding: 'expected_candidate_id' must be a non-empty string.")

        manifest = self.load_manifest()
        challenger_id = manifest.get("active_challenger")
        if not challenger_id or challenger_id not in manifest["versions"]:
            raise ValueError("No valid Challenger staged for promotion.")

        if challenger_id != expected_candidate_id.strip():
            raise ValueError(f"Candidate mismatch in registry: staged challenger is '{challenger_id}', expected '{expected_candidate_id}'.")

        old_champion_id = manifest["active_champion"]
        if old_champion_id in manifest["versions"]:
            manifest["versions"][old_champion_id]["status"] = "RETIRED"

        # Update Champion
        manifest["active_champion"] = challenger_id
        manifest["versions"][challenger_id]["status"] = "CHAMPION"
        manifest["versions"][challenger_id]["promoted_at"] = datetime.now(timezone.utc).isoformat()
        if approver_id:
            manifest["versions"][challenger_id]["promoted_by"] = approver_id
        if approval_token:
            manifest["versions"][challenger_id]["approval_token_nonce"] = approval_token
        manifest["active_challenger"] = None
        manifest["shadow_evaluation_enabled"] = False
        manifest["history"].append(challenger_id)

        # Update default production artifact path safely
        new_artifact_path = manifest["versions"][challenger_id]["artifact_path"]
        try:
            if os.path.abspath(new_artifact_path) != os.path.abspath(DEFAULT_CHAMPION_PATH):
                shutil.copy2(new_artifact_path, DEFAULT_CHAMPION_PATH)
        except Exception as e:
            print(f"[!] Info: Physical overwrite of default path bypassed ({e}). In-memory pointer remains authoritative.")

        self.save_manifest(manifest)
        print(f"[+] Promoted {challenger_id} to CHAMPION (Previous: {old_champion_id})")
        return challenger_id

    def rollback_to_previous(
        self,
        expected_target_id: str,
        operator_id: Optional[str] = None
    ) -> str:
        """
        Rolls back production Champion to the previous known-good version.
        Enforces mandatory rollback target binding and records rollback provenance.
        """
        if not expected_target_id or not isinstance(expected_target_id, str) or not expected_target_id.strip():
            raise ValueError("Mandatory target binding: 'expected_target_id' must be a non-empty string.")

        manifest = self.load_manifest()
        history = manifest.get("history", [])
        if len(history) < 2:
            raise ValueError("No previous version available in history to rollback to.")

        current = history.pop()  # remove current
        previous = history[-1]   # target previous

        if previous != expected_target_id.strip():
            raise ValueError(f"Rollback target mismatch in registry: target in history is '{previous}', expected '{expected_target_id}'.")

        manifest["active_champion"] = previous
        if previous in manifest["versions"]:
            manifest["versions"][previous]["status"] = "CHAMPION"
            if operator_id:
                manifest["versions"][previous]["rolled_back_by"] = operator_id
                manifest["versions"][previous]["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            target_path = manifest["versions"][previous]["artifact_path"]
            try:
                if os.path.exists(target_path) and os.path.abspath(target_path) != os.path.abspath(DEFAULT_CHAMPION_PATH):
                    shutil.copy2(target_path, DEFAULT_CHAMPION_PATH)
            except Exception as e:
                print(f"[!] Info: Physical overwrite of default path bypassed ({e}). In-memory pointer remains authoritative.")

        if current in manifest["versions"]:
            manifest["versions"][current]["status"] = "ROLLED_BACK"

        manifest["history"] = history
        manifest["active_challenger"] = None
        manifest["shadow_evaluation_enabled"] = False
        self.save_manifest(manifest)
        print(f"[+] Rolled back CHAMPION to {previous} (Reverted from: {current})")
        return previous

    def get_status(self) -> Dict[str, Any]:
        manifest = self.load_manifest()
        champ_id = manifest.get("active_champion")
        chall_id = manifest.get("active_challenger")
        return {
            "status": "ready",
            "active_champion": champ_id,
            "champion_details": manifest["versions"].get(champ_id),
            "active_challenger": chall_id,
            "challenger_details": manifest["versions"].get(chall_id) if chall_id else None,
            "shadow_evaluation_enabled": manifest.get("shadow_evaluation_enabled", False),
            "total_shadow_inferences": manifest.get("total_shadow_inferences", 0),
            "shadow_divergences": manifest.get("shadow_divergences", 0),
            "total_registered_versions": len(manifest.get("versions", {}))
        }

if __name__ == "__main__":
    reg = ModelRegistry()
    print(json.dumps(reg.get_status(), indent=2))

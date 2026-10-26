"""
ShieldDesk AI Safety Release Gate & Evaluation Harness.

Enforces permanent acceptance criteria before any candidate model may be
promoted to production:
1. Zero Tolerance for Remediation Policy Regressions:
   - 0% instances where Tier 3 / Critical flaws are classified as Tier 1.
   - 0% instances where active KEV weaponized flaws execute autonomously.
2. Threat Discrimination Invariant:
   - CISA KEV ROC-AUC must remain >= 0.970.
3. Regression Performance SLOs:
   - CVSS Score Continuous MAE must remain <= 0.650.
   - CVSS Severity Weighted F1 must remain >= 0.800.

Emits an immutable, cryptographically signed evaluation receipt bound to:
- Model artifact SHA-256
- Golden benchmark dataset SHA-256
- Exact calculated metrics (no default fabrications)
- Gate check evaluations and final verdict
"""

import os
import sys
import json
import math
import hmac
import hashlib
import argparse
from typing import Tuple, Dict, Any, Optional, Union
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, mean_absolute_error, roc_auc_score

# Ensure parent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from cve_random_forest import CVERandomForestModel
from safety_policy import evaluate_remediation_safety_guard, TIER_1_AUTONOMOUS
from auth_util import get_admin_assertion_secret

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "cve_random_forest_model.joblib")
DEFAULT_BENCHMARK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "golden_safety_benchmark.parquet")
RECEIPT_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

REQUIRED_BENCHMARK_COLUMNS = {
    "cve_id",
    "full_text",
    "epss_score",
    "kev_listed",
    "cvss_score",
    "cvss_severity",
    "description",
}

def evaluate_safety_gate(
    candidate_model_path: str = DEFAULT_MODEL_PATH,
    benchmark_path: str = DEFAULT_BENCHMARK_PATH,
    strict_exit: bool = False,
    signing_secret: Optional[str] = None,
    output_receipt_path: Optional[str] = None,
    save_to_disk: bool = True
) -> Tuple[bool, Dict[str, Any]]:
    """
    Evaluates candidate model against golden safety benchmark.
    Fails closed on missing data, metric exceptions, or SLO violations.
    Emits a cryptographically signed receipt envelope.
    """
    print("==================================================================")
    print("           SHIELDDESK AI MODEL SAFETY RELEASE GATE                ")
    print("==================================================================")
    print(f"[*] Candidate Model:   {candidate_model_path}")
    print(f"[*] Golden Benchmark:  {benchmark_path}")

    if not os.path.exists(candidate_model_path):
        raise FileNotFoundError(f"Model file {candidate_model_path} does not exist.")
    if not os.path.exists(benchmark_path):
        raise FileNotFoundError(f"Benchmark file {benchmark_path} does not exist.")

    # 1. Compute Model & Benchmark SHA-256 Hashes
    with open(candidate_model_path, "rb") as f:
        model_sha256 = hashlib.sha256(f.read()).hexdigest()

    with open(benchmark_path, "rb") as f:
        bench_hash = hashlib.sha256(f.read()).hexdigest()

    # 2. Strict Benchmark Dataset Validation (No fabricated fallbacks)
    df = pd.read_parquet(benchmark_path)
    missing_cols = REQUIRED_BENCHMARK_COLUMNS - set(df.columns)
    if missing_cols:
        raise ValueError(f"Benchmark dataset validation failed: missing required columns {missing_cols}")

    if len(df) == 0:
        raise ValueError("Benchmark dataset validation failed: dataset is empty.")

    # Ground truth labels must be present and non-null
    if df["kev_listed"].isna().any():
        raise ValueError("Benchmark dataset contains missing/NaN 'kev_listed' ground truth labels.")
    if df["cvss_score"].isna().any():
        raise ValueError("Benchmark dataset contains missing/NaN 'cvss_score' ground truth labels.")
    if df["cvss_severity"].isna().any():
        raise ValueError("Benchmark dataset contains missing/NaN 'cvss_severity' ground truth labels.")

    # Validate KEV ground truth contains both positive and negative classes for ROC-AUC
    unique_kev = np.unique(df["kev_listed"].astype(int))
    if len(unique_kev) < 2:
        raise ValueError("Benchmark dataset must contain both KEV (1) and non-KEV (0) examples.")

    print(f"[+] Loaded {len(df)} golden test cases (Dataset Hash: {bench_hash[:12]}...)")
    print(f"[+] Candidate Model Artifact Hash: {model_sha256[:12]}...")

    # 3. Load Model
    model = CVERandomForestModel.load(candidate_model_path)

    # 4. Extract Features
    X_test = model._extract_features(
        df["full_text"].fillna("").astype(str).tolist(),
        epss_scores=pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0).values,
        kev_statuses=df["kev_listed"].astype(int).values,
        is_fit=False
    )

    # 5. Predictions & Metrics Calculation (Fail closed on any metric exception)
    # A. Severity
    y_pred_sev = model.rf_severity.predict(X_test)
    y_true_sev = df["cvss_severity"].astype(str).values
    sev_f1_weighted = float(f1_score(y_true_sev, y_pred_sev, average="weighted", zero_division=0))
    sev_acc = float(accuracy_score(y_true_sev, y_pred_sev))

    # B. Score
    y_pred_score = np.clip(model.rf_score.predict(X_test), 0.0, 10.0)
    y_true_score = df["cvss_score"].astype(float).values
    score_mae = float(mean_absolute_error(y_true_score, y_pred_score))

    # C. KEV ROC-AUC (Fail closed on exception; never fabricate 0.98 fallback)
    raw_kev_prob = model.rf_kev.predict_proba(X_test)
    if np.max(raw_kev_prob) > 1.0:
        raw_kev_prob = raw_kev_prob / np.sum(raw_kev_prob, axis=1, keepdims=True)
    y_pred_kev = raw_kev_prob[:, 1]
    y_true_kev = df["kev_listed"].astype(int).values

    kev_auc: Optional[float] = None
    kev_auc_error: Optional[str] = None
    try:
        calc_auc = float(roc_auc_score(y_true_kev, y_pred_kev))
        if math.isnan(calc_auc) or math.isinf(calc_auc):
            kev_auc_error = "Calculated ROC-AUC is NaN or Infinite"
        else:
            kev_auc = calc_auc
    except Exception as exc:
        kev_auc_error = f"Threat discrimination metric calculation failed: {str(exc)}"

    # D. Safety Policy Audit: Verify 0 violations on Golden Cases
    violations = []
    y_pred_tier = model.rf_tier.predict(X_test)
    tier_probs = model.rf_tier.predict_proba(X_test)
    if np.max(tier_probs) > 1.0:
        tier_probs = tier_probs / np.sum(tier_probs, axis=1, keepdims=True)

    for i, row in df.iterrows():
        raw_tier = y_pred_tier[i]
        cve_id = row["cve_id"]
        cvss = float(row["cvss_score"])
        kev = int(row["kev_listed"])
        desc = str(row["description"])

        pred_dict = {
            "assigned_tier": raw_tier,
            "assigned_tier_confidence": float(np.max(tier_probs[i])),
            "cvss_score": float(y_pred_score[i]),
            "cvss_severity": str(y_pred_sev[i]),
            "kev_exploitation_risk": {
                "is_active_exploit_threat": bool(y_pred_kev[i] >= 0.35 or kev == 1),
                "exploit_probability": float(y_pred_kev[i])
            }
        }

        # Apply deterministic safety policy
        guarded = evaluate_remediation_safety_guard(pred_dict, description=desc)

        # Invariant check: Effective tier must NEVER be Tier 1 for High/Critical or KEV
        effective_tier = guarded["effective_assigned_tier"]
        if (kev == 1 or cvss >= 7.0 or str(row["cvss_severity"]).upper() in ("HIGH", "CRITICAL")) and effective_tier == TIER_1_AUTONOMOUS:
            violations.append({
                "cve_id": cve_id,
                "cvss_score": cvss,
                "kev_listed": kev,
                "violation": "High/Critical/KEV flaw permitted autonomous execution"
            })

    # 6. Evaluate Gate Checks
    gate_checks = {
        "gate_zero_tier_regressions": {
            "threshold": "0 violations",
            "actual": len(violations),
            "passed": len(violations) == 0
        },
        "gate_cisa_kev_roc_auc": {
            "threshold": ">= 0.970",
            "actual": round(kev_auc, 4) if kev_auc is not None else None,
            "passed": (kev_auc is not None) and (kev_auc >= 0.970),
            "error": kev_auc_error
        },
        "gate_cvss_score_mae": {
            "threshold": "<= 0.650",
            "actual": round(score_mae, 4),
            "passed": score_mae <= 0.650
        },
        "gate_cvss_severity_f1": {
            "threshold": ">= 0.800",
            "actual": round(sev_f1_weighted, 4),
            "passed": sev_f1_weighted >= 0.800
        }
    }

    passed = all(g["passed"] for g in gate_checks.values())
    for g_name, g_info in gate_checks.items():
        if not g_info["passed"]:
            print(f"[FAIL] FAILED GATE: {g_name} | Actual: {g_info['actual']} vs Required: {g_info['threshold']} (Error: {g_info.get('error')})")
        else:
            print(f"[PASS] PASSED GATE: {g_name} | Value: {g_info['actual']}")

    # 7. Construct Cryptographic Receipt Payload
    now_iso = datetime.now(timezone.utc).isoformat()
    receipt_payload = {
        "version": "1.0",
        "timestamp": now_iso,
        "model_path": candidate_model_path,
        "model_sha256": model_sha256,
        "benchmark_path": benchmark_path,
        "benchmark_dataset_hash": bench_hash,
        "benchmark_cases_count": len(df),
        "verdict": "APPROVED" if passed else "REJECTED",
        "gate_checks": gate_checks,
        "metrics": {
            "severity_accuracy": sev_acc,
            "severity_weighted_f1": sev_f1_weighted,
            "cvss_score_mae": score_mae,
            "kev_roc_auc": kev_auc,
            "safety_policy_violations": len(violations)
        },
        "violations": violations[:10]
    }

    # Canonical serialization
    canonical_bytes = json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    secret = signing_secret or get_admin_assertion_secret()
    sig = hmac.new(secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    receipt_hash = hashlib.sha256(canonical_bytes).hexdigest()

    receipt_envelope = {
        "payload": receipt_payload,
        "signature": sig,
        "signature_algorithm": "HMAC-SHA256",
        "receipt_hash": receipt_hash
    }

    # Save receipt
    receipt_file_path = None
    if save_to_disk:
        if output_receipt_path:
            receipt_file_path = output_receipt_path
            os.makedirs(os.path.dirname(os.path.abspath(receipt_file_path)), exist_ok=True)
        else:
            os.makedirs(RECEIPT_DIR, exist_ok=True)
            receipt_filename = f"eval_receipt_{int(datetime.now().timestamp())}.json"
            receipt_file_path = os.path.join(RECEIPT_DIR, receipt_filename)
        with open(receipt_file_path, "w", encoding="utf-8") as f:
            json.dump(receipt_envelope, f, indent=2)

    if receipt_file_path:
        print(f"\n[+] Generated Cryptographic Evaluation Receipt: {receipt_file_path}")
    print(f"[+] Receipt Hash: {receipt_hash}")
    print(f"[+] HMAC-SHA256 Signature: {sig[:16]}...")
    print(f"[+] Overall Gate Verdict: {'APPROVED' if passed else 'REJECTED'}")
    print("==================================================================")

    if strict_exit and not passed:
        sys.exit(1)

    return passed, receipt_envelope

def verify_evaluation_receipt(
    receipt_input: Union[str, Dict[str, Any]],
    expected_model_sha256: Optional[str] = None,
    expected_benchmark_hash: Optional[str] = None,
    secret: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Cryptographically verifies an evaluation receipt envelope:
    1. Validates HMAC-SHA256 signature against secret.
    2. Validates receipt_hash matches canonical payload digest.
    3. Validates overall verdict is 'APPROVED'.
    4. Validates all individual release gates passed.
    5. Validates model artifact SHA-256 matches expected model artifact.
    6. Validates benchmark dataset SHA-256 matches expected benchmark dataset.
    """
    if isinstance(receipt_input, str):
        if not os.path.exists(receipt_input):
            return False, f"Receipt file '{receipt_input}' does not exist.", {}
        try:
            with open(receipt_input, "r", encoding="utf-8") as f:
                envelope = json.load(f)
        except Exception as e:
            return False, f"Failed to parse receipt JSON: {str(e)}", {}
    elif isinstance(receipt_input, dict):
        envelope = receipt_input
    else:
        return False, "Invalid receipt input: must be file path or dictionary envelope.", {}

    if not isinstance(envelope, dict):
        return False, "Receipt format error: envelope must be a dictionary.", {}

    payload = envelope.get("payload")
    sig = envelope.get("signature")
    if not payload or not sig or not isinstance(payload, dict) or not isinstance(sig, str):
        return False, "Receipt format error: missing 'payload' or 'signature'.", {}

    # 1. Cryptographic HMAC-SHA256 signature verification
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signing_secret = secret or get_admin_assertion_secret()
    expected_sig = hmac.new(signing_secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return False, "Cryptographic verification failed: receipt HMAC signature mismatch (tampered receipt).", {}

    # 2. Receipt Hash verification
    expected_hash = hashlib.sha256(canonical_bytes).hexdigest()
    if envelope.get("receipt_hash") != expected_hash:
        return False, "Receipt integrity check failed: payload hash mismatch.", {}

    # 3. Verdict verification
    verdict = payload.get("verdict")
    if verdict != "APPROVED":
        return False, f"Receipt evaluation verdict is '{verdict}', not 'APPROVED'.", payload

    # 4. Gate Checks verification
    gate_checks = payload.get("gate_checks", {})
    for g_name, g_val in gate_checks.items():
        if not g_val.get("passed", False):
            return False, f"Receipt release gate '{g_name}' did not pass.", payload

    # 5. Model Artifact SHA-256 Binding
    if expected_model_sha256 is not None:
        receipt_model_sha = payload.get("model_sha256")
        if receipt_model_sha != expected_model_sha256:
            return False, (
                f"Model artifact binding mismatch: receipt was evaluated for model '{receipt_model_sha}', "
                f"but candidate artifact hash is '{expected_model_sha256}'."
            ), payload

    # 6. Benchmark Dataset Hash Binding
    if expected_benchmark_hash is not None:
        receipt_bench_hash = payload.get("benchmark_dataset_hash")
        if receipt_bench_hash != expected_benchmark_hash:
            return False, (
                f"Benchmark dataset binding mismatch: receipt used benchmark '{receipt_bench_hash}', "
                f"but expected benchmark hash is '{expected_benchmark_hash}'."
            ), payload

    return True, "", payload

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--benchmark", default=DEFAULT_BENCHMARK_PATH)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    evaluate_safety_gate(args.candidate, args.benchmark, strict_exit=args.strict)

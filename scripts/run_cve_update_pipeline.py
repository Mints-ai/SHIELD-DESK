"""
ShieldDesk Vulnerability Intelligence & Model Update Pipeline Orchestrator.

CLI commands:
  python scripts/run_cve_update_pipeline.py --sync-only       # Fast feed sync (KEV/EPSS)
  python scripts/run_cve_update_pipeline.py --status          # Print model registry status
  python scripts/run_cve_update_pipeline.py --eval-gate       # Run golden benchmark safety gate
  python scripts/run_cve_update_pipeline.py --rollback        # Atomic rollback to previous champion
"""

import os
import sys
import argparse
import subprocess

# Set working directory to ai-chat-desk for module resolution
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AI_DIR = os.path.join(REPO_ROOT, "ai-chat-desk")
sys.path.insert(0, AI_DIR)

from pipeline.feed_sync import CVEFeedSynchronizer
from models.registry import ModelRegistry
from eval.safety_gate import evaluate_safety_gate

from train_rf_model import train_single_rf

def run_sync():
    print("==================================================================")
    print("      STEP 1: THREAT INTELLIGENCE FEED SYNCHRONIZATION            ")
    print("==================================================================")
    syncer = CVEFeedSynchronizer()
    cisa_items = syncer.sync_cisa_kev()
    total = syncer.initialize_or_update_lookup_store(cisa_items=cisa_items)
    print(f"[+] Threat Intelligence Sync Complete: {total} active records indexed.\n")
    return total

def run_retrain(candidate_output_path: str = None) -> str:
    print("==================================================================")
    print("        STEP 2: AUTOMATED MODEL RETRAINING PIPELINE               ")
    print("==================================================================")
    if not candidate_output_path:
        candidate_output_path = os.path.join(AI_DIR, "models", "candidate_model.joblib")
    source_parquet = os.path.join(AI_DIR, "data", "cve_lookup_store.parquet")
    output_path = train_single_rf(source_parquet=source_parquet, output_model_path=candidate_output_path)
    print(f"[+] Automated Retraining Complete: {output_path}\n")
    return output_path

def run_gate(candidate_path: str = None):
    print("==================================================================")
    print("      STEP 3: GOLDEN SAFETY BENCHMARK & REGRESSION GATE           ")
    print("==================================================================")
    if not candidate_path:
        candidate_path = os.path.join(AI_DIR, "models", "cve_random_forest_model.joblib")
    benchmark_path = os.path.join(AI_DIR, "data", "golden_safety_benchmark.parquet")
    passed, receipt = evaluate_safety_gate(candidate_path, benchmark_path)
    return passed, receipt

def run_full_cycle():
    print("******************************************************************")
    print("     STARTING FULL AUTOMATED RETRAINING & MLOPS CYCLE            ")
    print("******************************************************************\n")
    run_sync()
    cand_path = run_retrain()
    passed, receipt = run_gate(cand_path)

    if passed:
        print("==================================================================")
        print("    STEP 4: STAGING APPROVED CHALLENGER IN MODEL REGISTRY         ")
        print("==================================================================")
        reg = ModelRegistry(models_dir=os.path.join(AI_DIR, "models"))
        version_id = reg.register_candidate(
            candidate_model_path=cand_path,
            receipt_data=receipt,
            dataset_path=os.path.join(AI_DIR, "data", "cve_lookup_store.parquet")
        )
        reg.stage_challenger(version_id, enable_shadow=True)
        print(f"[+] Candidate staged as Challenger {version_id} with shadow scoring enabled.")
    else:
        print("\n[!] Candidate model failed safety release gate. Promotion halted.")

    print_status()

def print_status():
    print("==================================================================")
    print("              MODEL REGISTRY & PROVENANCE STATUS                  ")
    print("==================================================================")
    reg = ModelRegistry(models_dir=os.path.join(AI_DIR, "models"))
    status = reg.get_status()
    print(f"Active Champion:      {status['active_champion']}")
    print(f"Active Challenger:    {status['active_challenger'] or 'None (Shadow Inactive)'}")
    print(f"Shadow Mode Enabled:  {status['shadow_evaluation_enabled']}")
    print(f"Total Shadow Evals:   {status['total_shadow_inferences']}")
    print(f"Shadow Divergences:   {status['shadow_divergences']}")
    print(f"Registered Versions:  {status['total_registered_versions']}")
    print("==================================================================\n")

def run_rollback(operator_id: Optional[str] = None, approval_token: Optional[str] = None):
    print("==================================================================")
    print("            ATOMIC PRODUCTION MODEL ROLLBACK                      ")
    print("==================================================================")
    reg = ModelRegistry(models_dir=os.path.join(AI_DIR, "models"))
    manifest = reg.load_manifest()
    history = manifest.get("history", [])
    if len(history) < 2:
        print("[!] No previous version available in history to rollback to.")
        return
    prev_target = history[-2]

    resolved_op = (operator_id or os.getenv("SHIELDDESK_OPERATOR_ID") or "").strip()
    resolved_token = (
        approval_token or
        os.getenv("SHIELDDESK_APPROVAL_TOKEN") or
        os.getenv("SHIELDDESK_APPROVAL_NONCE") or
        ""
    ).strip()

    if not resolved_op:
        raise ValueError(
            "Rollback aborted: Missing required administrator identity. "
            "Must provide --operator-id or set environment variable SHIELDDESK_OPERATOR_ID."
        )
    if not resolved_token:
        raise ValueError(
            "Rollback aborted: Missing required cryptographic approval token. "
            "Must provide --approval-token or set environment variable SHIELDDESK_APPROVAL_TOKEN."
        )

    prev = reg.rollback_to_previous(
        expected_target_id=prev_target,
        operator_id=resolved_op,
        approval_token=resolved_token
    )
    print(f"[+] Successfully rolled back to: {prev}\n")

def main():
    parser = argparse.ArgumentParser(description="ShieldDesk CVE Update Pipeline")
    parser.add_argument("--sync-only", action="store_true", help="Sync CISA KEV and EPSS into standalone lookup store")
    parser.add_argument("--retrain", action="store_true", help="Retrain candidate model on latest ingested dataset")
    parser.add_argument("--eval-gate", action="store_true", help="Evaluate candidate against golden safety benchmark")
    parser.add_argument("--full-cycle", action="store_true", help="Run full automated cycle: Sync -> Retrain -> Benchmark -> Stage Challenger")
    parser.add_argument("--status", action="store_true", help="Display model registry and shadow evaluation status")
    parser.add_argument("--rollback", action="store_true", help="Rollback production model to previous version")
    parser.add_argument("--operator-id", default=None, help="Verified administrator identity for authorized rollback")
    parser.add_argument("--approval-token", default=None, help="Cryptographic approval token for authorized rollback")
    args = parser.parse_args()

    if args.full_cycle:
        run_full_cycle()
    elif args.retrain:
        run_retrain()
    elif args.sync_only:
        run_sync()
    elif args.eval_gate:
        run_gate()
    elif args.rollback:
        run_rollback(operator_id=args.operator_id, approval_token=args.approval_token)
    elif args.status:
        print_status()
    else:
        # Default runs sync + status
        run_sync()
        print_status()

if __name__ == "__main__":
    main()

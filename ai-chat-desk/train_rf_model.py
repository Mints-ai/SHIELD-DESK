"""
Training script for the Unified Single Random Forest CVE Model.
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, r2_score, mean_squared_error, mean_absolute_error, classification_report, confusion_matrix, roc_auc_score
from cve_random_forest import CVERandomForestModel

def train_single_rf():
    print("==================================================================")
    print("      TRAINING UNIFIED SINGLE MODEL (RANDOM FOREST ENGINE)        ")
    print("==================================================================")

    df = pd.read_parquet("data/harmonized_cve.parquet")
    print(f"[+] Total Dataset: {len(df)} records")

    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["cvss_severity"]
    )
    print(f"[+] Train Set: {len(train_df)} | Test Set: {len(test_df)}")

    # Initialize and fit unified Random Forest model
    rf_model = CVERandomForestModel(n_estimators=160, random_state=42)
    rf_model.fit(train_df)

    # Evaluate on held-out test set
    print("\n--- Evaluating Unified Random Forest Model on Test Set ---")
    X_test = rf_model._extract_features(
        test_df["full_text"].tolist(),
        epss_scores=test_df["epss_score"].values,
        kev_statuses=test_df["kev_listed"].values,
        is_fit=False
    )

    # 1. Severity
    y_pred_sev = rf_model.rf_severity.predict(X_test)
    y_test_sev = test_df["cvss_severity"].values
    sev_acc = accuracy_score(y_test_sev, y_pred_sev)
    sev_f1_macro = f1_score(y_test_sev, y_pred_sev, average="macro")
    sev_f1_weighted = f1_score(y_test_sev, y_pred_sev, average="weighted")
    print(f"[1] CVSS Severity Accuracy: {sev_acc*100:.2f}% | Macro F1: {sev_f1_macro:.4f} | Weighted F1: {sev_f1_weighted:.4f}")
    print(classification_report(y_test_sev, y_pred_sev, digits=4))

    # 2. Score
    y_pred_score = np.clip(rf_model.rf_score.predict(X_test), 0.0, 10.0)
    y_test_score = test_df["cvss_score"].values
    score_r2 = r2_score(y_test_score, y_pred_score)
    score_rmse = np.sqrt(mean_squared_error(y_test_score, y_pred_score))
    score_mae = mean_absolute_error(y_test_score, y_pred_score)
    print(f"[2] CVSS Score R^2: {score_r2:.4f} | RMSE: {score_rmse:.4f} | MAE: {score_mae:.4f}")

    # 3. Tier
    y_pred_tier = rf_model.rf_tier.predict(X_test)
    y_test_tier = test_df["assigned_tier"].values
    tier_acc = accuracy_score(y_test_tier, y_pred_tier)
    tier_f1_macro = f1_score(y_test_tier, y_pred_tier, average="macro")
    tier_f1_weighted = f1_score(y_test_tier, y_pred_tier, average="weighted")
    print(f"[3] Remediation Tier Accuracy: {tier_acc*100:.2f}% | Macro F1: {tier_f1_macro:.4f} | Weighted F1: {tier_f1_weighted:.4f}")

    # 4. KEV
    y_pred_kev_prob = rf_model.rf_kev.predict_proba(X_test)[:, 1]
    y_test_kev = test_df["kev_listed"].values
    kev_roc = roc_auc_score(y_test_kev, y_pred_kev_prob)
    print(f"[4] KEV Threat ROC-AUC: {kev_roc:.4f}")

    # Save metrics
    metrics = {
        "model_architecture": "Single Unified Random Forest Model",
        "dataset_summary": {
            "total_records": len(df),
            "test_records": len(test_df),
            "domains": list(df["domain"].value_counts().to_dict().items())
        },
        "cvss_severity_metrics": {
            "accuracy": float(sev_acc),
            "macro_f1": float(sev_f1_macro),
            "weighted_f1": float(sev_f1_weighted),
            "classes": list(rf_model.rf_severity.classes_),
            "classification_report": classification_report(y_test_sev, y_pred_sev, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test_sev, y_pred_sev, labels=list(rf_model.rf_severity.classes_)).tolist()
        },
        "cvss_score_metrics": {
            "r2_score": float(score_r2),
            "rmse": float(score_rmse),
            "mae": float(score_mae)
        },
        "remediation_tier_metrics": {
            "accuracy": float(tier_acc),
            "macro_f1": float(tier_f1_macro),
            "weighted_f1": float(tier_f1_weighted),
            "classes": list(rf_model.rf_tier.classes_),
            "classification_report": classification_report(y_test_tier, y_pred_tier, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test_tier, y_pred_tier, labels=list(rf_model.rf_tier.classes_)).tolist()
        },
        "kev_exploitation_metrics": {
            "roc_auc": float(kev_roc),
            "f1_score": float(f1_score(y_test_kev, (y_pred_kev_prob >= 0.35).astype(int), zero_division=0))
        }
    }
    rf_model.metrics = metrics

    # Save the single unified model
    rf_model.save("models/cve_random_forest_model.joblib")
    with open("models/evaluation_report.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print("\n[+] SUCCESS! Single Random Forest Model trained and saved to models/cve_random_forest_model.joblib")

if __name__ == "__main__":
    train_single_rf()

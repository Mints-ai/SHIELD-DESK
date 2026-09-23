"""
Comprehensive Evaluation and Benchmarking Suite for CVE AI Models.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    mean_squared_error, mean_absolute_error, r2_score,
    classification_report, confusion_matrix, roc_auc_score
)
from feature_extractor import CVEFeatureExtractor

def evaluate_models():
    print("================================================================")
    print("           CVE AI MODEL EVALUATION & BENCHMARK REPORT           ")
    print("================================================================")

    df = pd.read_parquet("data/harmonized_cve.parquet")
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["cvss_severity"]
    )

    feature_extractor = joblib.load("models/feature_extractor.joblib")
    sev_model = joblib.load("models/cvss_severity_model.joblib")
    score_model = joblib.load("models/cvss_score_model.joblib")
    tier_model = joblib.load("models/remediation_tier_model.joblib")
    kev_model = joblib.load("models/kev_risk_model.joblib")

    X_test = feature_extractor.transform(
        test_df["full_text"],
        epss_scores=test_df["epss_score"],
        kev_statuses=test_df["kev_listed"]
    )

    # 1. Severity Evaluation
    y_test_sev = test_df["cvss_severity"].values
    y_pred_sev = sev_model.predict(X_test)
    sev_report = classification_report(y_test_sev, y_pred_sev, output_dict=True)
    sev_cm = confusion_matrix(y_test_sev, y_pred_sev, labels=list(sev_model.classes_)).tolist()

    # 2. Score Evaluation
    y_test_score = test_df["cvss_score"].values
    y_pred_score = np.clip(score_model.predict(X_test), 0.0, 10.0)
    score_r2 = r2_score(y_test_score, y_pred_score)
    score_rmse = np.sqrt(mean_squared_error(y_test_score, y_pred_score))
    score_mae = mean_absolute_error(y_test_score, y_pred_score)

    # 3. Tier Evaluation
    y_test_tier = test_df["assigned_tier"].values
    y_pred_tier = tier_model.predict(X_test)
    tier_report = classification_report(y_test_tier, y_pred_tier, output_dict=True)
    tier_cm = confusion_matrix(y_test_tier, y_pred_tier, labels=list(tier_model.classes_)).tolist()

    # 4. KEV Evaluation
    y_test_kev = test_df["kev_listed"].values
    y_pred_kev_prob = kev_model.predict_proba(X_test)[:, 1]
    y_pred_kev = (y_pred_kev_prob >= 0.40).astype(int)
    kev_roc = roc_auc_score(y_test_kev, y_pred_kev_prob)
    kev_f1 = f1_score(y_test_kev, y_pred_kev, zero_division=0)

    eval_results = {
        "dataset_summary": {
            "total_records": len(df),
            "test_records": len(test_df),
            "domains": list(df["domain"].value_counts().to_dict().items())
        },
        "cvss_severity_metrics": {
            "accuracy": float(accuracy_score(y_test_sev, y_pred_sev)),
            "macro_f1": float(f1_score(y_test_sev, y_pred_sev, average="macro")),
            "weighted_f1": float(f1_score(y_test_sev, y_pred_sev, average="weighted")),
            "classes": list(sev_model.classes_),
            "classification_report": sev_report,
            "confusion_matrix": sev_cm
        },
        "cvss_score_metrics": {
            "r2_score": float(score_r2),
            "rmse": float(score_rmse),
            "mae": float(score_mae)
        },
        "remediation_tier_metrics": {
            "accuracy": float(accuracy_score(y_test_tier, y_pred_tier)),
            "macro_f1": float(f1_score(y_test_tier, y_pred_tier, average="macro")),
            "weighted_f1": float(f1_score(y_test_tier, y_pred_tier, average="weighted")),
            "classes": list(tier_model.classes_),
            "classification_report": tier_report,
            "confusion_matrix": tier_cm
        },
        "kev_exploitation_metrics": {
            "roc_auc": float(kev_roc),
            "f1_score": float(kev_f1)
        }
    }

    with open("models/evaluation_report.json", "w") as f:
        json.dump(eval_results, f, indent=2)

    print("\n[+] Severity Accuracy: {:.2f}% | Macro F1: {:.4f}".format(
        eval_results["cvss_severity_metrics"]["accuracy"]*100,
        eval_results["cvss_severity_metrics"]["macro_f1"]
    ))
    print("[+] CVSS Score Regressor R^2: {:.4f} | RMSE: {:.4f}".format(score_r2, score_rmse))
    print("[+] Tier Classifier Accuracy: {:.2f}% | Macro F1: {:.4f}".format(
        eval_results["remediation_tier_metrics"]["accuracy"]*100,
        eval_results["remediation_tier_metrics"]["macro_f1"]
    ))
    print("[+] KEV Threat Predictor ROC-AUC: {:.4f}".format(kev_roc))
    print("\n[+] Detailed evaluation saved to models/evaluation_report.json")

if __name__ == "__main__":
    evaluate_models()

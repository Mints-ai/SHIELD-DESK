"""
CVE AI Model Training and Feature Extraction Pipeline.
Trains and exports:
1. Feature extraction pipeline (Word & Char TF-IDF + metadata features)
2. CVSS Severity Classifier (Calibrated probabilities for CRITICAL, HIGH, MEDIUM, LOW)
3. CVSS Score Regressor (Predicts continuous CVSS score 0.0 - 10.0)
4. Operational Remediation Tier Classifier (Tier 1: Autonomous, Tier 2: Human-Approved, Tier 3: Dual-Sign-Off)
5. KEV Exploitation Risk Classifier (Binary probability of CISA KEV exploitation)
6. Semantic Mitigation Recommendation Engine & Vector Index (Nearest Neighbors over 12,000+ mitigations)
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    mean_squared_error, mean_absolute_error, r2_score,
    classification_report, confusion_matrix, roc_auc_score
)
from sklearn.neighbors import NearestNeighbors
from feature_extractor import CVEFeatureExtractor

def train_all():
    print("==================================================================")
    print("           CVE AI MODEL TRAINING & KNOWLEDGE BASE ENGINE          ")
    print("==================================================================")

    # 1. Load data
    os.makedirs("models", exist_ok=True)
    df = pd.read_parquet("data/harmonized_cve.parquet")
    print(f"\n[+] Loaded {len(df)} total harmonized CVE vulnerability records.")

    # 2. Split
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["cvss_severity"]
    )
    print(f"[+] Stratified Train set: {len(train_df)} | Test set: {len(test_df)}")

    # 3. Fit Feature Extractor
    print("\n[+] Extracting unified Word+Char TF-IDF & Structural Features...")
    feature_extractor = CVEFeatureExtractor()
    feature_extractor.fit(train_df["full_text"])

    X_train = feature_extractor.transform(
        train_df["full_text"],
        epss_scores=train_df["epss_score"],
        kev_statuses=train_df["kev_listed"]
    )
    X_test = feature_extractor.transform(
        test_df["full_text"],
        epss_scores=test_df["epss_score"],
        kev_statuses=test_df["kev_listed"]
    )
    print(f"[+] Extracted Feature Matrix: {X_train.shape[1]} dimensions.")

    joblib.dump(feature_extractor, "models/feature_extractor.joblib")
    print("[+] Saved Feature Extractor to models/feature_extractor.joblib")

    metrics_report = {
        "dataset": {
            "total_records": len(df),
            "train_records": len(train_df),
            "test_records": len(test_df),
            "features_dim": X_train.shape[1]
        }
    }

    # =================================================================
    # 4. CVSS Severity Classifier (CRITICAL, HIGH, MEDIUM, LOW)
    # =================================================================
    print("\n------------------------------------------------------------------")
    print("1. Training CVSS Severity Classifier")
    print("------------------------------------------------------------------")
    y_train_sev = train_df["cvss_severity"].values
    y_test_sev = test_df["cvss_severity"].values

    sev_model = LogisticRegression(
        C=2.5,
        max_iter=500,
        class_weight="balanced",
        solver="sag",
        random_state=42
    )
    sev_model.fit(X_train, y_train_sev)
    y_pred_sev = sev_model.predict(X_test)
    y_prob_sev = sev_model.predict_proba(X_test)

    sev_acc = accuracy_score(y_test_sev, y_pred_sev)
    sev_f1_macro = f1_score(y_test_sev, y_pred_sev, average="macro")
    sev_f1_weighted = f1_score(y_test_sev, y_pred_sev, average="weighted")
    print(f"Accuracy: {sev_acc*100:.2f}% | Macro F1: {sev_f1_macro:.4f} | Weighted F1: {sev_f1_weighted:.4f}")

    joblib.dump(sev_model, "models/cvss_severity_model.joblib")
    metrics_report["cvss_severity"] = {
        "accuracy": float(sev_acc),
        "macro_f1": float(sev_f1_macro),
        "weighted_f1": float(sev_f1_weighted),
        "classes": list(sev_model.classes_),
        "confusion_matrix": confusion_matrix(y_test_sev, y_pred_sev, labels=list(sev_model.classes_)).tolist()
    }

    # =================================================================
    # 5. CVSS Numerical Score Regressor (0.0 - 10.0)
    # =================================================================
    print("\n------------------------------------------------------------------")
    print("2. Training CVSS Score Regressor (0.0 - 10.0)")
    print("------------------------------------------------------------------")
    y_train_score = train_df["cvss_score"].values
    y_test_score = test_df["cvss_score"].values

    score_model = Ridge(alpha=0.6, random_state=42)
    score_model.fit(X_train, y_train_score)
    y_pred_score = np.clip(score_model.predict(X_test), 0.0, 10.0)

    score_r2 = r2_score(y_test_score, y_pred_score)
    score_rmse = np.sqrt(mean_squared_error(y_test_score, y_pred_score))
    score_mae = mean_absolute_error(y_test_score, y_pred_score)
    print(f"R^2 Score: {score_r2:.4f} | RMSE: {score_rmse:.4f} | MAE: {score_mae:.4f}")

    joblib.dump(score_model, "models/cvss_score_model.joblib")
    metrics_report["cvss_score"] = {
        "r2_score": float(score_r2),
        "rmse": float(score_rmse),
        "mae": float(score_mae)
    }

    # =================================================================
    # 6. Operational Remediation Tier Classifier
    # =================================================================
    print("\n------------------------------------------------------------------")
    print("3. Training Operational Remediation Tier Classifier")
    print("------------------------------------------------------------------")
    y_train_tier = train_df["assigned_tier"].values
    y_test_tier = test_df["assigned_tier"].values

    tier_model = LogisticRegression(
        C=3.0,
        max_iter=500,
        class_weight="balanced",
        solver="sag",
        random_state=42
    )
    tier_model.fit(X_train, y_train_tier)
    y_pred_tier = tier_model.predict(X_test)

    tier_acc = accuracy_score(y_test_tier, y_pred_tier)
    tier_f1_macro = f1_score(y_test_tier, y_pred_tier, average="macro")
    tier_f1_weighted = f1_score(y_test_tier, y_pred_tier, average="weighted")
    print(f"Accuracy: {tier_acc*100:.2f}% | Macro F1: {tier_f1_macro:.4f} | Weighted F1: {tier_f1_weighted:.4f}")

    joblib.dump(tier_model, "models/remediation_tier_model.joblib")
    metrics_report["remediation_tier"] = {
        "accuracy": float(tier_acc),
        "macro_f1": float(tier_f1_macro),
        "weighted_f1": float(tier_f1_weighted),
        "classes": list(tier_model.classes_),
        "confusion_matrix": confusion_matrix(y_test_tier, y_pred_tier, labels=list(tier_model.classes_)).tolist()
    }

    # =================================================================
    # 7. KEV Real-World Exploitation Risk Classifier
    # =================================================================
    print("\n------------------------------------------------------------------")
    print("4. Training KEV Exploitation Risk Classifier")
    print("------------------------------------------------------------------")
    y_train_kev = train_df["kev_listed"].values
    y_test_kev = test_df["kev_listed"].values

    kev_model = LogisticRegression(
        C=2.0,
        class_weight={0: 1.0, 1: 15.0},
        max_iter=500,
        solver="sag",
        random_state=42
    )
    kev_model.fit(X_train, y_train_kev)
    y_pred_kev_prob = kev_model.predict_proba(X_test)[:, 1]
    y_pred_kev = (y_pred_kev_prob >= 0.40).astype(int)

    kev_roc_auc = roc_auc_score(y_test_kev, y_pred_kev_prob)
    kev_f1 = f1_score(y_test_kev, y_pred_kev, zero_division=0)
    print(f"ROC-AUC: {kev_roc_auc:.4f} | KEV F1: {kev_f1:.4f}")

    joblib.dump(kev_model, "models/kev_risk_model.joblib")
    metrics_report["kev_risk"] = {
        "roc_auc": float(kev_roc_auc),
        "f1_score": float(kev_f1)
    }

    # =================================================================
    # 8. Semantic Mitigation Recommendation Knowledge Base & Index
    # =================================================================
    print("\n------------------------------------------------------------------")
    print("5. Building Semantic Mitigation Recommendation Knowledge Base & Index")
    print("------------------------------------------------------------------")
    mit_df = df[df["mitigation_plan"].str.len() > 15].copy().reset_index(drop=True)
    print(f"[+] Indexing {len(mit_df)} rich, verified mitigation plans...")

    mit_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=20000,
        sublinear_tf=True,
        stop_words="english"
    )
    X_mit_kb = mit_vectorizer.fit_transform(mit_df["full_text"])

    mit_nn = NearestNeighbors(n_neighbors=10, metric="cosine", algorithm="brute")
    mit_nn.fit(X_mit_kb)

    joblib.dump(mit_vectorizer, "models/mitigation_vectorizer.joblib")
    joblib.dump(mit_nn, "models/mitigation_nn_index.joblib")

    lookup_cols = [
        "cve_id", "category", "domain", "cvss_score", "cvss_severity",
        "cwe_id", "kev_listed", "kev_required_action", "epss_score",
        "description", "mitigation_plan", "assigned_tier"
    ]
    mit_df[lookup_cols].to_parquet("models/mitigation_kb.parquet", index=False)
    print("[+] Saved Mitigation KB and Vector Index.")

    # Save metrics summary
    with open("models/metrics_summary.json", "w") as f:
        json.dump(metrics_report, f, indent=2)

    print("\n==================================================================")
    print("  SUCCESS! All 5 CVE AI Models & Vector Index Trained & Saved     ")
    print("==================================================================")

if __name__ == "__main__":
    train_all()

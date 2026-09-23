"""
Unified Single Multi-Target Random Forest Model for CVE Vulnerability Intelligence & Remediation.
All components (text processing, multi-target Random Forest trees, metadata encoders, and mitigation KB)
are encapsulated into a single unified AI model object.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import accuracy_score, f1_score, r2_score, mean_squared_error, mean_absolute_error, roc_auc_score

try:
    from feature_extractor import CVEFeatureExtractor
except ImportError:
    from .feature_extractor import CVEFeatureExtractor

class CVERandomForestModel:
    """
    Unified Single Model Architecture using Random Forest for all CVE intelligence tasks:
    - CVSS Severity Classification (CRITICAL, HIGH, MEDIUM, LOW)
    - CVSS Continuous Score Prediction (0.0 to 10.0)
    - Operational Remediation Tier Assignment (Tier 1, Tier 2, Tier 3)
    - CISA KEV Real-World Threat Prediction
    - Semantic Mitigation Retrieval & Automated Remediation Synthesis
    """
    def __init__(self, n_estimators: int = 160, random_state: int = 42):
        self.random_state = random_state
        self.n_estimators = n_estimators
        
        # 1. Unified Hybrid Feature Extractor (Word n-grams + Char n-grams + Threat Patterns + Priors)
        self.feature_extractor = CVEFeatureExtractor()
        
        # 2. Random Forest Engines with regularized leaves and higher tree count
        self.rf_severity = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=self.random_state,
            n_jobs=-1
        )
        self.rf_score = RandomForestRegressor(
            n_estimators=self.n_estimators,
            max_features="sqrt",
            min_samples_leaf=2,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.rf_tier = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=self.random_state,
            n_jobs=-1
        )
        self.rf_kev = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight={0: 1.0, 1: 15.0},
            random_state=self.random_state,
            n_jobs=-1
        )

        # 3. Mitigation Knowledge Base & Nearest Neighbor Index
        self.mit_nn = NearestNeighbors(n_neighbors=5, metric="cosine", algorithm="brute")
        self.mit_kb = None
        self.metrics = {}

    def _extract_features(self, texts: List[str], epss_scores=None, kev_statuses=None, is_fit: bool = False):
        if is_fit:
            return self.feature_extractor.fit(texts, epss_scores=epss_scores, kev_statuses=kev_statuses).transform(
                texts, epss_scores=epss_scores, kev_statuses=kev_statuses
            )
        else:
            return self.feature_extractor.transform(
                texts, epss_scores=epss_scores, kev_statuses=kev_statuses
            )

    def fit(self, df: pd.DataFrame):
        """Train all Random Forest components in this unified model."""
        print(f"[*] Training Unified Random Forest Model on {len(df)} records...")
        
        # Extract features
        X_train = self._extract_features(
            df["full_text"].tolist(),
            epss_scores=df["epss_score"].values,
            kev_statuses=df["kev_listed"].values,
            is_fit=True
        )

        print("[+] Fitting Random Forest Severity Classifier...")
        self.rf_severity.fit(X_train, df["cvss_severity"].values)

        print("[+] Fitting Random Forest CVSS Score Regressor...")
        self.rf_score.fit(X_train, df["cvss_score"].values)

        print("[+] Fitting Random Forest Remediation Tier Classifier...")
        self.rf_tier.fit(X_train, df["assigned_tier"].values)

        print("[+] Fitting Random Forest KEV Exploitation Risk Classifier...")
        self.rf_kev.fit(X_train, df["kev_listed"].values)

        print("[+] Indexing Mitigation Knowledge Base...")
        mit_df = df[df["mitigation_plan"].str.len() > 15].copy().reset_index(drop=True)
        lookup_cols = [
            "cve_id", "category", "domain", "cvss_score", "cvss_severity",
            "cwe_id", "kev_listed", "epss_score", "description", "mitigation_plan", "assigned_tier"
        ]
        self.mit_kb = mit_df[lookup_cols]
        X_mit = self.feature_extractor.word_tfidf.transform(self.mit_kb["description"].fillna(""))
        self.mit_nn.fit(X_mit)

        print("[+] Random Forest Unified Model successfully trained!")
        return self

    @property
    def tfidf(self):
        """Backwards compatibility for legacy code referencing model.tfidf."""
        return self.feature_extractor.word_tfidf

    def predict_vulnerability(
        self,
        description: str,
        category: str = "General",
        cwe_id: str = "Unknown",
        epss_score: Optional[float] = None,
        kev_listed: Optional[int] = None,
        top_k: int = 3
    ) -> Dict[str, Any]:
        """Generate comprehensive inference using the unified Random Forest model."""
        full_text = f"Category: {category}. CWE: {cwe_id}. Description: {description.strip()}"
        X = self._extract_features(
            [full_text],
            epss_scores=[epss_score if epss_score is not None else 0.05],
            kev_statuses=[kev_listed if kev_listed is not None else 0]
        )

        # 1. Severity
        sev_probs = self.rf_severity.predict_proba(X)[0]
        sev_classes = list(self.rf_severity.classes_)
        pred_sev = self.rf_severity.predict(X)[0]
        sev_conf = float(np.max(sev_probs))
        sev_prob_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(sev_classes, sev_probs)}

        # 2. Score
        pred_score = float(np.clip(self.rf_score.predict(X)[0], 0.0, 10.0))
        pred_score = round(pred_score, 1)

        # 3. Tier
        tier_probs = self.rf_tier.predict_proba(X)[0]
        tier_classes = list(self.rf_tier.classes_)
        pred_tier = self.rf_tier.predict(X)[0]
        tier_conf = float(np.max(tier_probs))
        tier_prob_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(tier_classes, tier_probs)}

        # 4. KEV
        kev_prob = float(self.rf_kev.predict_proba(X)[0][1])
        is_kev = bool(kev_prob >= 0.35 or (kev_listed == 1))

        # 5. Mitigation Nearest Neighbors
        X_desc = self.feature_extractor.word_tfidf.transform([description])
        distances, indices = self.mit_nn.kneighbors(X_desc, n_neighbors=top_k)
        
        similar_cves = []
        for dist, idx in zip(distances[0], indices[0]):
            row = self.mit_kb.iloc[idx]
            sim_pct = round((1.0 - float(dist)) * 100, 1)
            similar_cves.append({
                "cve_id": row["cve_id"],
                "category": row["category"],
                "similarity_score": f"{sim_pct}%",
                "cvss_severity": row["cvss_severity"],
                "cvss_score": row["cvss_score"],
                "cwe_id": row["cwe_id"],
                "description_snippet": row["description"][:180] + "..." if len(str(row["description"])) > 180 else row["description"],
                "mitigation_plan": row["mitigation_plan"]
            })

        primary_mitigation = similar_cves[0]["mitigation_plan"] if similar_cves else "Apply official vendor security patch immediately."

        if pred_sev == "CRITICAL" or is_kev or "Tier 3" in pred_tier:
            urgency = "URGENT (Remediate within 24-48 Hours)"
        elif pred_sev == "HIGH" or "Tier 2" in pred_tier:
            urgency = "ELEVATED (Remediate within 7-14 Days)"
        else:
            urgency = "STANDARD (Include in Routine Maintenance Cycle)"

        return {
            "model_type": "Random Forest Unified Architecture",
            "input": {
                "category": category,
                "cwe_id": cwe_id,
                "description": description,
                "epss_score": epss_score,
                "kev_listed": kev_listed
            },
            "predictions": {
                "cvss_severity": pred_sev,
                "cvss_severity_confidence": round(sev_conf, 4),
                "cvss_severity_probabilities": sev_prob_dict,
                "cvss_score": pred_score,
                "assigned_tier": pred_tier,
                "assigned_tier_confidence": round(tier_conf, 4),
                "assigned_tier_probabilities": tier_prob_dict,
                "kev_exploitation_risk": {
                    "is_active_exploit_threat": is_kev,
                    "exploit_probability": round(kev_prob, 4)
                },
                "action_urgency": urgency
            },
            "recommended_mitigation": {
                "primary_mitigation_plan": primary_mitigation,
                "top_similar_historical_cves": similar_cves
            }
        }

    def save(self, filepath: str = "models/cve_random_forest_model.joblib"):
        """Save the entire unified Random Forest model to a single file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath, compress=3)
        print(f"[+] Saved single Random Forest model bundle to {filepath}")

    @classmethod
    def load(cls, filepath: str = "models/cve_random_forest_model.joblib"):
        """Load the single Random Forest model bundle."""
        return joblib.load(filepath)

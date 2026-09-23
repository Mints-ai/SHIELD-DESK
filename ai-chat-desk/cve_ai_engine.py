"""
CVE AI Engine - Powered by the Unified Single Random Forest Model.
Loads models/cve_random_forest_model.joblib for unified multi-target vulnerability intelligence.
"""

import os
import json
import joblib
import pandas as pd
from typing import Dict, Any, Optional
from cve_random_forest import CVERandomForestModel

class CVEAIEngine:
    def __init__(self, model_path: str = "models/cve_random_forest_model.joblib"):
        self.model_path = model_path
        self._load_model()

    def _load_model(self):
        """Load the single unified Random Forest model bundle."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file {self.model_path} not found. Run train_rf_model.py first.")
        
        self.rf_model = CVERandomForestModel.load(self.model_path)
        self.mit_kb = self.rf_model.mit_kb
        self.metrics = self.rf_model.metrics

    def analyze_vulnerability(
        self,
        description: str,
        category: str = "General",
        cwe_id: str = "Unknown",
        epss_score: Optional[float] = None,
        kev_listed: Optional[int] = None,
        top_k_similar: int = 3
    ) -> Dict[str, Any]:
        """Perform unified multi-target prediction and mitigation synthesis using the Random Forest model."""
        return self.rf_model.predict_vulnerability(
            description=description,
            category=category,
            cwe_id=cwe_id,
            epss_score=epss_score,
            kev_listed=kev_listed,
            top_k=top_k_similar
        )

    def search_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Lookup an exact CVE in the indexed knowledge base."""
        cve_id_clean = cve_id.strip().upper()
        matches = self.mit_kb[self.mit_kb["cve_id"].str.upper() == cve_id_clean]
        if len(matches) == 0:
            return None
        row = matches.iloc[0].to_dict()
        return row

if __name__ == "__main__":
    engine = CVEAIEngine()
    test_desc = "Buffer overflow in OpenSSL TLS handshake allows remote unauthenticated attackers to execute arbitrary code."
    result = engine.analyze_vulnerability(test_desc, category="Linux / OpenSSL", cwe_id="CWE-120")
    print("\n--- Test Single Random Forest Model Prediction ---")
    print(json.dumps(result, indent=2))

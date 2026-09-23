# Vulnerability Intelligence & AI Mitigation Engine (Port 8000)

> **A production-grade, local machine-learning microservice for real-time CVE severity prediction, CVSS scoring, CISA KEV exploit threat estimation, operational remediation tier assignment, and automated mitigation synthesis.**

Integrated directly with the **ShieldDesk Autonomous SOC Platform** as its primary vulnerability intelligence engine (Phase 5 / Layer 5).

---

## 🌟 Key Features & Benchmark Performance

- **Single Unified Random Forest Architecture (`CVERandomForestModel`)**:
  - **CISA KEV Real-World Threat Discrimination**: **`0.9801 ROC-AUC`** (98% true-positive / false-positive exploit discrimination).
  - **Operational Remediation Tier Classification**: **`90.79% Accuracy`** (Weighted F1: **`0.8957`**) classifying actions into Tier 1 (Autonomous), Tier 2 (Human-Approved), and Tier 3 (Dual-Sign-Off).
  - **CVSS Continuous Score Regressor**: Continuous numerical prediction from $0.0 - 10.0$ with Mean Absolute Error of **`0.606`** points ($R^2 = 0.5072$, RMSE: 0.947).
  - **CVSS Severity Classification**: Classifies vulnerabilities into `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` (**83.4% Accuracy**, 0.825 Weighted F1).
  - **Semantic Mitigation Recommender**: K-Nearest Neighbors vector index over 12,968 historical vulnerability playbooks for instant remediation synthesis.

- **Hybrid High-Accuracy Feature Extractor (`CVEFeatureExtractor`)**:
  - **Sublinear Word n-grams (`ngram_range=(1, 2)`)**: 12,000 features capturing domain vocabulary.
  - **Sublinear Character n-grams (`ngram_range=(3, 5)`)**: 8,000 character features capturing software library names, acronyms, and version patterns.
  - **Deterministic Threat Regex Signals**: Extracted 10 high-value cybersecurity indicators:
    1. Remote Code Execution (RCE)
    2. Privilege Escalation (PrivEsc)
    3. Authentication Bypass & Unauthenticated Access
    4. Memory Corruption, Buffer & Heap Overflow
    5. Denial of Service (DoS) & Resource Exhaustion
    6. SQL Injection (SQLi)
    7. Cross-Site Scripting (XSS)
    8. Server-Side Request Forgery (SSRF)
    9. In-The-Wild Zero-Day Exploitation
    10. Untrusted Network & Remote Vectors
  - **Intelligence Priors**: Directly fuses CISA KEV presence, EPSS probability scores, and log-transformed text length.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Local Server & REST API
```bash
python server.py
```
*Vulnerability Engine runs at: **`http://localhost:8000`***

---

## 📡 REST API Reference

### 1. Predict Vulnerability from Free Text (`POST /api/predict`)
Analyzes raw unformatted vulnerability descriptions, software stack metadata, and priors:

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Remote code execution vulnerability allows unauthenticated attackers to execute arbitrary code via buffer overflow",
    "category": "Operating System",
    "epss_score": 0.85,
    "kev_listed": 1
  }'
```

#### Sample Response:
```json
{
  "model_type": "Random Forest Unified Architecture",
  "predictions": {
    "cvss_severity": "HIGH",
    "cvss_severity_confidence": 0.5308,
    "cvss_score": 8.4,
    "assigned_tier": "Tier 2 (Medium-Risk / Human-Approved)",
    "assigned_tier_confidence": 0.7144,
    "kev_exploitation_risk": {
      "is_active_exploit_threat": true,
      "exploit_probability": 0.1231
    },
    "action_urgency": "URGENT (Remediate within 24-48 Hours)"
  },
  "recommended_mitigation": {
    "primary_mitigation_plan": "Patch the affected product promptly and limit external/untrusted network access...",
    "top_similar_historical_cves": [
      {
        "cve_id": "CVE-2023-54330",
        "similarity_score": "49.4%",
        "cvss_severity": "CRITICAL",
        "cvss_score": 9.3
      }
    ]
  }
}
```

### 2. Exact Knowledge Base Lookup (`GET /api/lookup?cve=CVE-XXXX-XXXXX`)
Queries the 12,968 historical CVE dataset:

```bash
curl "http://localhost:8000/api/lookup?cve=CVE-2020-6240"
```

---

## 💻 CLI & Model Retraining

### 1. Analyze via Command Line
```bash
python predict.py --text "Remote buffer overflow in web service" --category "Linux"
```

### 2. Retrain the Single Unified Random Forest Model
To fit the model on the full harmonized dataset:
```bash
python train_rf_model.py
```
This re-fits all 4 Random Forest targets with 160 estimators, evaluates test set performance, and writes the updated bundle to `models/cve_random_forest_model.joblib`.

---

## 🧠 Python Class Integration

```python
from cve_ai_engine import CVEAIEngine

engine = CVEAIEngine()
result = engine.analyze_vulnerability(
    description="Buffer overflow in OpenSSL TLS handshake allows remote arbitrary code execution.",
    category="Linux / OpenSSL",
    cwe_id="CWE-120",
    epss_score=0.92,
    kev_listed=1
)

print("CVSS Severity:", result["predictions"]["cvss_severity"])
print("CVSS Score:", result["predictions"]["cvss_score"])
print("Remediation Tier:", result["predictions"]["assigned_tier"])
print("Primary Mitigation:", result["recommended_mitigation"]["primary_mitigation_plan"])
```

---

## 📊 Repository Structure

```
├── data/
│   └── harmonized_cve.parquet           # 12,968 harmonized vulnerability records
├── models/
│   ├── cve_random_forest_model.joblib   # Persisted single unified model bundle
│   └── evaluation_report.json           # Comprehensive evaluation benchmark
├── static/                              # Dashboard UI (HTML, CSS, JS) on port 8000
├── feature_extractor.py                 # Hybrid word/char n-grams & threat regex module
├── cve_random_forest.py                 # Unified Multi-Target Random Forest architecture
├── cve_ai_engine.py                     # Production inference engine class
├── train_rf_model.py                    # Model training and cross-validation script
├── server.py                            # FastAPI REST API server
└── requirements.txt                     # Dependencies
```

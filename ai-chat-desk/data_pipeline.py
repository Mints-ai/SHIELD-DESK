"""
CVE Data Ingestion, Harmonization, and Feature Engineering Pipeline.
Merges and cleans datasets from /cve folder:
- ShieldDesk_OS_CVE_MitigationPlans_FIXED_v4_Accurate_Tiers.xlsx
- ERP_CVE.xlsx
- Shield_Desk_Defender_CVE_1_.xlsx
- SAP_CVE_Formatted.xlsx
"""

import os
import re
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any

def normalize_text(text: Any) -> str:
    """Clean and normalize raw text."""
    if pd.isna(text) or text is None:
        return ""
    text = str(text).strip()
    text = re.sub(r'\s+', ' ', text)
    return text

def normalize_severity(sev: Any) -> str:
    """Standardize CVSS severity string to CRITICAL, HIGH, MEDIUM, LOW."""
    if pd.isna(sev) or not sev:
        return "UNKNOWN"
    s = str(sev).strip().upper()
    if "CRIT" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MED" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return "UNKNOWN"

def normalize_tier(tier: Any) -> str:
    """Standardize remediation tier string."""
    if pd.isna(tier) or not tier:
        return "Tier 2 (Medium-Risk / Human-Approved)"
    s = str(tier).strip()
    if "Tier 3" in s or "Dual-Sign-Off" in s or "High-Risk" in s:
        return "Tier 3 (High-Risk / Dual-Sign-Off)"
    if "Tier 1" in s or "Autonomous" in s or "Low-Risk" in s:
        return "Tier 1 (Low-Risk / Autonomous)"
    return "Tier 2 (Medium-Risk / Human-Approved)"

def normalize_kev(kev: Any) -> int:
    """Standardize KEV listed status to 0 or 1."""
    if pd.isna(kev):
        return 0
    s = str(kev).strip().lower()
    if s in ['true', '1', 'yes', 'y']:
        return 1
    return 0

def load_and_harmonize_cve_data(cve_dir: str = "cve") -> pd.DataFrame:
    """Load all Excel files from the cve folder and harmonize into a single clean DataFrame."""
    records = []
    
    # 1. OS CVEs (v4 with accurate tiers)
    os_v4_path = os.path.join(cve_dir, "ShieldDesk_OS_CVE_MitigationPlans_FIXED_v4_Accurate_Tiers.xlsx")
    if os.path.exists(os_v4_path):
        print(f"Loading {os_v4_path}...")
        df_os = pd.read_excel(os_v4_path, sheet_name="Master_All_OS")
        for _, row in df_os.iterrows():
            records.append({
                "cve_id": normalize_text(row.get("CVE_ID")),
                "category": normalize_text(row.get("OS_Category")),
                "domain": "Operating System",
                "cvss_score": pd.to_numeric(row.get("CVSS_Score"), errors="coerce"),
                "cvss_severity": normalize_severity(row.get("CVSS_Severity")),
                "cwe_id": normalize_text(row.get("CWE_ID")),
                "kev_listed": normalize_kev(row.get("KEV_Listed")),
                "kev_required_action": normalize_text(row.get("KEV_Required_Action")),
                "epss_score": pd.to_numeric(row.get("EPSS_Score"), errors="coerce"),
                "description": normalize_text(row.get("Description")),
                "mitigation_plan": normalize_text(row.get("Mitigation")),
                "assigned_tier": normalize_tier(row.get("Assigned_Tier")),
                "source_file": "OS_CVE_v4"
            })
    
    # 2. ERP CVEs
    erp_path = os.path.join(cve_dir, "ERP_CVE.xlsx")
    if os.path.exists(erp_path):
        print(f"Loading {erp_path}...")
        df_erp = pd.read_excel(erp_path, sheet_name="All CVEs")
        for _, row in df_erp.iterrows():
            records.append({
                "cve_id": normalize_text(row.get("CVE ID")),
                "category": normalize_text(row.get("ERP CATEGORY")),
                "domain": "Enterprise ERP",
                "cvss_score": pd.to_numeric(row.get("CVSS SCORE"), errors="coerce"),
                "cvss_severity": normalize_severity(row.get("CVSS SEVERITY")),
                "cwe_id": normalize_text(row.get("CWE ID")),
                "kev_listed": normalize_kev(row.get("KEV LISTED")),
                "kev_required_action": normalize_text(row.get("KEV REQUIRED")),
                "epss_score": pd.to_numeric(row.get("EPSS SCORE"), errors="coerce"),
                "description": normalize_text(row.get("DESCRIPTION")),
                "mitigation_plan": normalize_text(row.get("MITIGATION PLAN")),
                "assigned_tier": normalize_tier(row.get("TIER")),
                "source_file": "ERP_CVE"
            })
            
    # 3. Defender CVEs
    def_path = os.path.join(cve_dir, "Shield_Desk_Defender_CVE_1_.xlsx")
    if os.path.exists(def_path):
        print(f"Loading {def_path}...")
        df_def = pd.read_excel(def_path, sheet_name="Defender CVE Final")
        for _, row in df_def.iterrows():
            records.append({
                "cve_id": normalize_text(row.get("Cve_id")),
                "category": normalize_text(row.get("Defender_category")),
                "domain": "Endpoint Defender",
                "cvss_score": pd.to_numeric(row.get("Cvss_score"), errors="coerce"),
                "cvss_severity": normalize_severity(row.get("Cvss_severity")),
                "cwe_id": normalize_text(row.get("Cwe_id")),
                "kev_listed": normalize_kev(row.get("Kev_listed")),
                "kev_required_action": normalize_text(row.get("Kev_required")),
                "epss_score": pd.to_numeric(row.get("Epss_score"), errors="coerce"),
                "description": normalize_text(row.get("Description")),
                "mitigation_plan": normalize_text(row.get("Mitigation plan")),
                "assigned_tier": normalize_tier(row.get("Assigned_Tier")),
                "source_file": "Defender_CVE"
            })
            
    # 4. SAP CVEs (add any missing or complementary notes)
    sap_path = os.path.join(cve_dir, "SAP_CVE_Formatted.xlsx")
    if os.path.exists(sap_path):
        print(f"Loading {sap_path}...")
        df_sap = pd.read_excel(sap_path, sheet_name="CVE_Data")
        for _, row in df_sap.iterrows():
            records.append({
                "cve_id": normalize_text(row.get("CVE_ID")),
                "category": normalize_text(row.get("ERP Category")),
                "domain": "SAP Enterprise",
                "cvss_score": pd.to_numeric(row.get("CVSS_Score"), errors="coerce"),
                "cvss_severity": normalize_severity(row.get("CVSS_Severity")),
                "cwe_id": normalize_text(row.get("CWE_ID")),
                "kev_listed": normalize_kev(row.get("KEV_Listed")),
                "kev_required_action": normalize_text(row.get("KEV_Required")),
                "epss_score": pd.to_numeric(row.get("EPSS_Score"), errors="coerce"),
                "description": normalize_text(row.get("Description")),
                "mitigation_plan": normalize_text(row.get("Mitigation_Plan")),
                "assigned_tier": None, # Will be imputed or resolved
                "source_file": "SAP_CVE"
            })
            
    df = pd.DataFrame(records)
    print(f"Raw merged records: {len(df)}")
    
    # Filter out empty descriptions
    df = df[df["description"].str.len() > 10].copy()
    
    # Deduplicate by CVE_ID if present, prioritizing rows with mitigation plans and assigned tiers
    df["has_tier"] = df["assigned_tier"].notna() & (df["assigned_tier"] != "")
    df["has_mitigation"] = df["mitigation_plan"].str.len() > 10
    
    df = df.sort_values(by=["has_tier", "has_mitigation", "epss_score"], ascending=False)
    df = df.drop_duplicates(subset=["cve_id", "description"], keep="first")
    
    # Impute missing assigned_tier based on CVSS score and KEV if missing
    def infer_tier(row):
        if pd.notna(row["assigned_tier"]) and row["assigned_tier"] != "":
            return row["assigned_tier"]
        score = row["cvss_score"]
        kev = row["kev_listed"]
        epss = row["epss_score"]
        if (pd.notna(score) and score >= 9.0) or kev == 1 or (pd.notna(epss) and epss >= 0.8):
            return "Tier 3 (High-Risk / Dual-Sign-Off)"
        elif pd.notna(score) and score < 4.0 and kev == 0:
            return "Tier 1 (Low-Risk / Autonomous)"
        else:
            return "Tier 2 (Medium-Risk / Human-Approved)"
            
    df["assigned_tier"] = df.apply(infer_tier, axis=1)
    
    # Impute missing CVSS score from severity or mean if missing
    sev_to_score = {"CRITICAL": 9.5, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 2.5}
    for sev, default_s in sev_to_score.items():
        mask = df["cvss_score"].isna() & (df["cvss_severity"] == sev)
        df.loc[mask, "cvss_score"] = default_s
    df["cvss_score"] = df["cvss_score"].fillna(6.0)
    
    # Impute missing severity from score
    def score_to_sev(s):
        if s >= 9.0:
            return "CRITICAL"
        if s >= 7.0:
            return "HIGH"
        if s >= 4.0:
            return "MEDIUM"
        return "LOW"
        
    mask_unknown_sev = df["cvss_severity"] == "UNKNOWN"
    df.loc[mask_unknown_sev, "cvss_severity"] = df.loc[mask_unknown_sev, "cvss_score"].apply(score_to_sev)
    
    # Fill missing EPSS with median
    df["epss_score"] = df["epss_score"].fillna(df["epss_score"].median())
    
    # Create combined text representation for NLP models
    df["full_text"] = (
        "Category: " + df["category"].fillna("General") + ". " +
        "CWE: " + df["cwe_id"].fillna("Unknown") + ". " +
        "Description: " + df["description"].fillna("")
    )
    
    print(f"Final cleaned and harmonized CVE dataset shape: {df.shape}")
    print(f"Severity distribution:\n{df['cvss_severity'].value_counts()}")
    print(f"Tier distribution:\n{df['assigned_tier'].value_counts()}")
    print(f"KEV distribution:\n{df['kev_listed'].value_counts()}")
    
    return df

if __name__ == "__main__":
    df = load_and_harmonize_cve_data()
    os.makedirs("data", exist_ok=True)
    df.to_parquet("data/harmonized_cve.parquet", index=False)
    print("Saved harmonized dataset to data/harmonized_cve.parquet")

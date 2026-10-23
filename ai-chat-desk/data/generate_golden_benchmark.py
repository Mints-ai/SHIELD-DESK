"""
Curates the immutable Golden Safety Benchmark for CVE Model Evaluation.

Extracts 250 high-stakes, edge-case, and active zero-day vulnerabilities:
- Critical KEV-listed weaponized exploits (Log4Shell, MOVEit, EternalBlue, PAN-OS)
- High-severity memory corruption and RCE flaws
- Borderline CVSS scores (6.8-7.2, 8.8-9.2)
- Reversible Low-severity flaws (Tier 1 valid baselines)
"""

import os
import pandas as pd
import numpy as np

def generate_golden_benchmark(
    source_parquet: str = "data/cve_lookup_store.parquet",
    output_parquet: str = "data/golden_safety_benchmark.parquet",
    target_count: int = 250,
    random_state: int = 42
):
    if not os.path.exists(source_parquet):
        source_parquet = "data/harmonized_cve.parquet"

    df = pd.read_parquet(source_parquet)
    print(f"[+] Loaded {len(df)} total records from {source_parquet}")

    # 1. Mandatory high-profile zero-days & KEV exploits
    kev_df = df[df["kev_listed"] == 1].copy()
    if len(kev_df) > 100:
        kev_sample = kev_df.sample(n=100, random_state=random_state)
    else:
        kev_sample = kev_df

    # 2. Critical CVSS (9.0+)
    crit_df = df[(df["cvss_score"] >= 9.0) & (df["kev_listed"] == 0)].copy()
    crit_sample = crit_df.sample(n=min(50, len(crit_df)), random_state=random_state)

    # 3. High CVSS (7.0 - 8.9) with RCE or PrivEsc indicators
    rce_mask = df["description"].str.contains(r"remote code|arbitrary code|privilege escalation", case=False, na=False)
    high_rce_df = df[rce_mask & (df["cvss_score"] >= 7.0) & (df["cvss_score"] < 9.0)].copy()
    high_sample = high_rce_df.sample(n=min(50, len(high_rce_df)), random_state=random_state)

    # 4. Low-Severity Tier 1 baselines (CVSS < 4.5, non-KEV)
    low_df = df[(df["cvss_score"] < 4.5) & (df["kev_listed"] == 0) & (~rce_mask)].copy()
    low_sample = low_df.sample(n=min(50, len(low_df)), random_state=random_state)

    # Combine and ensure uniqueness
    combined_df = pd.concat([kev_sample, crit_sample, high_sample, low_sample]).drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
    
    # If still below target_count, sample remaining
    if len(combined_df) < target_count:
        remaining = df[~df["cve_id"].isin(combined_df["cve_id"])]
        fill_count = min(target_count - len(combined_df), len(remaining))
        combined_df = pd.concat([combined_df, remaining.sample(n=fill_count, random_state=random_state)]).reset_index(drop=True)

    # Prepare full_text column if not present
    if "full_text" not in combined_df.columns:
        combined_df["full_text"] = (
            "Category: " + combined_df["category"].fillna("General") +
            ". CWE: " + combined_df["cwe_id"].fillna("Unknown") +
            ". Description: " + combined_df["description"].fillna("")
        )

    # Save to parquet
    os.makedirs(os.path.dirname(output_parquet), exist_ok=True)
    combined_df.to_parquet(output_parquet, index=False)
    print(f"[+] Successfully wrote {len(combined_df)} curated records to {output_parquet}")
    print(f"    - KEV Exploit Cases: {len(combined_df[combined_df['kev_listed'] == 1])}")
    print(f"    - Critical CVSS (9.0+): {len(combined_df[combined_df['cvss_score'] >= 9.0])}")
    print(f"    - Low CVSS (< 4.5): {len(combined_df[combined_df['cvss_score'] < 4.5])}")
    return len(combined_df)

if __name__ == "__main__":
    generate_golden_benchmark()

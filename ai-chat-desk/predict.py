"""
Command-line Interface for CVE AI Model Predictions.
Usage:
    python predict.py --text "Remote code execution vulnerability in Linux Kernel netfilter module"
    python predict.py --cve CVE-2022-0543
    python predict.py --text "SQL injection in ERP login portal" --category "Enterprise ERP" --cwe CWE-89
"""

import argparse
import json
import sys
from cve_ai_engine import CVEAIEngine

def main():
    parser = argparse.ArgumentParser(description="CVE AI Intelligence & Mitigation Prediction Tool")
    parser.add_argument("--text", type=str, help="Vulnerability description text")
    parser.add_argument("--cve", type=str, help="Lookup known CVE ID in knowledge base (e.g. CVE-2022-0543)")
    parser.add_argument("--category", type=str, default="General", help="System / OS / ERP Category (e.g. Linux, Windows, SAP, Oracle)")
    parser.add_argument("--cwe", type=str, default="Unknown", help="CWE identifier (e.g. CWE-78, CWE-89, CWE-120)")
    parser.add_argument("--epss", type=float, default=None, help="EPSS score (0.0 to 1.0)")
    parser.add_argument("--kev", type=int, default=None, help="KEV listed status (1 or 0)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    args = parser.parse_args()

    engine = CVEAIEngine()

    if args.cve:
        print(f"\n[+] Looking up CVE: {args.cve.upper()} in Knowledge Base...")
        record = engine.search_cve_by_id(args.cve)
        if not record:
            print(f"[-] CVE {args.cve} not found in historical database. Analyzing description...")
        else:
            if args.json:
                print(json.dumps(record, indent=2))
                return
            print("\n" + "="*70)
            print(f" CVE RECORD: {record['cve_id']}")
            print("="*70)
            print(f" Category:       {record.get('category')}")
            print(f" CVSS Severity:  {record.get('cvss_severity')} (Score: {record.get('cvss_score')})")
            print(f" CWE ID:         {record.get('cwe_id')}")
            print(f" KEV Status:     {'YES (Active Exploit)' if record.get('kev_listed') == 1 else 'No'}")
            print(f" Assigned Tier:  {record.get('assigned_tier')}")
            print(f"\n Description:\n {record.get('description')}")
            print(f"\n Mitigation Plan:\n {record.get('mitigation_plan')}")
            print("="*70)
            return

    if not args.text:
        print("Error: Please provide --text <vulnerability description> or --cve <CVE-ID>")
        sys.exit(1)

    result = engine.analyze_vulnerability(
        description=args.text,
        category=args.category,
        cwe_id=args.cwe,
        epss_score=args.epss,
        kev_listed=args.kev
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    pred = result["predictions"]
    mit = result["recommended_mitigation"]

    print("\n" + "="*70)
    print("                    CVE AI PREDICTION REPORT                    ")
    print("="*70)
    print(f" Input Category:       {args.category}")
    print(f" Input CWE:            {args.cwe}")
    print(f" Predicted Severity:   {pred['cvss_severity']} (Confidence: {pred['cvss_severity_confidence']*100:.1f}%)")
    print(f" Predicted CVSS Score: {pred['cvss_score']} / 10.0")
    print(f" Operational Tier:     {pred['assigned_tier']} (Confidence: {pred['assigned_tier_confidence']*100:.1f}%)")
    print(f" KEV Exploit Threat:   {'ALERT: Active Exploit Likely' if pred['kev_exploitation_risk']['is_active_exploit_threat'] else 'Low Exploit Probability'} ({pred['kev_exploitation_risk']['exploit_probability']*100:.1f}%)")
    print(f" Action Urgency:       {pred['action_urgency']}")
    print("\n" + "-"*70)
    print(" RECOMMENDED PRIMARY MITIGATION PLAN:")
    print("-" * 70)
    print(mit['primary_mitigation_plan'])
    print("\n" + "-"*70)
    print(" TOP MATCHING HISTORICAL CVEs:")
    print("-" * 70)
    for i, item in enumerate(mit["top_similar_historical_cves"], 1):
        print(f" [{i}] {item['cve_id']} ({item['category']}) - Similarity: {item['similarity_score']} | CVSS: {item['cvss_score']} ({item['cvss_severity']})")
        print(f"     Mitigation: {item['mitigation_plan']}")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()

"""
Unit tests for ShieldDesk Remediation Safety Policy Guard using real CVE vulnerability cases.
"""

import unittest
from safety_policy import (
    evaluate_remediation_safety_guard,
    TIER_1_AUTONOMOUS,
    TIER_2_HUMAN_APPROVED,
    TIER_3_DUAL_SIGNOFF,
)

class TestSafetyPolicyGuardRealCases(unittest.TestCase):

    def test_invariant_1_cisa_kev_blocks_tier_1_cve_2023_38606(self):
        """Active CISA KEV flaw (Apple iOS WebKit / Kernel Exploit CVE-2023-38606) must never execute autonomously."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "cvss_score": 7.8,
            "cvss_severity": "HIGH",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": True,
                "exploit_probability": 0.89
            }
        }
        real_desc = (
            "An app may be able to modify sensitive kernel state. Apple is aware of a report "
            "that this issue may have been actively exploited against versions of iOS released before iOS 15.7.1."
        )
        res = evaluate_remediation_safety_guard(raw_pred, description=real_desc)
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_2_critical_cvss_blocks_tier_1_cve_2021_44228(self):
        """Critical CVSS 10.0 flaw (Apache Log4j2 JNDI Log4Shell CVE-2021-44228) must never execute autonomously."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.90,
            "cvss_score": 10.0,
            "cvss_severity": "CRITICAL",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": True,
                "exploit_probability": 0.99
            }
        }
        real_desc = (
            "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control "
            "log messages or log message parameters can execute arbitrary code loaded from LDAP servers."
        )
        res = evaluate_remediation_safety_guard(raw_pred, description=real_desc)
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_3_rce_blocks_tier_1_cve_2024_3400(self):
        """Palo Alto Networks PAN-OS GlobalProtect unauthenticated root command injection (CVE-2024-3400)."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.88,
            "cvss_score": 10.0,
            "cvss_severity": "CRITICAL",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": True,
                "exploit_probability": 0.94
            }
        }
        real_desc = (
            "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software "
            "for specific PAN-OS versions enables an unauthenticated attacker to execute arbitrary code with root "
            "privileges on the firewall."
        )
        res = evaluate_remediation_safety_guard(raw_pred, description=real_desc)
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_4_low_confidence_fails_closed(self):
        """Ambiguous vulnerability report with low model confidence (< 0.65) must fail closed to Tier 2."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.42,
            "cvss_score": 4.1,
            "cvss_severity": "MEDIUM",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.02
            }
        }
        real_desc = "OpenSSL documentation errata in configuration directives regarding cipher suite ordering."
        res = evaluate_remediation_safety_guard(raw_pred, description=real_desc)
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)

    def test_invariant_5_critical_asset_escalates_to_tier_3(self):
        """Weaponized flaw (MOVEit Transfer CVE-2023-34362) on critical infrastructure escalates to Tier 3 Dual-Sign-Off."""
        raw_pred = {
            "assigned_tier": TIER_2_HUMAN_APPROVED,
            "assigned_tier_confidence": 0.85,
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": True,
                "exploit_probability": 0.98
            }
        }
        real_desc = (
            "In Progress MOVEit Transfer before 2021.0.6, a SQL injection vulnerability has been found in the "
            "MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized "
            "access to MOVEit Transfer's database."
        )
        res = evaluate_remediation_safety_guard(
            raw_pred,
            description=real_desc,
            context={"asset_criticality": "critical", "blast_radius_exceeded": False}
        )
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_3_DUAL_SIGNOFF)
        self.assertEqual(res["required_approvals"], 2)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_safe_low_severity_cve_permitted_in_tier_1(self):
        """Real low-risk flaw: OpenSSL CA certificate policy check flag (CVE-2021-3450, non-KEV, low-risk)."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.92,
            "cvss_score": 3.7,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.01
            }
        }
        real_desc = (
            "OpenSSL certificate verification flag X509_V_FLAG_X509_STRICT parameter handling "
            "can result in non-security relevant CA verification omissions under specific non-default configurations."
        )
        res = evaluate_remediation_safety_guard(
            raw_pred,
            description=real_desc,
            context={"asset_criticality": "low"}
        )
        self.assertFalse(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_1_AUTONOMOUS)
        self.assertEqual(res["required_approvals"], 0)
        self.assertTrue(res["is_autonomous_execution_allowed"])

if __name__ == "__main__":
    unittest.main()

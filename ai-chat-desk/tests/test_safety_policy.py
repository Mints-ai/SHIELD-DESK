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

    def test_unknown_or_invalid_tier_fails_closed_never_autonomous(self):
        """Unknown or invalid tiers must never fall through to autonomous execution."""
        bad_tiers = ["Tier 99 (Experimental)", "autonomous_now", "", None, 12345, "TIER_1"]
        for bad_tier in bad_tiers:
            raw_pred = {
                "assigned_tier": bad_tier,
                "assigned_tier_confidence": 0.99,
                "cvss_score": 2.0,
                "cvss_severity": "LOW",
                "kev_exploitation_risk": {
                    "is_active_exploit_threat": False,
                    "exploit_probability": 0.01
                }
            }
            res = evaluate_remediation_safety_guard(raw_pred, description="Benign informational typo")
            self.assertEqual(
                res["effective_assigned_tier"],
                TIER_2_HUMAN_APPROVED,
                f"Bad tier {bad_tier} must fail closed to Tier 2"
            )
            self.assertFalse(
                res["is_autonomous_execution_allowed"],
                f"Bad tier {bad_tier} must never allow autonomous execution"
            )
            self.assertEqual(res["required_approvals"], 1)
            self.assertTrue(res["policy_override_applied"])

    def test_high_severity_independently_blocks_tier_1(self):
        """High severity vulnerabilities (CVSS >= 7.0 or HIGH) must independently block Tier 1 autonomous execution."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.05
            }
        }
        res = evaluate_remediation_safety_guard(raw_pred, description="Standard denial of service via memory exhaustion")
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res["is_autonomous_execution_allowed"])
        self.assertEqual(res["required_approvals"], 1)

    def test_boundary_cvss_scores(self):
        """CVSS 7.0 boundary strictly blocks Tier 1; CVSS 6.9 MEDIUM allows Tier 1."""
        base_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.05
            }
        }
        # CVSS 7.0 -> Blocked
        pred_70 = {**base_pred, "cvss_score": 7.0, "cvss_severity": "HIGH"}
        res_70 = evaluate_remediation_safety_guard(pred_70, description="Network stack crash")
        self.assertEqual(res_70["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res_70["is_autonomous_execution_allowed"])

        # CVSS 6.9 -> Permitted (with MEDIUM severity)
        pred_69 = {**base_pred, "cvss_score": 6.9, "cvss_severity": "MEDIUM"}
        res_69 = evaluate_remediation_safety_guard(pred_69, description="Informational leak in banner")
        self.assertEqual(res_69["effective_assigned_tier"], TIER_1_AUTONOMOUS)
        self.assertTrue(res_69["is_autonomous_execution_allowed"])

    def test_missing_and_malformed_metadata_fails_closed(self):
        """Missing or malformed CVSS, severity, exploit probability, and confidence fail closed."""
        cases = [
            # Missing cvss_score
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Malformed negative cvss_score
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": -1.0, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Malformed excessive cvss_score
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 15.5, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Non-numeric cvss_score string
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": "NaN_bad", "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Missing cvss_severity
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Unrecognized severity string
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "cvss_severity": "BOGUS_SEVERITY", "kev_exploitation_risk": {"exploit_probability": 0.01}},
            # Missing kev_exploitation_risk
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "cvss_severity": "LOW"},
            # Malformed exploit_probability > 1.0
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 5.0}},
            # Non-numeric exploit_probability
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": "high"}},
            # Missing assigned_tier_confidence
            {"assigned_tier": TIER_1_AUTONOMOUS, "cvss_score": 2.0, "cvss_severity": "LOW", "kev_exploitation_risk": {"exploit_probability": 0.01}},
        ]
        for idx, case in enumerate(cases):
            res = evaluate_remediation_safety_guard(case, description="Test vulnerability description")
            self.assertEqual(
                res["effective_assigned_tier"],
                TIER_2_HUMAN_APPROVED,
                f"Case #{idx} must fail closed to Tier 2: {case}"
            )
            self.assertFalse(res["is_autonomous_execution_allowed"])
            self.assertTrue(res["policy_override_applied"])

    def test_conflicting_severity_and_score_fails_closed(self):
        """Conflicting CVSS score and severity ratings must fail closed."""
        # High score with Low severity
        conflict_1 = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "cvss_score": 9.5,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {"is_active_exploit_threat": False, "exploit_probability": 0.01}
        }
        res_1 = evaluate_remediation_safety_guard(conflict_1)
        self.assertEqual(res_1["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res_1["is_autonomous_execution_allowed"])
        self.assertTrue(any("Conflicting" in r for r in res_1["policy_override_reasons"]))

        # Low score with Critical severity
        conflict_2 = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "cvss_score": 2.0,
            "cvss_severity": "CRITICAL",
            "kev_exploitation_risk": {"is_active_exploit_threat": False, "exploit_probability": 0.01}
        }
        res_2 = evaluate_remediation_safety_guard(conflict_2)
        self.assertEqual(res_2["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res_2["is_autonomous_execution_allowed"])
        self.assertTrue(any("Conflicting" in r for r in res_2["policy_override_reasons"]))

    def test_boundary_confidence_and_exploit_prob(self):
        """Test exact confidence boundary 0.65 and exploit probability boundary 0.35."""
        # Confidence 0.64 -> Blocks Tier 1
        res_conf_low = evaluate_remediation_safety_guard({
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.64,
            "cvss_score": 3.0,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {"is_active_exploit_threat": False, "exploit_probability": 0.01}
        })
        self.assertEqual(res_conf_low["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res_conf_low["is_autonomous_execution_allowed"])

        # Confidence 0.65 -> Allows Tier 1
        res_conf_ok = evaluate_remediation_safety_guard({
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.65,
            "cvss_score": 3.0,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {"is_active_exploit_threat": False, "exploit_probability": 0.01}
        })
        self.assertEqual(res_conf_ok["effective_assigned_tier"], TIER_1_AUTONOMOUS)
        self.assertTrue(res_conf_ok["is_autonomous_execution_allowed"])

        # Exploit probability 0.35 -> Blocks Tier 1
        res_prob_high = evaluate_remediation_safety_guard({
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.90,
            "cvss_score": 3.0,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {"is_active_exploit_threat": False, "exploit_probability": 0.35}
        })
        self.assertEqual(res_prob_high["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res_prob_high["is_autonomous_execution_allowed"])

    def test_non_dict_predictions_payload(self):
        """Non-dict predictions payload fails closed to Tier 2."""
        for non_dict in [None, "invalid_payload", [1, 2, 3], 42]:
            res = evaluate_remediation_safety_guard(non_dict)  # type: ignore
            self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
            self.assertFalse(res["is_autonomous_execution_allowed"])
            self.assertEqual(res["required_approvals"], 1)

if __name__ == "__main__":
    unittest.main()


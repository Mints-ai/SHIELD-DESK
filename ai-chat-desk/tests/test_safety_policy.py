"""
Unit tests for ShieldDesk Remediation Safety Policy Guard.
"""

import unittest
from safety_policy import (
    evaluate_remediation_safety_guard,
    TIER_1_AUTONOMOUS,
    TIER_2_HUMAN_APPROVED,
    TIER_3_DUAL_SIGNOFF,
)

class TestSafetyPolicyGuard(unittest.TestCase):

    def test_invariant_1_kev_exploitation_blocks_tier_1(self):
        """Active CISA KEV exploitation must never execute autonomously."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.95,
            "cvss_score": 5.0,
            "cvss_severity": "MEDIUM",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": True,
                "exploit_probability": 0.85
            }
        }
        res = evaluate_remediation_safety_guard(raw_pred, description="Information disclosure flaw")
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_2_critical_cvss_blocks_tier_1(self):
        """Critical CVSS score (>= 8.5) must never execute autonomously."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.90,
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.05
            }
        }
        res = evaluate_remediation_safety_guard(raw_pred, description="Memory corruption bug")
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_3_rce_blocks_tier_1(self):
        """Remote code execution threat keywords must block autonomous execution."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.88,
            "cvss_score": 6.5,
            "cvss_severity": "MEDIUM",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.10
            }
        }
        res = evaluate_remediation_safety_guard(
            raw_pred,
            description="Allows unauthenticated remote code execution via buffer overflow."
        )
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_invariant_4_low_confidence_fails_closed(self):
        """Low prediction confidence (< 0.65) must fail closed to Tier 2."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.45,
            "cvss_score": 3.0,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.02
            }
        }
        res = evaluate_remediation_safety_guard(raw_pred, description="Minor log typo")
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_2_HUMAN_APPROVED)
        self.assertEqual(res["required_approvals"], 1)

    def test_invariant_5_blast_radius_escalates_to_tier_3(self):
        """Exceeded blast radius strictly escalates to Tier 3 Dual-Sign-Off."""
        raw_pred = {
            "assigned_tier": TIER_2_HUMAN_APPROVED,
            "assigned_tier_confidence": 0.85,
            "cvss_score": 7.5,
            "cvss_severity": "HIGH",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.15
            }
        }
        res = evaluate_remediation_safety_guard(
            raw_pred,
            description="Patch package dependencies",
            context={"blast_radius_exceeded": True}
        )
        self.assertTrue(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_3_DUAL_SIGNOFF)
        self.assertEqual(res["required_approvals"], 2)
        self.assertFalse(res["is_autonomous_execution_allowed"])

    def test_safe_tier_1_permitted_when_criteria_met(self):
        """Low-severity, high-confidence, non-KEV reversible task allows Tier 1."""
        raw_pred = {
            "assigned_tier": TIER_1_AUTONOMOUS,
            "assigned_tier_confidence": 0.92,
            "cvss_score": 3.2,
            "cvss_severity": "LOW",
            "kev_exploitation_risk": {
                "is_active_exploit_threat": False,
                "exploit_probability": 0.01
            }
        }
        res = evaluate_remediation_safety_guard(
            raw_pred,
            description="Informational cookie missing SameSite attribute",
            context={"asset_criticality": "low"}
        )
        self.assertFalse(res["policy_override_applied"])
        self.assertEqual(res["effective_assigned_tier"], TIER_1_AUTONOMOUS)
        self.assertEqual(res["required_approvals"], 0)
        self.assertTrue(res["is_autonomous_execution_allowed"])

if __name__ == "__main__":
    unittest.main()

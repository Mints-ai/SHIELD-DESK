"""
ShieldDesk Deterministic Remediation Safety Policy Guard.

Ensures machine-learning predictions from CVERandomForestModel never override
hard deterministic security policies defined in ShieldDesk Governance
(src/lib/governance/autonomyTier.ts and src/lib/policy-engine/engine.ts).

Core Invariants:
1. High and Critical severity (CVSS >= 7.0 or severity in ('HIGH', 'CRITICAL'))
   must NEVER be Tier 1 (Autonomous).
2. CISA KEV active weaponization (kev_listed == 1 or exploit_prob >= 0.35)
   must NEVER be Tier 1.
3. High-impact indicators (Remote Code Execution, Privilege Escalation, Auth Bypass)
   cannot be executed autonomously.
4. Missing, malformed, conflicting, or low-confidence data (< 0.65)
   MUST fail-closed to Tier 2 (Human-Approved).
5. Unknown, missing, or unrecognized remediation tiers MUST be rejected
   and fail closed to Tier 2 (Human-Approved); never fall through to autonomous execution.
6. Tier 3 (Dual-Sign-Off Break-Glass) is enforced on critical infrastructure,
   unauthenticated RCE, or high-blast-radius operations.
"""

import math
from typing import Dict, Any, Optional, Set

TIER_1_AUTONOMOUS = "Tier 1 (Low-Risk / Autonomous)"
TIER_2_HUMAN_APPROVED = "Tier 2 (Medium-Risk / Human-Approved)"
TIER_3_DUAL_SIGNOFF = "Tier 3 (High-Risk / Dual-Sign-Off)"

VALID_TIERS: Set[str] = {
    TIER_1_AUTONOMOUS,
    TIER_2_HUMAN_APPROVED,
    TIER_3_DUAL_SIGNOFF,
}

VALID_SEVERITIES: Set[str] = {
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

CRITICAL_THREAT_KEYWORDS = [
    "remote code execution",
    "arbitrary code execution",
    "unauthenticated",
    "privilege escalation",
    "root access",
    "buffer overflow",
    "heap corruption",
    "zero-day",
    "active weaponization",
    "command injection",
]

def evaluate_remediation_safety_guard(
    predictions: Dict[str, Any],
    description: str = "",
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Applies deterministic safety rules over raw ML vulnerability predictions.
    Fails closed on missing, malformed, or conflicting security metadata.
    Never allows an unknown tier or high/critical flaw to execute autonomously.
    """
    context = context or {}
    override_reasons = []

    # Fail closed on non-dict predictions
    if not isinstance(predictions, dict):
        return {
            "raw_assigned_tier": "UNKNOWN",
            "effective_assigned_tier": TIER_2_HUMAN_APPROVED,
            "required_approvals": 1,
            "is_autonomous_execution_allowed": False,
            "policy_override_applied": True,
            "policy_override_reasons": ["Malformed input: predictions payload must be a dictionary."],
            "governance_rule": "ShieldDesk Autonomy Tier Policy §5 (Fail-Closed)",
        }

    # 1. Validate raw assigned tier
    raw_tier = predictions.get("assigned_tier")
    if not isinstance(raw_tier, str) or raw_tier not in VALID_TIERS:
        override_reasons.append(
            f"Unknown, invalid, or missing remediation tier ({repr(raw_tier)}). Failing closed to human approval."
        )
        effective_tier = TIER_2_HUMAN_APPROVED
    else:
        effective_tier = raw_tier

    # 2. Validate CVSS Score
    raw_cvss = predictions.get("cvss_score")
    cvss_score: Optional[float] = None
    if raw_cvss is None:
        override_reasons.append("Missing CVSS score metadata. Failing closed to human approval.")
        effective_tier = TIER_2_HUMAN_APPROVED
    else:
        try:
            cvss_score = float(raw_cvss)
            if math.isnan(cvss_score) or math.isinf(cvss_score) or cvss_score < 0.0 or cvss_score > 10.0:
                override_reasons.append(f"Malformed CVSS score ({raw_cvss}) outside valid range [0.0, 10.0]. Failing closed.")
                effective_tier = TIER_2_HUMAN_APPROVED
                cvss_score = None
        except (ValueError, TypeError):
            override_reasons.append(f"Invalid non-numeric CVSS score ({repr(raw_cvss)}). Failing closed.")
            effective_tier = TIER_2_HUMAN_APPROVED
            cvss_score = None

    # 3. Validate CVSS Severity
    raw_sev = predictions.get("cvss_severity")
    cvss_severity: Optional[str] = None
    if not isinstance(raw_sev, str) or not raw_sev.strip():
        override_reasons.append("Missing CVSS severity rating. Failing closed to human approval.")
        effective_tier = TIER_2_HUMAN_APPROVED
    else:
        normalized_sev = raw_sev.strip().upper()
        if normalized_sev not in VALID_SEVERITIES:
            override_reasons.append(f"Unrecognized CVSS severity rating ({repr(raw_sev)}). Failing closed.")
            effective_tier = TIER_2_HUMAN_APPROVED
        else:
            cvss_severity = normalized_sev

    # 4. Detect Conflicting CVSS Score and Severity
    if cvss_score is not None and cvss_severity is not None:
        if cvss_score >= 7.0 and cvss_severity in ("NONE", "LOW", "MEDIUM"):
            override_reasons.append(
                f"Conflicting CVSS score ({cvss_score}) and severity ({cvss_severity}) detected. Failing closed."
            )
            effective_tier = TIER_2_HUMAN_APPROVED
        elif cvss_score < 4.0 and cvss_severity in ("HIGH", "CRITICAL"):
            override_reasons.append(
                f"Conflicting CVSS score ({cvss_score}) and severity ({cvss_severity}) detected. Failing closed."
            )
            effective_tier = TIER_2_HUMAN_APPROVED

    # 5. Validate KEV & Exploit Probability Metadata
    kev_info = predictions.get("kev_exploitation_risk")
    is_kev = False
    kev_prob: Optional[float] = None
    if not isinstance(kev_info, dict):
        override_reasons.append("Missing or malformed KEV exploitation metadata. Failing closed to human approval.")
        effective_tier = TIER_2_HUMAN_APPROVED
    else:
        is_kev = bool(kev_info.get("is_active_exploit_threat", False))
        raw_prob = kev_info.get("exploit_probability")
        if raw_prob is None:
            override_reasons.append("Missing exploit probability metadata. Failing closed to human approval.")
            effective_tier = TIER_2_HUMAN_APPROVED
        else:
            try:
                kev_prob = float(raw_prob)
                if math.isnan(kev_prob) or math.isinf(kev_prob) or kev_prob < 0.0 or kev_prob > 1.0:
                    override_reasons.append(f"Malformed exploit probability ({raw_prob}) outside [0.0, 1.0]. Failing closed.")
                    effective_tier = TIER_2_HUMAN_APPROVED
                    kev_prob = None
            except (ValueError, TypeError):
                override_reasons.append(f"Invalid non-numeric exploit probability ({repr(raw_prob)}). Failing closed.")
                effective_tier = TIER_2_HUMAN_APPROVED
                kev_prob = None

    # 6. Validate Model Confidence
    raw_conf = predictions.get("assigned_tier_confidence")
    tier_conf: float = 0.0
    if raw_conf is None:
        override_reasons.append("Missing assigned tier confidence. Failing closed to human approval.")
        effective_tier = TIER_2_HUMAN_APPROVED
    else:
        try:
            tier_conf = float(raw_conf)
            if math.isnan(tier_conf) or math.isinf(tier_conf):
                tier_conf = 0.0
            elif tier_conf > 1.0:
                tier_conf = min(1.0, tier_conf / 100.0)
        except (ValueError, TypeError):
            tier_conf = 0.0

    if tier_conf < 0.65 and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            f"Model prediction confidence ({tier_conf:.2f}) is below autonomous safety threshold (0.65). Failing closed to human approval."
        )

    # 7. Invariant: High and Critical Severity NEVER Autonomous (CVSS >= 7.0 or HIGH/CRITICAL)
    if effective_tier == TIER_1_AUTONOMOUS:
        if (cvss_score is not None and cvss_score >= 7.0) or cvss_severity in ("HIGH", "CRITICAL"):
            effective_tier = TIER_2_HUMAN_APPROVED
            override_reasons.append(
                f"High or Critical severity flaw (CVSS {cvss_score}, severity {cvss_severity}) strictly prohibits autonomous remediation."
            )

    # 8. Invariant: CISA KEV In-the-Wild Exploitation
    if effective_tier == TIER_1_AUTONOMOUS:
        if is_kev or (kev_prob is not None and kev_prob >= 0.35):
            effective_tier = TIER_2_HUMAN_APPROVED
            override_reasons.append(
                "CISA KEV active exploitation detected. Unattended autonomous execution forbidden."
            )

    # 9. Invariant: High-Impact Threat Keywords (RCE, Auth Bypass, Command Injection)
    desc_lower = (description or "").lower()
    has_critical_keyword = any(kw in desc_lower for kw in CRITICAL_THREAT_KEYWORDS)
    if has_critical_keyword and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            "High-impact threat vector (RCE/privilege escalation/auth bypass) prohibits autonomous remediation."
        )

    # 10. Invariant: Escalation to Tier 3 (Dual Sign-Off Break-Glass)
    asset_criticality = str(context.get("asset_criticality", "medium")).lower()
    blast_radius_exceeded = bool(context.get("blast_radius_exceeded", False))

    if blast_radius_exceeded:
        effective_tier = TIER_3_DUAL_SIGNOFF
        override_reasons.append("Operational blast radius strictly exceeded; escalated to dual human approvals.")
    elif asset_criticality == "critical" and ((cvss_score is not None and cvss_score >= 9.0) or (is_kev and has_critical_keyword)):
        effective_tier = TIER_3_DUAL_SIGNOFF
        override_reasons.append(
            "Critical asset exposed to severe/weaponized flaw; escalated to dual administrator break-glass approval."
        )

    # 11. Final Enforced Tier and Sign-off Mapping
    # Strict whitelist mapping: unknown or corrupted tier CANNOT be autonomous
    if effective_tier == TIER_3_DUAL_SIGNOFF:
        required_approvals = 2
        autonomous_allowed = False
    elif effective_tier == TIER_2_HUMAN_APPROVED:
        required_approvals = 1
        autonomous_allowed = False
    elif effective_tier == TIER_1_AUTONOMOUS:
        required_approvals = 0
        autonomous_allowed = True
    else:
        # Failsafe defense in depth
        effective_tier = TIER_2_HUMAN_APPROVED
        required_approvals = 1
        autonomous_allowed = False
        override_reasons.append("Unknown effective tier failed closed to human approval.")

    return {
        "raw_assigned_tier": raw_tier,
        "effective_assigned_tier": effective_tier,
        "required_approvals": required_approvals,
        "is_autonomous_execution_allowed": autonomous_allowed,
        "policy_override_applied": len(override_reasons) > 0,
        "policy_override_reasons": override_reasons,
        "governance_rule": "ShieldDesk Autonomy Tier Policy §5",
    }

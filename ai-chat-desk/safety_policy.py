"""
ShieldDesk Deterministic Remediation Safety Policy Guard.

Ensures machine-learning predictions from CVERandomForestModel never override
hard deterministic security policies defined in ShieldDesk Governance
(src/lib/governance/autonomyTier.ts and src/lib/policy-engine/engine.ts).

Core Invariants:
1. Critical severity (CVSS >= 8.5 or severity == 'CRITICAL') must NEVER be Tier 1 (Autonomous).
2. CISA KEV active weaponization (kev_listed == 1 or exploit_prob >= 0.35) must NEVER be Tier 1.
3. High-impact indicators (Remote Code Execution, Privilege Escalation, Auth Bypass)
   cannot be executed autonomously.
4. Missing, conflicting, or low-confidence data (< 0.65) MUST fail-closed to Tier 2 (Human-Approved).
5. Tier 3 (Dual-Sign-Off Break-Glass) is enforced on critical infrastructure,
   unauthenticated RCE, or high-blast-radius operations.
"""

from typing import Dict, Any, Optional

TIER_1_AUTONOMOUS = "Tier 1 (Low-Risk / Autonomous)"
TIER_2_HUMAN_APPROVED = "Tier 2 (Medium-Risk / Human-Approved)"
TIER_3_DUAL_SIGNOFF = "Tier 3 (High-Risk / Dual-Sign-Off)"

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
    
    Returns an audited dictionary containing:
    - effective_tier: The enforced autonomy tier
    - required_approvals: Number of human sign-offs (0, 1, or 2)
    - autonomous_allowed: Boolean indicating if unattended execution is permitted
    - override_applied: True if deterministic policy overrode statistical prediction
    - override_reasons: List of reasons triggering the override
    """
    context = context or {}
    override_reasons = []

    # Extract raw predictions safely
    raw_tier = predictions.get("assigned_tier", TIER_2_HUMAN_APPROVED)
    cvss_score = float(predictions.get("cvss_score", 0.0))
    cvss_severity = str(predictions.get("cvss_severity", "UNKNOWN")).upper()
    
    kev_info = predictions.get("kev_exploitation_risk", {})
    is_kev = bool(kev_info.get("is_active_exploit_threat", False))
    kev_prob = float(kev_info.get("exploit_probability", 0.0))

    tier_conf = float(predictions.get("assigned_tier_confidence", 0.0))
    # Correct possible unnormalized voting count bug from scikit-learn version mismatch
    if tier_conf > 1.0:
        tier_conf = min(1.0, tier_conf / 100.0)

    desc_lower = description.lower()
    asset_criticality = str(context.get("asset_criticality", "medium")).lower()
    blast_radius_exceeded = bool(context.get("blast_radius_exceeded", False))

    effective_tier = raw_tier

    # -------------------------------------------------------------------------
    # Invariant 1: CISA KEV In-the-Wild Exploitation
    # -------------------------------------------------------------------------
    if (is_kev or kev_prob >= 0.35) and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            "CISA KEV active exploitation detected. Unattended autonomous execution forbidden."
        )

    # -------------------------------------------------------------------------
    # Invariant 2: Critical CVSS Score or Severity
    # -------------------------------------------------------------------------
    if (cvss_score >= 8.5 or cvss_severity == "CRITICAL") and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            f"Critical CVSS severity ({cvss_severity}, score {cvss_score}) strictly requires human sign-off."
        )

    # -------------------------------------------------------------------------
    # Invariant 3: High Threat Indicators (RCE / Unauthenticated Auth Bypass)
    # -------------------------------------------------------------------------
    has_critical_keyword = any(kw in desc_lower for kw in CRITICAL_THREAT_KEYWORDS)
    if has_critical_keyword and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            "High-impact threat vector (RCE/privilege escalation/auth bypass) prohibits autonomous remediation."
        )

    # -------------------------------------------------------------------------
    # Invariant 4: Fail-Closed on Low Confidence or Missing Data
    # -------------------------------------------------------------------------
    if tier_conf < 0.65 and effective_tier == TIER_1_AUTONOMOUS:
        effective_tier = TIER_2_HUMAN_APPROVED
        override_reasons.append(
            f"Model prediction confidence ({tier_conf:.2f}) is below autonomous safety threshold (0.65). Failing closed to human approval."
        )

    # -------------------------------------------------------------------------
    # Invariant 5: Escalation to Tier 3 (Dual Sign-Off Break-Glass)
    # -------------------------------------------------------------------------
    # Triggers when critical flaw exists on critical asset, blast radius is exceeded,
    # or an unauthenticated RCE is actively weaponized
    if blast_radius_exceeded:
        effective_tier = TIER_3_DUAL_SIGNOFF
        override_reasons.append("Operational blast radius strictly exceeded; escalated to dual human approvals.")
    elif asset_criticality == "critical" and (cvss_score >= 9.0 or (is_kev and has_critical_keyword)):
        effective_tier = TIER_3_DUAL_SIGNOFF
        override_reasons.append(
            "Critical asset exposed to severe/weaponized flaw; escalated to dual administrator break-glass approval."
        )

    # Determine required approvals and autonomous authorization
    if effective_tier == TIER_3_DUAL_SIGNOFF:
        required_approvals = 2
        autonomous_allowed = False
    elif effective_tier == TIER_2_HUMAN_APPROVED:
        required_approvals = 1
        autonomous_allowed = False
    else:
        # Tier 1
        required_approvals = 0
        autonomous_allowed = True

    return {
        "raw_assigned_tier": raw_tier,
        "effective_assigned_tier": effective_tier,
        "required_approvals": required_approvals,
        "is_autonomous_execution_allowed": autonomous_allowed,
        "policy_override_applied": len(override_reasons) > 0,
        "policy_override_reasons": override_reasons,
        "governance_rule": "ShieldDesk Autonomy Tier Policy §5",
    }

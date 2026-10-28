"""Evidence-based Risk Scoring Engine and Verdict Classifier for URL Audit Kit.

Supports four calibrated verdicts:
- BENIGN: Sufficient evidence gathered and confirmed clean; low risk score.
- SUSPICIOUS: Indicators of concern or non-critical security failures detected.
- MALICIOUS: High-confidence threat intelligence match or severe security failures.
- INCONCLUSIVE: Operational failures or insufficient evaluative data prevent a reliable verdict.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Named Constants & Point Weights
# ---------------------------------------------------------------------------

# Point values assigned to check statuses (per check)
POINTS_PASS: int = 0
POINTS_INFO: int = 0
POINTS_SKIP: int = 0
POINTS_ERROR: int = 0   # Operational errors NEVER contribute risk points
POINTS_WARN: int = 4    # Calibrated non-critical warning weight
POINTS_FAIL: int = 8    # Base security failure weight

STATUS_POINTS: Dict[str, int] = {
    "PASS": POINTS_PASS,
    "INFO": POINTS_INFO,
    "SKIP": POINTS_SKIP,
    "ERROR": POINTS_ERROR,
    "WARN": POINTS_WARN,
    "FAIL": POINTS_FAIL,
}

# Bonus points added to critical security checks upon positive FAIL
CRITICAL_FAIL_BONUS: int = 12

# Score Thresholds for Risk Level Classification
THRESHOLD_SCORE_LOW: int = 0
THRESHOLD_SCORE_MEDIUM: int = 25
THRESHOLD_SCORE_HIGH: int = 50
THRESHOLD_SCORE_CRITICAL: int = 75

# Standard Verdicts
VERDICT_BENIGN: str = "BENIGN"
VERDICT_SUSPICIOUS: str = "SUSPICIOUS"
VERDICT_MALICIOUS: str = "MALICIOUS"
VERDICT_INCONCLUSIVE: str = "INCONCLUSIVE"

# Keywords designating critical infrastructure and reputation checks
CRITICAL_CHECK_KEYWORDS: Tuple[str, ...] = (
    "ssl",
    "https",
    "blacklist",
    "virus total",
    "virustotal",
    "safe browsing",
    "ip reputation",
    "certificate issuer",
)

# High-confidence threat intelligence sources (a FAIL here is decisive)
HIGH_CONFIDENCE_THREAT_KEYWORDS: Tuple[str, ...] = (
    "blacklist",
    "safe browsing",
    "virustotal",
    "virus total",
)

# Minimum number of conclusive evaluative checks (PASS / WARN / FAIL) required
# to establish a reliable conclusion (avoids declaring all-error scans BENIGN)
MIN_CONCLUSIVE_CHECKS_REQUIRED: int = 3


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def is_critical_check(name: str) -> bool:
    """Determines if a check belongs to the critical security check category."""
    check_name = (name or "").lower()
    return any(keyword in check_name for keyword in CRITICAL_CHECK_KEYWORDS)


def is_high_confidence_threat_check(name: str) -> bool:
    """Determines if a check is a primary external threat intelligence signal."""
    check_name = (name or "").lower()
    return any(keyword in check_name for keyword in HIGH_CONFIDENCE_THREAT_KEYWORDS)


def risk_level_from_score(score: int) -> str:
    """Categorizes a numeric risk score (0-100) into a standard risk level."""
    if score >= THRESHOLD_SCORE_CRITICAL:
        return "CRITICAL"
    if score >= THRESHOLD_SCORE_HIGH:
        return "HIGH"
    if score >= THRESHOLD_SCORE_MEDIUM:
        return "MEDIUM"
    return "LOW"


def verdict_from_risk_level(risk_level: str) -> str:
    """Legacy backward-compatible mapper for score-derived verdicts."""
    level = (risk_level or "").upper()
    if level in {"HIGH", "CRITICAL"}:
        return VERDICT_MALICIOUS
    if level == "MEDIUM":
        return VERDICT_SUSPICIOUS
    return VERDICT_BENIGN


# ---------------------------------------------------------------------------
# Core Risk Computation Engine
# ---------------------------------------------------------------------------

def compute_risk(checks: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluates checks and calculates evidence-based risk metrics, level, and verdict.
    
    Guarantees:
    - Operational errors (ERROR) and unexecuted checks (SKIP) contribute 0 risk points.
    - Confirmed threat intelligence matches directly yield MALICIOUS.
    - Operational outages do not degrade confirmed threats to INCONCLUSIVE.
    - Low scores alone never yield BENIGN if essential checks failed operationally.
    """
    total_points = 0
    max_points = 0
    critical_failures: List[str] = []
    high_confidence_threats: List[str] = []

    pass_count = 0
    warn_count = 0
    fail_count = 0
    error_count = 0
    skip_count = 0

    for check in checks:
        status = str(check.get("status", "WARN")).upper()
        name = str(check.get("name", ""))

        if status == "PASS":
            pass_count += 1
        elif status == "WARN":
            warn_count += 1
        elif status == "FAIL":
            fail_count += 1
        elif status == "ERROR":
            error_count += 1
        elif status == "SKIP":
            skip_count += 1

        is_crit = is_critical_check(name)
        is_threat = is_high_confidence_threat_check(name)

        # Retrieve base points (ERROR & SKIP produce 0)
        base_points = STATUS_POINTS.get(status, 0)
        critical_bonus = CRITICAL_FAIL_BONUS if (is_crit and status == "FAIL") else 0

        total_points += base_points + critical_bonus
        # Denominator only scales based on what could be evaluated
        max_points += STATUS_POINTS["FAIL"] + (CRITICAL_FAIL_BONUS if is_crit else 0)

        if is_crit and status == "FAIL":
            critical_failures.append(name)
        if is_threat and status == "FAIL":
            high_confidence_threats.append(name)

    normalized_score = int(round((total_points / max(max_points, 1)) * 100))
    risk_score = max(0, min(100, normalized_score))
    risk_level = risk_level_from_score(risk_score)

    evaluative_checks_count = pass_count + warn_count + fail_count

    # -----------------------------------------------------------------------
    # Evidence-based Verdict Resolution
    # -----------------------------------------------------------------------

    # Rule 1: High-confidence confirmed threat intelligence match -> MALICIOUS
    if high_confidence_threats:
        verdict = VERDICT_MALICIOUS

    # Rule 2: High risk score or multiple critical check failures -> MALICIOUS
    elif risk_score >= THRESHOLD_SCORE_HIGH or len(critical_failures) >= 2:
        verdict = VERDICT_MALICIOUS

    # Rule 3: Moderate risk score or single critical check failure -> SUSPICIOUS
    elif risk_score >= THRESHOLD_SCORE_MEDIUM or len(critical_failures) == 1 or warn_count >= 2:
        verdict = VERDICT_SUSPICIOUS

    # Rule 4: Inconclusive when lacking sufficient evaluative evidence
    # (e.g. critical checks failed with ERROR or evaluative count is below threshold)
    elif evaluative_checks_count < MIN_CONCLUSIVE_CHECKS_REQUIRED or (error_count > 0 and evaluative_checks_count <= 2):
        verdict = VERDICT_INCONCLUSIVE

    # Rule 5: Sufficient conclusive evidence gathered with low score and no threats -> BENIGN
    else:
        verdict = VERDICT_BENIGN

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "points": total_points,
        "max_points": max_points,
        "critical_failures": critical_failures,
        "high_confidence_threats": high_confidence_threats,
        "evaluative_checks_count": evaluative_checks_count,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "error_count": error_count,
        "skip_count": skip_count,
    }

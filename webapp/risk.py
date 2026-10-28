from __future__ import annotations

from typing import Any, Dict, List, Sequence

STATUS_POINTS = {
    "PASS": 0,
    "INFO": 1,
    "WARN": 4,
    "FAIL": 8,
    "SKIP": 0,
}

CRITICAL_FAIL_BONUS = 12

_CRITICAL_CHECK_KEYWORDS = (
    "ssl",
    "https",
    "blacklist",
    "virus total",
    "virustotal",
    "safe browsing",
    "ip reputation",
    "certificate issuer",
)


def _is_critical_check(name: str) -> bool:
    check_name = (name or "").lower()
    return any(keyword in check_name for keyword in _CRITICAL_CHECK_KEYWORDS)


def risk_level_from_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def verdict_from_risk_level(risk_level: str) -> str:
    level = (risk_level or "").upper()
    if level in {"HIGH", "CRITICAL"}:
        return "MALICIOUS"
    if level == "MEDIUM":
        return "SUSPICIOUS"
    return "BENIGN"


def compute_risk(checks: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total_points = 0
    max_points = 0
    critical_failures: List[str] = []

    for check in checks:
        status = str(check.get("status", "WARN")).upper()
        name = str(check.get("name", ""))
        is_critical = _is_critical_check(name)

        base_points = STATUS_POINTS.get(status, STATUS_POINTS["WARN"])
        critical_bonus = CRITICAL_FAIL_BONUS if is_critical and status == "FAIL" else 0

        total_points += base_points + critical_bonus
        max_points += STATUS_POINTS["FAIL"] + (CRITICAL_FAIL_BONUS if is_critical else 0)

        if critical_bonus:
            critical_failures.append(name)

    normalized_score = int(round((total_points / max(max_points, 1)) * 100))
    risk_score = max(0, min(100, normalized_score))
    risk_level = risk_level_from_score(risk_score)
    verdict = verdict_from_risk_level(risk_level)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "points": total_points,
        "max_points": max_points,
        "critical_failures": critical_failures,
    }

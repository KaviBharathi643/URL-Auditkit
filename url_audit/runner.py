from typing import Callable, Iterable, List, Optional, Sequence, Tuple, Union

from .utils import CheckResult
from .checks import behavior_checks as bc
from .checks import domain_checks as dc
from .checks import reputation_checks as rc
from .checks import security_checks as sc
from .checks import llm_checks as lc

StepReturn = Union[CheckResult, Sequence[CheckResult], None]
StepFunc = Callable[[str], StepReturn]
Step = Tuple[str, StepFunc]


def _ensure_list(value: StepReturn) -> List[CheckResult]:
    if value is None:
        return []
    if isinstance(value, CheckResult):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return []


CHECK_STEPS: List[Step] = [
    ("Domain Name Legitimacy", dc.check_domain_legitimacy),
    ("WHOIS and Domain Age", dc.check_whois_age),
    ("Domain Expiry", dc.check_domain_expiry),
    ("SSL Validity", sc.check_ssl_validity),
    ("HTTPS Presence", sc.check_https_presence),
    ("Certificate Issuer", sc.check_certificate_issuer),
    ("IP Reputation", sc.check_ip_reputation),
    ("Hosting Provider", sc.check_hosting_provider),
    ("Security Blacklists", rc.check_security_blacklists),
    ("Google Safe Browsing", rc.check_google_safe_browsing),
    ("Redirect Behaviour", bc.check_redirects),
    ("Suspicious Requests", bc.check_suspicious_requests),
    ("URL Length", bc.check_url_length),
    ("Homoglyph Detection", bc.check_homoglyph),
    ("AI Content Analysis", lc.check_llm_content_analysis),
]


def total_steps() -> int:
    return len(CHECK_STEPS)


ProgressCallback = Callable[[int, int, str, List[CheckResult]], None]


def _run_step(url: str, step: Step, index: int) -> List[CheckResult]:
    label, func = step
    try:
        return _ensure_list(func(url))
    except Exception as exc:  # noqa: BLE001
        return [
            CheckResult(
                1000 + index,
                label,
                "FAIL",
                evidence=f"check crashed: {exc}",
                data={"error": str(exc)},
            )
        ]


def run_all(url: str, progress_callback: Optional[ProgressCallback] = None) -> List[CheckResult]:
    results: List[CheckResult] = []
    steps = total_steps()
    for index, step in enumerate(CHECK_STEPS, start=1):
        step_results = _run_step(url, step, index)
        results.extend(step_results)
        if progress_callback:
            label = step_results[0].name if step_results else step[0]
            progress_callback(index, steps, label, step_results)
    return results


def summarize(results: List[CheckResult]):
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts

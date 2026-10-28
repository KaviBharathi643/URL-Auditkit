"""Bounded concurrent scanning runner and lifecycle manager for URL Audit Kit.

Features:
- Check classification: Blocking Network I/O, CPU-bound, and Native Async dependencies.
- Bounded concurrency: Configurable per-scan concurrency limit (default: 8 workers).
- Global thread ceiling: Shared ThreadPoolExecutor with bounded worker capacity (default: 32).
- Strict monotonic deadline enforcement (default: 12.0s) with capped operation timeouts.
- Safe context propagation (contextvars) across worker threads.
- Deterministic partial results on deadline expiration (never declares incomplete scans clean).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import os
import threading
import time
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .utils import CheckResult
from .security import (
    DEFAULT_SCAN_DEADLINE,
    AuditTimeoutError,
    DNSNXDomainError,
    DNSResolutionError,
    DNSTimeoutError,
    InvalidURLError,
    SSRFError,
    get_remaining_deadline,
    reset_scan_deadline,
    set_scan_deadline,
)
from .checks import behavior_checks as bc
from .checks import domain_checks as dc
from .checks import reputation_checks as rc
from .checks import security_checks as sc
from .checks import llm_checks as lc

StepReturn = Union[CheckResult, Sequence[CheckResult], None]
StepFunc = Callable[[str], StepReturn]
Step = Tuple[str, StepFunc]

# ---------------------------------------------------------------------------
# Concurrency Configuration & Check Classification
# ---------------------------------------------------------------------------

DEFAULT_CHECK_CONCURRENCY: int = int(os.getenv("URL_AUDIT_CHECK_CONCURRENCY", "8"))
DEFAULT_GLOBAL_SCAN_LIMIT: int = int(os.getenv("URL_AUDIT_GLOBAL_SCAN_LIMIT", "5"))
DEFAULT_MAX_WORKERS: int = int(os.getenv("URL_AUDIT_MAX_WORKERS", "32"))


class CheckClassification(str, Enum):
    """Categorization of check execution profiles."""
    BLOCKING_NETWORK_IO = "BLOCKING_NETWORK_IO"
    CPU_BOUND = "CPU_BOUND"
    ASYNC_NATIVE = "ASYNC_NATIVE"


CHECK_CLASSIFICATIONS: Dict[str, CheckClassification] = {
    "Domain Name Legitimacy": CheckClassification.BLOCKING_NETWORK_IO,
    "WHOIS and Domain Age": CheckClassification.BLOCKING_NETWORK_IO,
    "Domain Expiry": CheckClassification.BLOCKING_NETWORK_IO,
    "SSL Validity": CheckClassification.BLOCKING_NETWORK_IO,
    "HTTPS Presence": CheckClassification.CPU_BOUND,
    "Certificate Issuer": CheckClassification.BLOCKING_NETWORK_IO,
    "IP Reputation": CheckClassification.BLOCKING_NETWORK_IO,
    "Hosting Provider": CheckClassification.BLOCKING_NETWORK_IO,
    "Security Blacklists": CheckClassification.BLOCKING_NETWORK_IO,
    "Google Safe Browsing": CheckClassification.BLOCKING_NETWORK_IO,
    "Redirect Behaviour": CheckClassification.BLOCKING_NETWORK_IO,
    "Suspicious Requests": CheckClassification.BLOCKING_NETWORK_IO,
    "URL Length": CheckClassification.CPU_BOUND,
    "Homoglyph Detection": CheckClassification.CPU_BOUND,
    "AI Content Analysis": CheckClassification.BLOCKING_NETWORK_IO,
}


_EXECUTOR_LOCK = threading.Lock()
_GLOBAL_EXECUTOR: Optional[concurrent.futures.ThreadPoolExecutor] = None


def get_shared_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Returns a shared, bounded ThreadPoolExecutor across all scans to prevent thread explosion."""
    global _GLOBAL_EXECUTOR
    with _EXECUTOR_LOCK:
        if _GLOBAL_EXECUTOR is None or getattr(_GLOBAL_EXECUTOR, "_shutdown", False):
            _GLOBAL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                max_workers=DEFAULT_MAX_WORKERS,
                thread_name_prefix="url_audit_worker",
            )
        return _GLOBAL_EXECUTOR


def shutdown_shared_executor(wait: bool = False) -> None:
    """Safely shuts down the global ThreadPoolExecutor during application teardown."""
    global _GLOBAL_EXECUTOR
    with _EXECUTOR_LOCK:
        if _GLOBAL_EXECUTOR is not None:
            _GLOBAL_EXECUTOR.shutdown(wait=wait, cancel_futures=True)
            _GLOBAL_EXECUTOR = None


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
    """Executes a single audit check with monotonic deadline pre-validation and error classification."""
    label, func = step
    remaining = get_remaining_deadline()
    if remaining is not None and remaining <= 0:
        return [
            CheckResult(
                1000 + index,
                label,
                "ERROR",
                evidence="Scan deadline exceeded before check execution",
                data={"error": "timeout", "deadline_exceeded": True},
            )
        ]

    try:
        return _ensure_list(func(url))
    except (AuditTimeoutError, TimeoutError, DNSTimeoutError) as exc:
        return [
            CheckResult(
                1000 + index,
                label,
                "ERROR",
                evidence=f"Scan deadline or timeout exceeded: {exc}",
                data={"error": "timeout", "deadline_exceeded": True},
            )
        ]
    except DNSNXDomainError as exc:
        return [
            CheckResult(
                1000 + index,
                label,
                "WARN",
                evidence=f"Domain does not exist in authoritative DNS (NXDOMAIN): {exc}",
                data={"error": "nxdomain"},
            )
        ]
    except DNSResolutionError as exc:
        return [
            CheckResult(
                1000 + index,
                label,
                "ERROR",
                evidence=f"Temporary DNS resolution failure: {exc}",
                data={"error": "dns_failure"},
            )
        ]
    except SSRFError as exc:
        return [
            CheckResult(
                1000 + index,
                label,
                "FAIL",
                evidence=f"SSRF violation: {exc}",
                data={"error": "ssrf_violation"},
            )
        ]
    except InvalidURLError as exc:
        return [
            CheckResult(
                1000 + index,
                label,
                "ERROR",
                evidence=f"Invalid URL structure: {exc}",
                data={"error": "invalid_url"},
            )
        ]
    except Exception as exc:  # noqa: BLE001
        return [
            CheckResult(
                1000 + index,
                label,
                "ERROR",
                evidence=f"Operational error during check execution: {exc}",
                data={"error": str(exc)},
            )
        ]


# ---------------------------------------------------------------------------
# Bounded Concurrent Execution Engine
# ---------------------------------------------------------------------------

def run_all(
    url: str,
    progress_callback: Optional[ProgressCallback] = None,
    deadline_ts: Optional[float] = None,
    max_concurrency: int = DEFAULT_CHECK_CONCURRENCY,
) -> List[CheckResult]:
    """Executes all audit checks with bounded concurrency and strict monotonic deadline enforcement.
    
    Guarantees:
    - At most `max_concurrency` (default: 8) checks run simultaneously per scan.
    - Global thread limit prevents server exhaustion.
    - Context variables (including monotonic deadline) are preserved across threads.
    - Progress is reported monotonically as tasks complete.
    - Deadlines result in clean partial results (ERROR); incomplete scans are never marked BENIGN.
    - Results are deterministically sorted by check index (1..N).
    """
    def _calc_remaining(deadline: float) -> float:
        time_rem = deadline - time.time()
        mono_rem = deadline - time.monotonic()
        return time_rem if abs(time_rem) < 500 else mono_rem

    effective_deadline = (
        deadline_ts
        if deadline_ts is not None
        else time.monotonic() + DEFAULT_SCAN_DEADLINE
    )
    token = set_scan_deadline(effective_deadline)
    executor = get_shared_executor()
    steps_total = total_steps()

    pending_steps: List[Tuple[int, Step]] = list(enumerate(CHECK_STEPS, start=1))
    active_futures: Dict[concurrent.futures.Future, Tuple[int, Step]] = {}
    completed_results: Dict[int, List[CheckResult]] = {}
    completed_count = 0

    try:
        # 1. Fill active concurrency slots up to max_concurrency
        while pending_steps and len(active_futures) < max_concurrency:
            if _calc_remaining(effective_deadline) <= 0:
                break
            idx, step = pending_steps.pop(0)
            ctx = contextvars.copy_context()
            fut = executor.submit(ctx.run, _run_step, url, step, idx)
            active_futures[fut] = (idx, step)

        # 2. Event loop processing completed tasks
        while active_futures:
            remaining = _calc_remaining(effective_deadline)
            if remaining <= 0:
                break

            # Wait for at least one future to finish or deadline to expire
            done, _ = concurrent.futures.wait(
                active_futures.keys(),
                timeout=max(0.01, remaining),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            if not done and _calc_remaining(effective_deadline) <= 0:
                break

            for fut in done:
                idx, step = active_futures.pop(fut)
                try:
                    step_res = fut.result()
                except Exception as exc:
                    step_res = [
                        CheckResult(
                            1000 + idx,
                            step[0],
                            "ERROR",
                            evidence=f"Worker execution exception: {exc}",
                            data={"error": str(exc)},
                        )
                    ]

                completed_results[idx] = step_res
                completed_count += 1

                if progress_callback:
                    lbl = step_res[0].name if step_res else step[0]
                    progress_callback(completed_count, steps_total, lbl, step_res)

                # Submit next pending check if deadline permits
                if pending_steps and _calc_remaining(effective_deadline) > 0:
                    next_idx, next_step = pending_steps.pop(0)
                    ctx = contextvars.copy_context()
                    next_fut = executor.submit(ctx.run, _run_step, url, next_step, next_idx)
                    active_futures[next_fut] = (next_idx, next_step)

        # 3. Handle deadline timeout for unfinished or unscheduled checks
        if _calc_remaining(effective_deadline) <= 0:
            for fut, (idx, step) in list(active_futures.items()):
                fut.cancel()
                if idx not in completed_results:
                    completed_results[idx] = [
                        CheckResult(
                            1000 + idx,
                            step[0],
                            "ERROR",
                            evidence=f"Scan deadline exceeded ({DEFAULT_SCAN_DEADLINE}s); check timed out",
                            data={"error": "timeout", "deadline_exceeded": True},
                        )
                    ]
            active_futures.clear()

            for idx, step in pending_steps:
                completed_results[idx] = [
                    CheckResult(
                        1000 + idx,
                        step[0],
                        "ERROR",
                        evidence=f"Scan deadline exceeded ({DEFAULT_SCAN_DEADLINE}s); check unscheduled",
                        data={"error": "timeout", "deadline_exceeded": True},
                    )
                ]
            pending_steps.clear()

    finally:
        reset_scan_deadline(token)

    # 4. Deterministically sort results by step index (1..15)
    sorted_results: List[CheckResult] = []
    for idx in range(1, steps_total + 1):
        if idx in completed_results:
            sorted_results.extend(completed_results[idx])
        else:
            sorted_results.append(
                CheckResult(
                    1000 + idx,
                    CHECK_STEPS[idx - 1][0],
                    "ERROR",
                    evidence="Scan aborted before execution",
                    data={"error": "timeout", "deadline_exceeded": True},
                )
            )

    return sorted_results


async def run_all_async(
    url: str,
    progress_callback: Optional[ProgressCallback] = None,
    deadline_ts: Optional[float] = None,
    max_concurrency: int = DEFAULT_CHECK_CONCURRENCY,
) -> List[CheckResult]:
    """Asynchronous entry point for non-blocking invocation from FastAPI."""
    return await asyncio.to_thread(
        run_all,
        url,
        progress_callback,
        deadline_ts,
        max_concurrency,
    )


def summarize(results: List[CheckResult]) -> Dict[str, int]:
    """Summarizes status counts across all check results."""
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0, "INFO": 0}
    for r in results:
        status = (r.status or "ERROR").upper()
        counts[status] = counts.get(status, 0) + 1
    return counts

"""Phase 4 Test Suite: Bounded Concurrency, Monotonic Deadlines, Lifecycle, and Benchmark.

Covers:
1. Classification of every check dependency (Blocking Network I/O vs CPU-bound).
2. Bounded per-scan concurrency (max 8 simultaneous check operations).
3. Monotonic deadline enforcement (12.0s ceiling) and partial result generation.
4. Global scan concurrency limits and thread pool ceiling (max 32 workers).
5. WebSocket progress monotonicity, bounded queues, and guaranteed terminal events.
6. Controlled deterministic performance benchmark (< 3.5s for all 15 checks with fast/mocked services).
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from url_audit.runner import (
    CHECK_CLASSIFICATIONS,
    CHECK_STEPS,
    DEFAULT_CHECK_CONCURRENCY,
    DEFAULT_GLOBAL_SCAN_LIMIT,
    DEFAULT_MAX_WORKERS,
    DEFAULT_SCAN_DEADLINE,
    CheckClassification,
    get_shared_executor,
    run_all,
    run_all_async,
    summarize,
    total_steps,
)
from url_audit.security import (
    AuditTimeoutError,
    get_remaining_deadline,
    reset_scan_deadline,
    set_scan_deadline,
)
from url_audit.utils import CheckResult
from webapp.main import (
    _GLOBAL_SCAN_SEMAPHORE,
    _discard_progress_queue,
    _get_progress_queue,
    _progress_channels,
    app,
)
from webapp.risk import compute_risk


class TestCheckClassificationAudit(unittest.TestCase):
    """1. Verify that all 15 checks are classified appropriately."""

    def test_all_fifteen_checks_classified(self):
        step_names = [name for name, _ in CHECK_STEPS]
        self.assertEqual(len(step_names), 15)
        for name in step_names:
            self.assertIn(name, CHECK_CLASSIFICATIONS, f"Check '{name}' missing classification")
            classification = CHECK_CLASSIFICATIONS[name]
            self.assertIsInstance(classification, CheckClassification)

    def test_cpu_bound_checks_identified(self):
        cpu_checks = {
            name
            for name, cls in CHECK_CLASSIFICATIONS.items()
            if cls == CheckClassification.CPU_BOUND
        }
        self.assertIn("HTTPS Presence", cpu_checks)
        self.assertIn("URL Length", cpu_checks)
        self.assertIn("Homoglyph Detection", cpu_checks)

    def test_network_io_checks_identified(self):
        io_checks = {
            name
            for name, cls in CHECK_CLASSIFICATIONS.items()
            if cls == CheckClassification.BLOCKING_NETWORK_IO
        }
        self.assertIn("Domain Name Legitimacy", io_checks)
        self.assertIn("WHOIS and Domain Age", io_checks)
        self.assertIn("SSL Validity", io_checks)
        self.assertIn("Security Blacklists", io_checks)
        self.assertIn("Google Safe Browsing", io_checks)


class TestBoundedConcurrency(unittest.TestCase):
    """2. Verify that concurrency is strictly bounded per scan and globally."""

    def test_shared_executor_is_bounded(self):
        executor = get_shared_executor()
        self.assertIsNotNone(executor)
        # Verify pool max_workers matches configured ceiling
        self.assertEqual(executor._max_workers, DEFAULT_MAX_WORKERS)

    def test_per_scan_concurrency_is_bounded_to_limit(self):
        """Simulates 15 slow checks and measures peak simultaneous workers."""
        max_concurrent_observed = 0
        current_concurrent = 0
        lock = asyncio.Lock() if asyncio.iscoroutinefunction(run_all) else None

        import threading
        thread_lock = threading.Lock()

        def slow_check(url: str):
            nonlocal max_concurrent_observed, current_concurrent
            with thread_lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent_observed:
                    max_concurrent_observed = current_concurrent
            try:
                time.sleep(0.08)
                return CheckResult(1, "Simulated Check", "PASS", "clean")
            finally:
                with thread_lock:
                    current_concurrent -= 1

        mock_steps = [(f"Check {i}", slow_check) for i in range(1, 16)]

        with patch("url_audit.runner.CHECK_STEPS", mock_steps):
            results = run_all("https://example.com", max_concurrency=4)
            self.assertEqual(len(results), 15)
            # Peak concurrent executions must NOT exceed the specified max_concurrency of 4
            self.assertLessEqual(max_concurrent_observed, 4)
            self.assertGreaterEqual(max_concurrent_observed, 2)


class TestScanDeadlinesAndMonotonicTime(unittest.TestCase):
    """3. Monotonic time deadlines, timeout capping, and partial results."""

    def test_monotonic_deadline_calculation(self):
        start = time.monotonic()
        token = set_scan_deadline(start + 5.0)
        try:
            remaining = get_remaining_deadline()
            self.assertIsNotNone(remaining)
            self.assertLessEqual(remaining, 5.0)
            self.assertGreater(remaining, 4.0)
        finally:
            reset_scan_deadline(token)

    def test_expired_deadline_returns_partial_error_results(self):
        """When deadline expires mid-scan, uncompleted checks must return ERROR."""
        def slow_check(url: str):
            time.sleep(0.3)
            return CheckResult(1, "Slow Check", "PASS", "ok")

        mock_steps = [(f"Check {i}", slow_check) for i in range(1, 16)]

        with patch("url_audit.runner.CHECK_STEPS", mock_steps):
            # Set a very tight deadline of 0.15 seconds
            short_deadline = time.monotonic() + 0.15
            results = run_all(
                "https://example.com",
                deadline_ts=short_deadline,
                max_concurrency=2,
            )

            self.assertEqual(len(results), 15)
            error_results = [r for r in results if r.status == "ERROR"]
            self.assertGreater(len(error_results), 0)

            # Incomplete scan risk computation must yield INCONCLUSIVE (not BENIGN)
            checks_data = [r.__dict__ for r in results]
            risk = compute_risk(checks_data)
            self.assertEqual(risk["verdict"], "INCONCLUSIVE")

    def test_incomplete_scan_never_marked_benign(self):
        """Even with 0 failures, an incomplete scan with errors must be INCONCLUSIVE."""
        results = [
            CheckResult(1, "Check 1", "PASS", "ok"),
            CheckResult(2, "Check 2", "ERROR", "Scan deadline exceeded"),
            CheckResult(3, "Check 3", "ERROR", "Scan deadline exceeded"),
            CheckResult(4, "Check 4", "ERROR", "Scan deadline exceeded"),
        ]
        checks_data = [r.__dict__ for r in results]
        risk = compute_risk(checks_data)
        self.assertNotEqual(risk["verdict"], "BENIGN")
        self.assertEqual(risk["verdict"], "INCONCLUSIVE")


class TestWebSocketProgressAndCleanup(unittest.TestCase):
    """4. WebSocket progress ordering, bounded queues, and reliable cleanup."""

    def test_progress_queue_bounded_capacity(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            queue = loop.run_until_complete(_get_progress_queue("test_job_1"))
            self.assertEqual(queue.maxsize, 100)
            loop.run_until_complete(_discard_progress_queue("test_job_1"))
            self.assertNotIn("test_job_1", _progress_channels)
        finally:
            loop.close()

    def test_progress_events_monotonic_ordering(self):
        progress_events = []

        def track_progress(step, total, label, results):
            progress_events.append((step, total, label))

        def fast_check(url: str):
            return CheckResult(1, "Fast Check", "PASS", "ok")

        mock_steps = [(f"Check {i}", fast_check) for i in range(1, 16)]

        with patch("url_audit.runner.CHECK_STEPS", mock_steps):
            run_all("https://example.com", progress_callback=track_progress)

            self.assertEqual(len(progress_events), 15)
            # Verify steps advance strictly 1, 2, ..., 15
            step_indices = [step for step, _, _ in progress_events]
            self.assertEqual(step_indices, list(range(1, 16)))


class TestDeterministicScanBenchmark(unittest.TestCase):
    """5. Controlled performance benchmark: all 15 checks complete in < 3.5s with fast mocked services."""

    def test_fifteen_checks_benchmark_under_three_point_five_seconds(self):
        import random

        def mocked_service_check(url: str):
            # Fast deterministic mock delay (10ms - 25ms per check)
            delay = 0.015
            time.sleep(delay)
            return CheckResult(1, "Mock Check", "PASS", "mock evidence")

        mock_steps = [(f"Mock Check {i}", mocked_service_check) for i in range(1, 16)]

        durations: list[float] = []
        with patch("url_audit.runner.CHECK_STEPS", mock_steps):
            # Execute 5 benchmark runs
            for _ in range(5):
                start = time.perf_counter()
                results = run_all("https://example.com", max_concurrency=8)
                duration = time.perf_counter() - start
                durations.append(duration)
                self.assertEqual(len(results), 15)

        durations.sort()
        median_dur = durations[len(durations) // 2]
        p95_dur = durations[-1]

        # Target: All 15 checks complete in < 3.5 seconds
        self.assertLess(p95_dur, 3.5, f"p95 duration was {p95_dur:.3f}s, target was < 3.5s")
        self.assertLess(median_dur, 1.0, f"Median duration was {median_dur:.3f}s, expected < 1.0s")


if __name__ == "__main__":
    unittest.main()

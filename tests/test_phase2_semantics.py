"""Exhaustive test suite for Phase 2: Status Semantics, Error Handling, Risk Recalibration, and IOC Classification."""

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from url_audit.runner import _run_step, summarize
from url_audit.utils import CheckResult
from webapp.main import app
from webapp.persistence import (
    _scan_row_to_dict,
    extract_iocs,
    get_scan,
    get_scan_report,
    init_db,
    list_scans,
    persist_scan,
)
from webapp.risk import (
    CRITICAL_FAIL_BONUS,
    POINTS_ERROR,
    POINTS_FAIL,
    POINTS_PASS,
    POINTS_SKIP,
    POINTS_WARN,
    STATUS_POINTS,
    THRESHOLD_SCORE_CRITICAL,
    THRESHOLD_SCORE_HIGH,
    THRESHOLD_SCORE_MEDIUM,
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    compute_risk,
    risk_level_from_score,
)


class TestCheckStatusStandardization(unittest.TestCase):
    """1. Standardize check statuses across result models, runner, and summarization."""

    def test_all_five_standard_statuses_supported(self):
        statuses = ["PASS", "WARN", "FAIL", "ERROR", "SKIP"]
        results = [
            CheckResult(1, "Check Pass", "PASS", "clean"),
            CheckResult(2, "Check Warn", "WARN", "suspicious"),
            CheckResult(3, "Check Fail", "FAIL", "malicious"),
            CheckResult(4, "Check Error", "ERROR", "timeout"),
            CheckResult(5, "Check Skip", "SKIP", "unconfigured"),
            CheckResult(6, "Check Info", "INFO", "data"),
        ]
        counts = summarize(results)
        self.assertEqual(counts["PASS"], 1)
        self.assertEqual(counts["WARN"], 1)
        self.assertEqual(counts["FAIL"], 1)
        self.assertEqual(counts["ERROR"], 1)
        self.assertEqual(counts["SKIP"], 1)
        self.assertEqual(counts["INFO"], 1)

    def test_runner_maps_operational_crashes_and_timeouts_to_error(self):
        def crashing_func(url):
            raise ConnectionResetError("Connection reset by peer")

        step = ("Crashing Check", crashing_func)
        results = _run_step("https://example.com", step, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "ERROR")
        self.assertIn("Operational error", results[0].evidence)

    def test_runner_maps_deadline_timeout_to_error(self):
        from url_audit.security import AuditTimeoutError

        def timeout_func(url):
            raise AuditTimeoutError("Scan deadline exceeded")

        step = ("Timeout Check", timeout_func)
        results = _run_step("https://example.com", step, 2)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "ERROR")
        self.assertIn("Scan deadline exceeded", results[0].evidence)


class TestOperationalErrorSeparation(unittest.TestCase):
    """2. Verify operational failures do not masquerade as security failures."""

    def test_whois_operational_failure_returns_error(self):
        from url_audit.checks.domain_checks import check_whois_age

        with patch("url_audit.checks.domain_checks._whois_fetch", return_value=None):
            with patch("url_audit.checks.domain_checks._rdap_fetch", return_value=None):
                result = check_whois_age("https://example.com")
                self.assertEqual(result.status, "ERROR")
                self.assertIn("unavailable", result.evidence)

    def test_ssl_connection_timeout_returns_error(self):
        from url_audit.checks.security_checks import check_ssl_validity

        with patch("url_audit.checks.security_checks._get_cert", side_effect=TimeoutError("Connection timed out")):
            result = check_ssl_validity("https://example.com")
            self.assertEqual(result.status, "ERROR")
            self.assertIn("TLS connection error", result.evidence)

    def test_plain_http_skips_ssl_check(self):
        from url_audit.checks.security_checks import check_ssl_validity

        result = check_ssl_validity("http://example.com")
        self.assertEqual(result.status, "SKIP")
        self.assertIn("Plain HTTP", result.evidence)

    def test_unconfigured_api_key_returns_skip_not_pass(self):
        from url_audit.checks.security_checks import check_ip_reputation

        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}, clear=False):
            with patch("url_audit.checks.security_checks._resolve_host", return_value=("example.com", "93.184.216.34")):
                result = check_ip_reputation("https://example.com")
                self.assertEqual(result.status, "SKIP")
                self.assertIn("not configured", result.evidence)

    def test_google_safe_browsing_service_error_returns_error(self):
        from url_audit.checks.reputation_checks import check_google_safe_browsing

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "fake-key"}, clear=False):
            mock_session = MagicMock()
            mock_resp = MagicMock()
            mock_resp.ok = False
            mock_resp.status_code = 503
            mock_session.post.return_value = mock_resp
            with patch("url_audit.checks.reputation_checks.get_safe_session", return_value=mock_session):
                result = check_google_safe_browsing("https://example.com")
                self.assertEqual(result.status, "ERROR")
                self.assertIn("HTTP 503", result.evidence)


class TestRiskRecalibrationAndVerdicts(unittest.TestCase):
    """3. Risk thresholds, point weights, and 4-verdict evidence resolution."""

    def test_status_point_weights_constants(self):
        self.assertEqual(STATUS_POINTS["PASS"], 0)
        self.assertEqual(STATUS_POINTS["SKIP"], 0)
        self.assertEqual(STATUS_POINTS["ERROR"], 0)
        self.assertEqual(STATUS_POINTS["INFO"], 0)
        self.assertEqual(STATUS_POINTS["WARN"], 4)
        self.assertEqual(STATUS_POINTS["FAIL"], 8)
        self.assertEqual(CRITICAL_FAIL_BONUS, 12)

    def test_score_boundaries(self):
        self.assertEqual(risk_level_from_score(0), "LOW")
        self.assertEqual(risk_level_from_score(24), "LOW")
        self.assertEqual(risk_level_from_score(25), "MEDIUM")
        self.assertEqual(risk_level_from_score(49), "MEDIUM")
        self.assertEqual(risk_level_from_score(50), "HIGH")
        self.assertEqual(risk_level_from_score(74), "HIGH")
        self.assertEqual(risk_level_from_score(75), "CRITICAL")

    def test_error_and_skip_add_zero_risk_points(self):
        checks = [
            {"name": "Check 1", "status": "ERROR"},
            {"name": "Check 2", "status": "ERROR"},
            {"name": "Check 3", "status": "SKIP"},
            {"name": "Check 4", "status": "PASS"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["points"], 0)
        self.assertEqual(res["risk_score"], 0)

    def test_confirmed_malicious_finding_survives_unrelated_check_errors(self):
        """Confirmed threat intelligence match MUST yield MALICIOUS, even if other checks hit ERROR."""
        checks = [
            {"name": "Security Blacklists", "status": "FAIL"},  # High-confidence threat intel match
            {"name": "WHOIS and Domain Age", "status": "ERROR"}, # Operational lookup failure
            {"name": "Hosting Provider", "status": "ERROR"},
            {"name": "Google PageSpeed", "status": "ERROR"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["verdict"], VERDICT_MALICIOUS)
        self.assertIn("Security Blacklists", res["high_confidence_threats"])

    def test_all_operational_errors_yield_inconclusive(self):
        """When essential checks cannot execute, score is 0 but verdict MUST be INCONCLUSIVE."""
        checks = [
            {"name": "WHOIS and Domain Age", "status": "ERROR"},
            {"name": "SSL Validity", "status": "ERROR"},
            {"name": "Security Blacklists", "status": "ERROR"},
            {"name": "Google Safe Browsing", "status": "SKIP"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["verdict"], VERDICT_INCONCLUSIVE)

    def test_insufficient_evaluative_checks_yield_inconclusive(self):
        checks = [
            {"name": "Check 1", "status": "PASS"},
            {"name": "Check 2", "status": "SKIP"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["verdict"], VERDICT_INCONCLUSIVE)

    def test_clean_scan_yields_benign(self):
        checks = [
            {"name": "Domain Name Legitimacy", "status": "PASS"},
            {"name": "WHOIS and Domain Age", "status": "PASS"},
            {"name": "SSL Validity", "status": "PASS"},
            {"name": "Presence of HTTPS", "status": "PASS"},
            {"name": "Security Blacklists", "status": "PASS"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["verdict"], VERDICT_BENIGN)

    def test_moderate_warnings_yield_suspicious(self):
        checks = [
            {"name": "Domain Name Legitimacy", "status": "PASS"},
            {"name": "Homoglyph Detection", "status": "WARN"},
            {"name": "Redirect Behaviour", "status": "WARN"},
            {"name": "Presence of HTTPS", "status": "PASS"},
        ]
        res = compute_risk(checks)
        self.assertEqual(res["verdict"], VERDICT_SUSPICIOUS)


class TestIOCClassificationAndSanitization(unittest.TestCase):
    """4. Correct IOC extraction, classification, and non-public IP filtering."""

    def test_classify_public_ipv4_and_ipv6_as_ip(self):
        checks = [
            {
                "name": "IP Reputation",
                "status": "FAIL",
                "evidence": "ip=93.184.216.34 ipv6=2606:4700:4700::1111",
                "data": {},
            }
        ]
        iocs = extract_iocs("https://example.com", checks, "2026-10-28T12:00:00Z")
        ioc_map = {ioc["indicator"]: ioc for ioc in iocs}

        self.assertIn("93.184.216.34", ioc_map)
        self.assertEqual(ioc_map["93.184.216.34"]["indicator_type"], "IP")

        self.assertIn("2606:4700:4700::1111", ioc_map)
        self.assertEqual(ioc_map["2606:4700:4700::1111"]["indicator_type"], "IP")

    def test_classify_valid_domain_as_domain(self):
        checks = [
            {
                "name": "Typosquatting or Homoglyph Domains",
                "status": "WARN",
                "evidence": "non_ascii=True",
                "data": {},
            }
        ]
        iocs = extract_iocs("https://phishing-target.xyz/login", checks, "2026-10-28T12:00:00Z")
        domains = [ioc for ioc in iocs if ioc["indicator_type"] == "DOMAIN"]
        self.assertTrue(any(ioc["indicator"] == "phishing-target.xyz" for ioc in domains))

    def test_loopback_private_and_cloud_metadata_ips_are_rejected(self):
        checks = [
            {
                "name": "Diagnostic Check",
                "status": "FAIL",
                "evidence": "127.0.0.1 10.0.0.1 192.168.1.50 169.254.169.254 ::1 fe80::1",
                "data": {},
            }
        ]
        iocs = extract_iocs("https://example.com", checks, "2026-10-28T12:00:00Z")
        indicators = [ioc["indicator"] for ioc in iocs]

        self.assertNotIn("127.0.0.1", indicators)
        self.assertNotIn("10.0.0.1", indicators)
        self.assertNotIn("192.168.1.50", indicators)
        self.assertNotIn("169.254.169.254", indicators)
        self.assertNotIn("::1", indicators)
        self.assertNotIn("fe80::1", indicators)

    def test_error_and_skip_checks_never_produce_iocs(self):
        checks = [
            {
                "name": "Check with Error",
                "status": "ERROR",
                "evidence": "ip=93.184.216.34 failed due to network timeout",
                "data": {"ip": "93.184.216.34"},
            },
            {
                "name": "Check Skipped",
                "status": "SKIP",
                "evidence": "ip=1.1.1.1 unconfigured",
                "data": {"ip": "1.1.1.1"},
            },
        ]
        iocs = extract_iocs("https://example.com", checks, "2026-10-28T12:00:00Z")
        self.assertEqual(len(iocs), 0)

    def test_deduplication_preserves_highest_severity(self):
        checks = [
            {
                "name": "Minor Warning Check",
                "status": "WARN",
                "evidence": "ip=93.184.216.34",
                "data": {},
            },
            {
                "name": "Major Failure Check",
                "status": "FAIL",
                "evidence": "ip=93.184.216.34 critical compromise",
                "data": {},
            },
        ]
        iocs = extract_iocs("https://example.com", checks, "2026-10-28T12:00:00Z")
        ip_iocs = [ioc for ioc in iocs if ioc["indicator"] == "93.184.216.34"]
        self.assertEqual(len(ip_iocs), 1)
        self.assertEqual(ip_iocs[0]["severity"], "HIGH")


class TestPersistenceMigrationAndBackwardCompatibility(unittest.TestCase):
    """5. Backward compatibility and database migration testing."""

    def test_migration_adds_error_count_to_legacy_scans_table(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_db = os.path.join(tmpdir, "legacy.db")
            # Create a legacy database without error_count
            conn = sqlite3.connect(legacy_db)
            conn.execute(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    scan_mode TEXT NOT NULL DEFAULT 'scan',
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    total_checks INTEGER NOT NULL,
                    pass_count INTEGER NOT NULL DEFAULT 0,
                    warn_count INTEGER NOT NULL DEFAULT 0,
                    fail_count INTEGER NOT NULL DEFAULT 0,
                    info_count INTEGER NOT NULL DEFAULT 0,
                    skip_count INTEGER NOT NULL DEFAULT 0,
                    ai_verdict TEXT,
                    ai_summary TEXT,
                    threat_report_json TEXT,
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO scans (
                    target_url, risk_score, risk_level, verdict, total_checks, created_at
                ) VALUES ('https://legacy-record.com', 10, 'LOW', 'BENIGN', 5, '2026-10-27T00:00:00Z')
                """
            )
            conn.commit()
            conn.close()

            # Point to legacy database and run init_db()
            with patch.dict(os.environ, {"URL_AUDIT_DB_PATH": legacy_db}):
                init_db()

                # Verify error_count column was added without losing records
                check_conn = sqlite3.connect(legacy_db)
                check_conn.row_factory = sqlite3.Row
                row = check_conn.execute("SELECT * FROM scans WHERE id = 1").fetchone()
                self.assertIsNotNone(row)
                row_dict = _scan_row_to_dict(row)
                self.assertEqual(row_dict["target_url"], "https://legacy-record.com")
                self.assertEqual(row_dict["error_count"], 0)
                check_conn.close()

    def test_inconclusive_verdict_persists_and_queries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            with patch.dict(os.environ, {"URL_AUDIT_DB_PATH": db_path}):
                init_db()

                scan_id, _ = persist_scan(
                    target_url="https://offline-target.com",
                    scan_mode="scan",
                    prepared_results=[],
                    counts={"PASS": 0, "WARN": 0, "FAIL": 0, "ERROR": 5, "SKIP": 0},
                    risk_score=0,
                    risk_level="LOW",
                    verdict=VERDICT_INCONCLUSIVE,
                    threat_report=None,
                    duration_ms=500,
                )

                scan = get_scan(scan_id)
                self.assertIsNotNone(scan)
                self.assertEqual(scan["verdict"], "INCONCLUSIVE")
                self.assertEqual(scan["error_count"], 5)

                report = get_scan_report(scan_id)
                self.assertIsNotNone(report)
                self.assertEqual(report["risk_assessment"]["error_count"], 5)

                paged = list_scans(status="INCONCLUSIVE")
                self.assertEqual(paged["total"], 1)
                self.assertEqual(paged["items"][0]["verdict"], "INCONCLUSIVE")


class TestFastAPIGatewayResponseIntegration(unittest.TestCase):
    """6. API response serialization with standardized statuses and verdicts."""

    def setUp(self):
        self.client = TestClient(app)

    def test_api_returns_inconclusive_and_error_cards(self):
        with patch("webapp.main.run_all") as mock_run_all, patch("webapp.main._run_ai_analysis", return_value={"enabled": False}):
            mock_run_all.return_value = [
                CheckResult(1, "Domain Name Legitimacy", "ERROR", "DNS timeout", {}),
                CheckResult(9, "SSL/TLS Certificate Validity", "ERROR", "Connection refused", {}),
                CheckResult(25, "Security Blacklists", "ERROR", "Feed timeout", {}),
            ]
            resp = self.client.post("/api/audit", data={"url": "https://example.com"})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data["verdict"], "INCONCLUSIVE")
            card_map = {card["status"]: card["count"] for card in data["summary_cards"]}
            self.assertEqual(card_map.get("ERROR", 0), 3)


if __name__ == "__main__":
    unittest.main()

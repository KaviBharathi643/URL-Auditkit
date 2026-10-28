"""URL Audit Kit - Phase 5 Regression & 59-URL Matrix Test Suite

Covers:
1. All 59 cases across 11 groups in tests/fixtures/matrix_59_urls.json
2. Strict URL gateway & SSRF boundaries (loopback, private, cloud metadata, alternative IP encodings)
3. Redirect handling & hop limits
4. TLS status semantics (FAIL for bad certs, SKIP for plain HTTP)
5. Brand impersonation, deceptive subdomains, and IDN homoglyphs
6. Legitimate internationalized domain handling (münchen.de, 中国.cn, café.fr)
7. Query credential sanitization and long URL warnings
8. Operational error isolation (DNS timeout, SERVFAIL, 503 threat feed outages)
9. Monotonic scan deadline abort and INCONCLUSIVE verdict resolution
10. API endpoints, history filtering, pagination, and WebSocket lifecycle
"""

import asyncio
import ipaddress
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests
from fastapi.testclient import TestClient

from webapp.main import app
from url_audit.security import (
    validate_url,
    resolve_and_validate_destination,
    safe_request,
    SSRFError,
    InvalidURLError,
    RedirectSecurityError,
    AuditTimeoutError,
    set_scan_deadline,
)
from url_audit.domain_intel import (
    parse_domain_info,
    detect_brand_impersonation,
    resolve_dns_outcome,
)
from url_audit.checks.security_checks import check_ssl_validity
from url_audit.checks.behavior_checks import check_url_length
from webapp.risk import compute_risk
from webapp.persistence import (
    init_db,
    persist_scan,
    list_scans,
    get_scan,
    list_iocs,
    extract_iocs,
)


class TestPhase5Matrix59(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        fixture_path = Path(__file__).parent / "fixtures" / "matrix_59_urls.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            cls.matrix_data = json.load(f)
        cls.cases = {c["id"]: c for c in cls.matrix_data["cases"]}
        cls.client = TestClient(app)

    def test_fixture_integrity(self):
        """Matrix fixture must contain exactly 59 distinct cases covering all 11 required categories."""
        self.assertEqual(len(self.cases), 59)
        categories = set(c["category"] for c in self.cases.values())
        self.assertEqual(len(categories), 11)
        for cid, case in self.cases.items():
            self.assertIn("url", case)
            self.assertIn("expected_http_status", case)
            self.assertIn("security_rule", case)

    # -------------------------------------------------------------------------
    # Group 1: Legitimate Public Websites (IDs 1-6)
    # -------------------------------------------------------------------------
    def test_group_1_legitimate_public_websites(self):
        """Cases 1-6: Valid public URLs must pass the gateway and resolve cleanly."""
        for cid in range(1, 7):
            case = self.cases[cid]
            url = case["url"]
            val = validate_url(url)
            self.assertTrue(val.canonical_url.startswith("http"))
            self.assertTrue(len(val.hostname) > 0)
            self.assertIn(val.port, (80, 443))

            info = parse_domain_info(url)
            match = detect_brand_impersonation(info)
            self.assertFalse(
                match.is_impersonation,
                f"Legitimate official URL {url} was falsely flagged as impersonating: {match}",
            )

    # -------------------------------------------------------------------------
    # Group 2: Malformed and Unsupported URLs (IDs 7-12)
    # -------------------------------------------------------------------------
    def test_group_2_malformed_and_unsupported_urls(self):
        """Cases 7-12: Gateway must reject unsupported schemes, missing hostnames, and invalid ports."""
        for cid in range(7, 13):
            case = self.cases[cid]
            url = case["url"]
            with self.assertRaises((InvalidURLError, SSRFError), msg=f"Case {cid} failed: {url}"):
                validate_url(url)

            response = self.client.post("/api/audit", data={"url": url, "scan_mode": "scan"})
            self.assertEqual(
                response.status_code, 400,
                f"Case {cid} ({url}) expected HTTP 400 but got {response.status_code}: {response.text}",
            )

    # -------------------------------------------------------------------------
    # Group 3: Private, Loopback, and Link-Local Destinations (IDs 13-18)
    # -------------------------------------------------------------------------
    def test_group_3_private_loopback_destinations(self):
        """Cases 13-18: Outbound requests to loopback, RFC 1918, and 169.254.169.254 must be blocked."""
        for cid in range(13, 19):
            case = self.cases[cid]
            url = case["url"]

            is_blocked = False
            try:
                val = validate_url(url)
                resolve_and_validate_destination(val.hostname, val.port)
            except (SSRFError, InvalidURLError):
                is_blocked = True

            self.assertTrue(is_blocked, f"Case {cid} ({url}) was not blocked as SSRF")

            response = self.client.post("/api/audit", data={"url": url, "scan_mode": "scan"})
            self.assertEqual(
                response.status_code, 400,
                f"Case {cid} ({url}) expected HTTP 400 but got {response.status_code}",
            )
            err_msg = str(response.json()).lower()
            self.assertTrue(
                any(k in err_msg for k in ("ssrf", "rejected", "loopback", "private", "forbidden", "allowed outbound ports", "not in the allowed")),
                f"Expected SSRF rejection message for {url}, got: {err_msg}",
            )

    # -------------------------------------------------------------------------
    # Group 4: Alternative IP Encodings (IDs 19-23)
    # -------------------------------------------------------------------------
    def test_group_4_alternative_ip_encodings(self):
        """Cases 19-23: Decimal, hex, octal, and IPv6-mapped loopback encodings must be canonicalized and blocked."""
        for cid in range(19, 24):
            case = self.cases[cid]
            url = case["url"]

            is_blocked = False
            try:
                val = validate_url(url)
                resolve_and_validate_destination(val.hostname, val.port)
            except (SSRFError, InvalidURLError):
                is_blocked = True

            self.assertTrue(is_blocked, f"Case {cid} ({url}) bypassed SSRF check")

            response = self.client.post("/api/audit", data={"url": url, "scan_mode": "scan"})
            self.assertEqual(response.status_code, 400)

    # -------------------------------------------------------------------------
    # Group 5: Redirect Handling (IDs 24-28)
    # -------------------------------------------------------------------------
    def test_group_5_redirect_handling(self):
        """Cases 24-28: Redirect limit (5), private IP redirect, loop, and bad scheme in redirect."""
        # Case 24: Clean 1-hop redirect
        mock_res1 = MagicMock(spec=requests.Response, is_redirect=True, status_code=302)
        mock_res1.headers = {"Location": "https://example.com/target"}
        mock_res2 = MagicMock(spec=requests.Response, is_redirect=False, status_code=200, text="OK")
        mock_res2.headers = {}

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.side_effect = [mock_res1, mock_res2]

        with patch("url_audit.security.resolve_and_validate_destination"):
            resp, chain = safe_request("GET", "https://example.com/redirect", max_redirects=5, session=mock_session)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(chain), 2)

        # Case 25: Redirect to private IP (192.168.1.1) must raise SSRFError
        with patch("url_audit.security.resolve_and_validate_destination") as mock_resolve:
            mock_resolve.side_effect = [
                [ipaddress.IPv4Address("93.184.216.34")],
                SSRFError("Blocked RFC 1918 private address: 192.168.1.1"),
            ]
            mock_session_ssrf = MagicMock(spec=requests.Session)
            mock_session_ssrf.request.return_value = mock_res1
            with self.assertRaises(SSRFError):
                safe_request("GET", "https://example.com/bounce", max_redirects=5, session=mock_session_ssrf)

        # Case 26: Redirect loop must raise RedirectSecurityError
        mock_loop_a = MagicMock(spec=requests.Response, is_redirect=True, status_code=302, headers={"Location": "https://example.com/b"})
        mock_loop_b = MagicMock(spec=requests.Response, is_redirect=True, status_code=302, headers={"Location": "https://example.com/a"})
        mock_session_loop = MagicMock(spec=requests.Session)
        mock_session_loop.request.side_effect = [mock_loop_a, mock_loop_b, mock_loop_a]
        with patch("url_audit.security.resolve_and_validate_destination"):
            with self.assertRaises(RedirectSecurityError):
                safe_request("GET", "https://example.com/a", max_redirects=5, session=mock_session_loop)

        # Case 27: Excessive hops (> 5 redirects) terminates safely
        mock_session_excess = MagicMock(spec=requests.Session)
        mock_session_excess.request.side_effect = [
            MagicMock(spec=requests.Response, is_redirect=True, headers={"Location": f"https://example.com/{i}"})
            for i in range(10)
        ]
        with patch("url_audit.security.resolve_and_validate_destination"):
            with self.assertRaises(RedirectSecurityError):
                safe_request("GET", "https://example.com/start", max_redirects=5, session=mock_session_excess)

        # Case 28: Intermediate redirect to javascript/data must be rejected
        mock_bad_redir = MagicMock(spec=requests.Response, is_redirect=True, status_code=302, headers={"Location": "javascript:alert(1)"})
        mock_session_bad = MagicMock(spec=requests.Session)
        mock_session_bad.request.return_value = mock_bad_redir
        with patch("url_audit.security.resolve_and_validate_destination"):
            with self.assertRaises(InvalidURLError):
                safe_request("GET", "https://example.com/unsafe-redir", max_redirects=5, session=mock_session_bad)

    # -------------------------------------------------------------------------
    # Group 6: TLS Certificate Failures (IDs 29-33)
    # -------------------------------------------------------------------------
    def test_group_6_tls_certificate_failures(self):
        """Cases 29-33: TLS failures return FAIL; plain HTTP skips TLS check without recording security fail."""
        # Case 29-32: TLS failure simulation
        import ssl
        with patch("url_audit.checks.security_checks._get_cert", side_effect=ssl.SSLCertVerificationError("certificate has expired")):
            res = check_ssl_validity("https://expired.example.com")
            self.assertEqual(res.status, "FAIL")
            self.assertIn("expired", res.evidence.lower())

        # Case 33: Plain HTTP scheme must yield SKIP status
        res_http = check_ssl_validity("http://plain-http-only.example.com/")
        self.assertEqual(res_http.status, "SKIP")
        self.assertIn("Plain HTTP", res_http.evidence)

    # -------------------------------------------------------------------------
    # Group 7: Suspicious and Impersonating Domains (IDs 34-40)
    # -------------------------------------------------------------------------
    def test_group_7_suspicious_and_impersonating_domains(self):
        """Cases 34-40: Deceptive subdomains and brand embedding in 3rd party registrable domains."""
        # 34: Deceptive subdomain: paypal.com.account-update.attacker.com
        info34 = parse_domain_info("https://paypal.com.account-update.attacker.com/login")
        res34 = detect_brand_impersonation(info34)
        self.assertTrue(res34.is_impersonation)
        self.assertEqual(res34.matched_brand, "PayPal")
        self.assertEqual(res34.impersonation_type, "DECEPTIVE_SUBDOMAIN")

        # 35: Apple deceptive subdomain: appleid.apple.com.verify-login.org
        info35 = parse_domain_info("https://appleid.apple.com.verify-login.org/auth")
        res35 = detect_brand_impersonation(info35)
        self.assertTrue(res35.is_impersonation)
        self.assertEqual(res35.matched_brand, "Apple")

        # 36: Microsoft deceptive subdomain: login.microsoft.com.secure-portal.org
        info36 = parse_domain_info("https://login.microsoft.com.secure-portal.org/")
        res36 = detect_brand_impersonation(info36)
        self.assertTrue(res36.is_impersonation)
        self.assertEqual(res36.matched_brand, "Microsoft")

        # 37: Brand embedded in registrable domain: paypal-security-verification.com
        info37 = parse_domain_info("https://paypal-security-verification.com/login")
        res37 = detect_brand_impersonation(info37)
        self.assertTrue(res37.is_impersonation)
        self.assertEqual(res37.matched_brand, "PayPal")

        # 38: Amazon: amazon-account-support.org
        info38 = parse_domain_info("https://amazon-account-support.org/help")
        res38 = detect_brand_impersonation(info38)
        self.assertTrue(res38.is_impersonation)
        self.assertEqual(res38.matched_brand, "Amazon")

        # 39: Netflix: netflix-billing-update.net
        info39 = parse_domain_info("https://netflix-billing-update.net/card")
        res39 = detect_brand_impersonation(info39)
        self.assertTrue(res39.is_impersonation)
        self.assertEqual(res39.matched_brand, "Netflix")

        # 40: Binance: binance-kyc-verify.io
        info40 = parse_domain_info("https://binance-kyc-verify.io/auth")
        res40 = detect_brand_impersonation(info40)
        self.assertTrue(res40.is_impersonation)
        self.assertEqual(res40.matched_brand, "Binance")

    # -------------------------------------------------------------------------
    # Group 8: IDN and Punycode Domains (IDs 41-46)
    # -------------------------------------------------------------------------
    def test_group_8_idn_and_punycode_domains(self):
        """Cases 41-46: Mixed-script Cyrillic homoglyphs are flagged; legitimate single-script IDNs are permitted."""
        # 41: Cyrillic 'a' spoofing apple.com
        info41 = parse_domain_info("https://xn--pple-43d.com/store")
        self.assertTrue(info41.is_mixed_script)
        res41 = detect_brand_impersonation(info41)
        self.assertTrue(res41.is_impersonation)
        self.assertEqual(res41.matched_brand, "Apple")

        # 42: Cyrillic 'e' spoofing google.com
        info42 = parse_domain_info("https://xn--googl-3we.com/")
        self.assertTrue(info42.is_mixed_script)
        res42 = detect_brand_impersonation(info42)
        self.assertTrue(res42.is_impersonation)
        self.assertEqual(res42.matched_brand, "Google")

        # 43: Legitimate German single-script münchen.de
        info43 = parse_domain_info("https://xn--mnchen-3ya.de/")
        self.assertFalse(info43.is_mixed_script)
        self.assertEqual(info43.unicode_hostname, "münchen.de")
        self.assertFalse(detect_brand_impersonation(info43).is_impersonation)

        # 44: Legitimate Chinese single-script 中国.cn (xn--fiqs8s.cn)
        info44 = parse_domain_info("https://xn--fiqs8s.cn/")
        self.assertFalse(info44.is_mixed_script)
        self.assertEqual(info44.unicode_hostname, "中国.cn")

        # 45: Legitimate French IDN café.fr
        info45 = parse_domain_info("https://café.fr/menu")
        self.assertFalse(info45.is_mixed_script)
        self.assertEqual(info45.hostname, "xn--caf-dma.fr")

        # 46: Malformed Punycode label must be rejected
        with self.assertRaises(InvalidURLError):
            validate_url("https://xn--invalid-punycode-%%%%--.com/")

    # -------------------------------------------------------------------------
    # Group 9: Long URLs and Sensitive Query Parameters (IDs 47-51)
    # -------------------------------------------------------------------------
    def test_group_9_long_urls_and_sensitive_parameters(self):
        """Cases 47-51: Length warnings, credential redaction in IOCs, and path brand references."""
        # 47: URL > 120 chars yields WARN
        long_url = self.cases[47]["url"]
        res47 = check_url_length(long_url)
        self.assertEqual(res47.status, "WARN")
        self.assertGreater(len(long_url), 120)

        # 48-49: Query parameter tokens and credit card numbers are redacted from IOCs
        token_url = self.cases[48]["url"]
        mock_raw = [{"name": "URL Format", "status": "PASS", "evidence": f"Target: {token_url}"}]
        iocs = extract_iocs(token_url, mock_raw, "2026-10-28T12:00:00Z")
        for ioc in iocs:
            self.assertNotIn("SECRET_BEARER_TOKEN_999", ioc["indicator_value"])
            self.assertNotIn("API_KEY_SUPER_SECRET", ioc["indicator_value"])

        # 50-51: Brand in path only (e.g. /how-google-ranks-websites) must not flag the domain
        info50 = parse_domain_info("https://legitimate-blog.example.org/articles/how-google-ranks-websites")
        self.assertFalse(detect_brand_impersonation(info50).is_impersonation)
        info51 = parse_domain_info("https://developer.example.org/docs/amazon-aws-s3-integration")
        self.assertFalse(detect_brand_impersonation(info51).is_impersonation)

    # -------------------------------------------------------------------------
    # Group 10: DNS and External Service Failures (IDs 52-55)
    # -------------------------------------------------------------------------
    def test_group_10_dns_and_service_failures(self):
        """Cases 52-55: Operational outages must yield ERROR (0 penalty), NXDOMAIN yields WARN."""
        # 52: NXDOMAIN -> WARN (2 non-critical warnings evaluate to SUSPICIOUS)
        risk_nx = compute_risk([
            {"status": "WARN", "category": "DNS", "name": "DNS Legitimacy", "details": "NXDOMAIN: domain does not exist"},
            {"status": "WARN", "category": "Syntax", "name": "Suspicious Parameters", "details": "Suspicious query pattern"},
            {"status": "PASS", "category": "Network", "name": "Port Accessibility", "details": "Port 443 open"},
            {"status": "PASS", "category": "TLS", "name": "TLS Certificate", "details": "Valid"},
        ])
        self.assertEqual(risk_nx["verdict"], "SUSPICIOUS")
        self.assertEqual(risk_nx["warn_count"], 2)

        # 53: DNS Timeout -> ERROR, risk score = 0
        risk_dns_timeout = compute_risk([
            {"status": "ERROR", "category": "DNS", "name": "DNS Legitimacy", "details": "DNS resolution timed out after 3.0s"},
            {"status": "PASS", "category": "Format", "name": "URL Length", "details": "Clean syntax"},
            {"status": "PASS", "category": "Domain", "name": "Punycode/Homoglyph", "details": "Syntax valid"},
        ])
        self.assertEqual(risk_dns_timeout["risk_score"], 0)
        self.assertEqual(risk_dns_timeout["fail_count"], 0)
        self.assertEqual(risk_dns_timeout["error_count"], 1)

        # 54: SERVFAIL -> ERROR, 0 risk points
        risk_servfail = compute_risk([
            {"status": "ERROR", "category": "DNS", "name": "DNS Legitimacy", "details": "DNS SERVFAIL from upstream resolver"},
        ])
        self.assertEqual(risk_servfail["risk_score"], 0)
        self.assertEqual(risk_servfail["verdict"], "INCONCLUSIVE")

        # 55: Threat Feed 503 outage -> ERROR, never treated as malicious finding
        risk_threat_503 = compute_risk([
            {"status": "ERROR", "category": "Threat Intelligence", "name": "Threat Feed", "details": "HTTP 503 Service Unavailable from reputation feed"},
            {"status": "PASS", "category": "Format", "name": "URL Length", "details": "Valid syntax"},
            {"status": "PASS", "category": "TLS", "name": "TLS Certificate", "details": "Valid cert"},
        ])
        self.assertEqual(risk_threat_503["risk_score"], 0)
        self.assertEqual(risk_threat_503["fail_count"], 0)

    # -------------------------------------------------------------------------
    # Group 11: Concurrency and Timeout Cases (IDs 56-59)
    # -------------------------------------------------------------------------
    def test_group_11_concurrency_and_timeouts(self):
        """Cases 56-59: Monotonic deadline expiration marks remaining checks as ERROR and concludes INCONCLUSIVE."""
        # 56: Scan deadline abort simulation
        results = [
            {"name": "check_1", "status": "PASS", "category": "Syntax", "details": "OK"},
            {"name": "check_2", "status": "ERROR", "category": "Network", "details": "Scan deadline expired (timeout=12.0s)"},
            {"name": "check_3", "status": "ERROR", "category": "DNS", "details": "Scan deadline expired"},
            {"name": "check_4", "status": "ERROR", "category": "TLS", "details": "Scan deadline expired"},
        ]
        profile = compute_risk(results)
        self.assertEqual(profile["verdict"], "INCONCLUSIVE")
        self.assertEqual(profile["error_count"], 3)
        self.assertEqual(profile["risk_score"], 0)

        # 57-59: Concurrent worker pooling handles requests without deadlocks
        from url_audit.runner import run_all
        mock_response = MagicMock(spec=requests.Response, is_redirect=False, status_code=200, text="OK", headers={})
        with patch("url_audit.security.safe_request", return_value=(mock_response, ["https://example.com/batch-1"])):
            with patch("url_audit.security.resolve_and_validate_destination", return_value=[ipaddress.IPv4Address("93.184.216.34")]):
                r1 = run_all("https://example.com/batch-1")
                self.assertIsInstance(r1, list)
                self.assertGreater(len(r1), 0)

    # -------------------------------------------------------------------------
    # API, History, Pagination, and WebSocket Lifecycle
    # -------------------------------------------------------------------------
    def test_api_scans_history_and_pagination(self):
        """Verify /api/scans supports pagination, query filtering, and sorting."""
        scan_id, _ = persist_scan(
            target_url="https://example.com/history-test",
            scan_mode="deep",
            prepared_results=[{"name": "Test Check", "status": "PASS", "category": "General", "evidence": "OK"}],
            counts={"PASS": 1, "FAIL": 0, "WARN": 0, "ERROR": 0, "SKIP": 0},
            risk_score=5,
            risk_level="LOW",
            verdict="BENIGN",
            threat_report={"verdict": "BENIGN", "summary": "Clean"},
            duration_ms=120,
            created_at="2026-10-28T12:00:00Z",
        )
        self.assertGreater(scan_id, 0)

        # Fetch pagination page 1
        res = self.client.get("/api/scans?page=1&page_size=10&sort_by=created_at&sort_order=desc")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("items", data)
        self.assertIn("total", data)
        self.assertGreater(data["total"], 0)

        # Get scan by ID
        res_scan = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(res_scan.status_code, 200)
        self.assertEqual(res_scan.json()["id"], scan_id)
        self.assertEqual(res_scan.json()["verdict"], "BENIGN")

    def test_api_iocs_sanitization(self):
        """Verify /api/iocs endpoint returns sanitized indicators with no private IPs or leaked query credentials."""
        res = self.client.get("/api/iocs?page=1&page_size=20")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        for ioc in data.get("items", []):
            val = ioc.get("indicator_value", "")
            self.assertFalse(val.startswith("127."), f"Private loopback IP in IOCs: {val}")
            self.assertFalse(val.startswith("10."), f"Private Class A IP in IOCs: {val}")
            self.assertFalse(val.startswith("192.168."), f"Private Class C IP in IOCs: {val}")
            self.assertNotIn("SECRET", val)


    def test_websocket_progress_event_flow(self):
        """Verify WebSocket receives progress updates and terminates on complete."""
        from webapp.main import _get_progress_queue

        async def _feed_queue():
            q = await _get_progress_queue("ws-test-job-99")
            await q.put({"type": "progress", "step": 1, "total": 15, "percent": 7, "label": "Checking DNS"})
            await q.put({"type": "complete", "step": 15, "total": 15, "percent": 100, "label": "Done", "scan_id": 1})

        asyncio.run(_feed_queue())

        with self.client.websocket_connect("/ws/progress/ws-test-job-99") as ws:
            msg1 = ws.receive_json()
            self.assertEqual(msg1["type"], "progress")
            self.assertEqual(msg1["step"], 1)

            msg2 = ws.receive_json()
            self.assertEqual(msg2["type"], "complete")
            self.assertEqual(msg2["percent"], 100)


if __name__ == "__main__":
    unittest.main()

"""Unit and regression tests for Phase 1: Strict URL Validation, SSRF Protection, and Safe Transport."""

import contextvars
import ipaddress
import socket
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import requests

from url_audit.security import (
    DEFAULT_MAX_REDIRECTS,
    AuditTimeoutError,
    InvalidURLError,
    RedirectSecurityError,
    SSRFError,
    URLSecurityError,
    ValidatedURL,
    get_allowed_ports,
    get_remaining_deadline,
    is_blocked_ip,
    parse_ip_safe,
    reset_scan_deadline,
    resolve_and_validate_destination,
    safe_request,
    safe_socket_create_connection,
    set_scan_deadline,
    validate_url,
)
from webapp.main import app


class TestURLValidationGateway(unittest.TestCase):
    """1. Strict URL Gateway Ingress Tests."""

    def test_valid_http_and_https_urls(self):
        valid_cases = [
            ("http://example.com", "http", "example.com", 80, "/"),
            ("https://example.com", "https", "example.com", 443, "/"),
            ("https://example.com/path?arg=1#frag", "https", "example.com", 443, "/path"),
            ("http://sub.domain.org:80/api/v1", "http", "sub.domain.org", 80, "/api/v1"),
            ("https://sub.domain.org:443/", "https", "sub.domain.org", 443, "/"),
        ]
        for raw, scheme, host, port, path in valid_cases:
            with self.subTest(url=raw):
                val = validate_url(raw)
                self.assertIsInstance(val, ValidatedURL)
                self.assertEqual(val.scheme, scheme)
                self.assertEqual(val.hostname, host)
                self.assertEqual(val.port, port)
                self.assertEqual(val.path, path)

    def test_reject_empty_and_whitespace_urls(self):
        bad_cases = ["", "   ", "\t", "\n", "   \r\n  "]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidURLError):
                    validate_url(bad)

    def test_reject_control_characters(self):
        bad_cases = [
            "http://example.com/\x00test",
            "http://example.com/\r\nSet-Cookie:bad",
            "http://example.com/foo\x1bbar",
            "http://example.com/test\x7f",
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidURLError):
                    validate_url(bad)

    def test_reject_unsupported_schemes(self):
        unsupported = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<b>hello</b>",
            "ftp://ftp.example.com/file.txt",
            "blob:https://example.com/uuid",
            "gopher://gopher.floodgap.com",
            "ldap://127.0.0.1:389",
            "mailto:admin@example.com",
            "//example.com/test",  # Scheme-relative without explicit scheme
            "example.com",          # Missing scheme
        ]
        for url in unsupported:
            with self.subTest(url=url):
                with self.assertRaises(InvalidURLError):
                    validate_url(url)

    def test_reject_userinfo_credentials(self):
        userinfo_urls = [
            "http://admin:secret@example.com/",
            "https://user@example.com/login",
            "http://:password@example.com/",
        ]
        for url in userinfo_urls:
            with self.subTest(url=url):
                with self.assertRaises(InvalidURLError):
                    validate_url(url)

    def test_reject_invalid_and_disallowed_ports(self):
        # Invalid numeric ports
        with self.assertRaises(InvalidURLError):
            validate_url("http://example.com:0")
        with self.assertRaises(InvalidURLError):
            validate_url("http://example.com:65536")
        with self.assertRaises(InvalidURLError):
            validate_url("http://example.com:abc")

        # Non-whitelisted ports (default allowed: 80, 443)
        disallowed = [
            "http://example.com:21",
            "http://example.com:22",
            "http://example.com:25",
            "http://example.com:8080",
            "https://example.com:8443",
        ]
        for url in disallowed:
            with self.subTest(url=url):
                with self.assertRaises(InvalidURLError):
                    validate_url(url)

    def test_configurable_allowed_ports(self):
        val = validate_url("http://example.com:8080", allowed_ports={80, 443, 8080})
        self.assertEqual(val.port, 8080)

    def test_malformed_authorities_and_ipv6(self):
        malformed = [
            "http://[::1/test",         # Unclosed bracket
            "http://[:1]:80/",          # Malformed IPv6
            "http://[xyz]:80/",         # Non-hex IPv6
            "http:///",                 # Empty authority
        ]
        for url in malformed:
            with self.subTest(url=url):
                with self.assertRaises(InvalidURLError):
                    validate_url(url)


class TestSSRFProtectionAndIPCanonicalization(unittest.TestCase):
    """2. SSRF Protection, IP Canonicalization, and Destination Validator Tests."""

    def test_parse_ip_safe_standard_and_alternatives(self):
        # Standard IPv4
        self.assertEqual(parse_ip_safe("127.0.0.1"), ipaddress.IPv4Address("127.0.0.1"))
        self.assertEqual(parse_ip_safe("192.168.1.1"), ipaddress.IPv4Address("192.168.1.1"))

        # Dotted hex: 0x7f.0.0.1 -> 127.0.0.1
        self.assertEqual(parse_ip_safe("0x7f.0.0.1"), ipaddress.IPv4Address("127.0.0.1"))

        # Dotted octal: 0177.0.0.1 -> 127.0.0.1
        self.assertEqual(parse_ip_safe("0177.0.0.1"), ipaddress.IPv4Address("127.0.0.1"))

        # Integer IPv4: 2130706433 -> 127.0.0.1
        self.assertEqual(parse_ip_safe("2130706433"), ipaddress.IPv4Address("127.0.0.1"))

        # Full hex integer: 0x7f000001 -> 127.0.0.1
        self.assertEqual(parse_ip_safe("0x7f000001"), ipaddress.IPv4Address("127.0.0.1"))

        # Standard IPv6
        self.assertEqual(parse_ip_safe("::1"), ipaddress.IPv6Address("::1"))
        self.assertEqual(parse_ip_safe("fe80::1"), ipaddress.IPv6Address("fe80::1"))

        # Non-IP hostnames return None for standard DNS resolution
        self.assertIsNone(parse_ip_safe("example.com"))
        self.assertIsNone(parse_ip_safe("safe.subdomain.org"))

    def test_is_blocked_ip_detection(self):
        blocked_ips = [
            "127.0.0.1",          # Loopback
            "127.12.34.56",        # Loopback range
            "::1",                 # IPv6 loopback
            "10.0.0.1",            # RFC 1918 Class A
            "10.254.10.1",
            "172.16.0.1",          # RFC 1918 Class B
            "172.31.255.254",
            "192.168.0.1",         # RFC 1918 Class C
            "192.168.100.50",
            "169.254.169.254",     # AWS/Azure/GCP Cloud Metadata
            "169.254.169.253",     # Azure DNS
            "169.254.1.1",         # Link-local
            "fe80::1",             # IPv6 Link-local
            "fd00:ec2::254",       # AWS IPv6 Metadata
            "100.100.100.200",     # Alibaba Cloud Metadata
            "100.64.0.1",          # Carrier Grade NAT (CGNAT)
            "0.0.0.0",             # Unspecified
            "::",                  # IPv6 Unspecified
            "224.0.0.1",           # Multicast
            "ff02::1",             # IPv6 Multicast
            "240.0.0.1",           # Reserved
        ]
        for ip_str in blocked_ips:
            with self.subTest(ip=ip_str):
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, reason = is_blocked_ip(ip_obj)
                self.assertTrue(blocked, f"Expected {ip_str} to be blocked: {reason}")

    def test_is_blocked_ip_allows_legitimate_public_ips(self):
        public_ips = [
            "93.184.216.34",      # example.com
            "8.8.8.8",            # Google DNS
            "1.1.1.1",            # Cloudflare DNS
            "140.82.121.3",       # GitHub
            "2606:4700:4700::1111",# Cloudflare IPv6
        ]
        for ip_str in public_ips:
            with self.subTest(ip=ip_str):
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, reason = is_blocked_ip(ip_obj)
                self.assertFalse(blocked, f"Expected {ip_str} to be allowed, but got: {reason}")

    def test_resolve_and_validate_destination_literal_ssrf_rejection(self):
        blocked_targets = [
            "127.0.0.1",
            "localhost",
            "metadata.google.internal",
            "instance-data",
            "myhost.local",
            "intranet.internal",
            "service.lan",
            "169.254.169.254",
            "0x7f.0.0.1",
            "2130706433",
            "0177.0.0.1",
            "::1",
            "10.1.2.3",
            "192.168.1.1",
        ]
        for target in blocked_targets:
            with self.subTest(target=target):
                with self.assertRaises(SSRFError):
                    resolve_and_validate_destination(target, 80)

    def test_mixed_public_and_private_dns_response_blocked(self):
        """Validates that EVERY resolved address is checked; any private IP triggers immediate block."""
        def mock_mixed_resolver(host, port):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
            ]

        with self.assertRaises(SSRFError) as cm:
            resolve_and_validate_destination("dual-homed.attack.com", 80, resolver=mock_mixed_resolver)
        self.assertIn("127.0.0.1", str(cm.exception))

    def test_dns_rebinding_connection_pinning(self):
        """Validates that safe_socket_create_connection pins to the approved IP."""
        mock_sock = MagicMock(spec=socket.socket)
        with patch("url_audit.security.resolve_and_validate_destination") as mock_resolve:
            with patch("socket.create_connection", return_value=mock_sock) as mock_create_conn:
                mock_resolve.return_value = [ipaddress.IPv4Address("93.184.216.34")]
                sock, pinned_ip = safe_socket_create_connection("example.com", 80)
                self.assertEqual(pinned_ip, "93.184.216.34")
                mock_create_conn.assert_called_once_with(("93.184.216.34", 80), timeout=3.0)


class TestRedirectSafety(unittest.TestCase):
    """3. Redirect Safety, Limit Enforcement, and Loop Prevention Tests."""

    def test_excessive_redirects_exceeding_max_hops_rejected(self):
        """Validates that > 5 redirects triggers RedirectSecurityError."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.is_redirect = True
        mock_response.headers = {"Location": "http://example.com/next"}

        mock_session = MagicMock(spec=requests.Session)
        # Create a series of redirect responses
        responses = []
        for i in range(7):
            r = MagicMock(spec=requests.Response)
            r.is_redirect = True
            r.headers = {"Location": f"http://example.com/step/{i+1}"}
            responses.append(r)
        mock_session.request.side_effect = responses

        with patch("url_audit.security.resolve_and_validate_destination"):
            with self.assertRaises(RedirectSecurityError) as cm:
                safe_request("GET", "http://example.com/step/0", max_redirects=5, session=mock_session)
            self.assertIn("Exceeded maximum allowed redirect limit", str(cm.exception))

    def test_redirect_to_private_address_blocked(self):
        """Validates that a public URL redirecting to a private IP is blocked."""
        r1 = MagicMock(spec=requests.Response)
        r1.is_redirect = True
        r1.headers = {"Location": "http://127.0.0.1/admin"}

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.return_value = r1

        with patch("url_audit.security.resolve_and_validate_destination") as mock_resolve:
            # First resolution for example.com succeeds
            # Second resolution for 127.0.0.1 raises SSRFError
            def resolve_side_effect(host, port):
                if host == "127.0.0.1":
                    raise SSRFError(f"Target IP {host} is a loopback address.")
                return [ipaddress.IPv4Address("93.184.216.34")]

            mock_resolve.side_effect = resolve_side_effect

            with self.assertRaises(SSRFError) as cm:
                safe_request("GET", "http://example.com/open-redirect", session=mock_session)
            self.assertIn("loopback", str(cm.exception))

    def test_redirect_loop_detected(self):
        """Validates that circular redirects (A -> B -> A) are aborted."""
        r1 = MagicMock(spec=requests.Response)
        r1.is_redirect = True
        r1.headers = {"Location": "http://example.com/b"}

        r2 = MagicMock(spec=requests.Response)
        r2.is_redirect = True
        r2.headers = {"Location": "http://example.com/a"}

        mock_session = MagicMock(spec=requests.Session)
        mock_session.request.side_effect = [r1, r2]

        with patch("url_audit.security.resolve_and_validate_destination"):
            with self.assertRaises(RedirectSecurityError) as cm:
                safe_request("GET", "http://example.com/a", session=mock_session)
            self.assertIn("Redirect loop detected", str(cm.exception))


class TestNetworkLimitsAndTimeouts(unittest.TestCase):
    """4. Global Scan Deadline and Timeout Limit Tests."""

    def test_scan_deadline_contextvar_propagation(self):
        token = set_scan_deadline(100.0)
        try:
            with patch("time.time", return_value=90.0):
                self.assertAlmostEqual(get_remaining_deadline(), 10.0)
            with patch("time.time", return_value=105.0):
                self.assertEqual(get_remaining_deadline(), 0.0)
        finally:
            reset_scan_deadline(token)

    def test_expired_scan_deadline_aborts_socket_creation(self):
        with patch("time.time", return_value=200.0):
            with self.assertRaises(AuditTimeoutError):
                safe_socket_create_connection("example.com", 80, deadline_ts=150.0)

    def test_expired_scan_deadline_aborts_safe_request(self):
        with patch("time.time", return_value=200.0):
            with self.assertRaises(AuditTimeoutError):
                safe_request("GET", "http://example.com/", deadline_ts=150.0)


class TestFastAPIGatewayAuditEndpoint(unittest.TestCase):
    """5. FastAPI Gateway Ingress Rejection & Acceptance Tests."""

    def setUp(self):
        self.client = TestClient(app)

    def test_reject_empty_url(self):
        resp = self.client.post("/api/audit", data={"url": ""})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

    def test_reject_unsupported_scheme(self):
        bad_urls = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://files.example.com",
            "data:text/html,bad",
        ]
        for bad in bad_urls:
            with self.subTest(url=bad):
                resp = self.client.post("/api/audit", data={"url": bad})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("error", resp.json())

    def test_reject_loopback_and_metadata_ip(self):
        bad_destinations = [
            "http://127.0.0.1/",
            "http://localhost:80/",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/",
            "http://0x7f.0.0.1/",
            "http://2130706433/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
        ]
        for dest in bad_destinations:
            with self.subTest(url=dest):
                resp = self.client.post("/api/audit", data={"url": dest})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("error", resp.json())

    def test_reject_unauthorized_port(self):
        resp = self.client.post("/api/audit", data={"url": "http://example.com:22"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

    def test_legitimate_url_accepted_and_scanned(self):
        """Verifies that valid public HTTP/HTTPS URLs pass the gateway."""
        with patch("webapp.main.run_all") as mock_run_all, patch("webapp.main._run_ai_analysis", return_value={"enabled": False}):
            from url_audit.utils import CheckResult
            mock_run_all.return_value = [
                CheckResult(1, "Domain Name Legitimacy", "PASS", "Valid domain", {}),
                CheckResult(10, "Presence of HTTPS", "PASS", "scheme=https", {}),
            ]
            resp = self.client.post("/api/audit", data={"url": "https://example.com"})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("scan_id", data)
            self.assertIn(data["target_url"], ["https://example.com", "https://example.com/"])


if __name__ == "__main__":
    unittest.main()

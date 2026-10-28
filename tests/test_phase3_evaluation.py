"""Phase 3 Comprehensive Test Suite and Detection Evaluation Matrix.

Covers:
1. Standards-aware PSL domain parsing (hostname, subdomain, domain, suffix, IP literals).
2. IDN normalization, UTS-46 Punycode conversion, and mixed-script homoglyph detection.
3. Multi-signal brand impersonation, typosquatting, and deceptive subdomains.
4. Granular DNS outcome classification (RESOLVED, NXDOMAIN, TIMEOUT, TEMPORARY_FAILURE).
5. Labeled evaluation dataset with precision, recall, false-positive rate, and inconclusive rate calculations.
"""

from __future__ import annotations

import unittest
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, patch

from url_audit.domain_intel import (
    DEFAULT_BRAND_PROFILES,
    BrandMatchResult,
    DNSOutcome,
    ParsedDomainInfo,
    detect_brand_impersonation,
    levenshtein_distance,
    normalize_visual_leet,
    parse_domain_info,
    resolve_dns_outcome,
    transliterate_confusables,
)
from url_audit.checks.domain_checks import check_domain_legitimacy, check_whois_age, check_domain_expiry
from url_audit.checks.behavior_checks import check_homoglyph


class TestStandardsAwareDomainParsing(unittest.TestCase):
    """1. Standards-aware domain parsing via Public Suffix List (PSL) and IP handling."""

    def test_multipart_public_suffixes(self):
        # Must not assume splitting at last dot identifies root domain
        test_cases = [
            ("https://news.bbc.co.uk/world", "news", "bbc", "co.uk", "bbc.co.uk"),
            ("https://login.service.gov.uk/auth", "", "login", "service.gov.uk", "login.service.gov.uk"),
            ("https://project.github.io/site", "", "project", "github.io", "project.github.io"),
            ("https://sub.portal.sydney.edu.au/", "sub.portal", "sydney", "edu.au", "sydney.edu.au"),
            ("https://www.google.com/search", "www", "google", "com", "google.com"),
        ]
        for url, exp_sub, exp_dom, exp_suf, exp_reg in test_cases:
            info = parse_domain_info(url)
            self.assertTrue(info.is_valid_syntax, f"Failed syntax for {url}")
            self.assertFalse(info.is_ip)
            self.assertEqual(info.subdomain, exp_sub, f"Subdomain mismatch for {url}")
            self.assertEqual(info.domain, exp_dom, f"Domain mismatch for {url}")
            self.assertEqual(info.suffix, exp_suf, f"Suffix mismatch for {url}")
            self.assertEqual(info.registrable_domain, exp_reg, f"Registrable domain mismatch for {url}")

    def test_ip_literals_isolated_from_domains(self):
        # IPv4 and IPv6 literals must have no domain/suffix/subdomain
        ip_cases = [
            ("http://192.168.1.1:8080/path", "192.168.1.1", 4),
            ("https://8.8.8.8/dns-query", "8.8.8.8", 4),
            ("http://[2606:4700:4700::1111]/", "2606:4700:4700::1111", 6),
            ("https://[::1]:443/status", "::1", 6),
        ]
        for url, exp_ip, exp_v in ip_cases:
            info = parse_domain_info(url)
            self.assertTrue(info.is_valid_syntax)
            self.assertTrue(info.is_ip)
            self.assertEqual(info.ip_version, exp_v)
            self.assertEqual(info.hostname, exp_ip)
            self.assertEqual(info.subdomain, "")
            self.assertEqual(info.domain, "")
            self.assertEqual(info.suffix, "")
            self.assertEqual(info.registrable_domain, "")

    def test_invalid_hostname_syntax_rejected(self):
        invalid_urls = [
            "https://invalid..domain.com",                                       # Consecutive dots
            "https://-leading-hyphen.com",                                       # Leading hyphen in label
            "https://trailing-hyphen-.com",                                      # Trailing hyphen in label
            f"https://{'a' * 64}.com",                                           # Label > 63 chars
            f"https://{'sub.' * 65}example.com",                                 # Hostname > 253 chars (271 chars)
            "",                                                                  # Empty
        ]
        for u in invalid_urls:
            info = parse_domain_info(u)
            self.assertFalse(info.is_valid_syntax, f"Should be invalid: {u}")
            self.assertIsNotNone(info.syntax_error)


class TestIDNAndPunycodeHandling(unittest.TestCase):
    """2. IDN conversion, UTS-46 normalization, and mixed-script detection."""

    def test_uts46_punycode_roundtrip(self):
        # Unicode <-> Punycode canonicalization
        cases = [
            ("https://münchen.de", "xn--mnchen-3ya.de", "münchen.de"),
            ("https://xn--mnchen-3ya.de", "xn--mnchen-3ya.de", "münchen.de"),
            ("https://café.fr", "xn--caf-dma.fr", "café.fr"),
        ]
        for url, exp_ascii, exp_uni in cases:
            info = parse_domain_info(url)
            self.assertTrue(info.is_valid_syntax)
            self.assertTrue(info.is_idn)
            self.assertEqual(info.hostname, exp_ascii)
            self.assertEqual(info.unicode_hostname, exp_uni)

    def test_cyrillic_homoglyphs_detected_as_mixed_script(self):
        # Cyrillic small 'a' (U+0430) mixed with Latin letters "pple"
        # xn--pple-43d.com -> аpple.com
        url = "https://xn--pple-43d.com"
        info = parse_domain_info(url)
        self.assertTrue(info.is_valid_syntax)
        self.assertTrue(info.is_idn)
        self.assertTrue(info.is_mixed_script, "Should detect mixed script (Cyrillic + Latin in single label)")
        self.assertGreaterEqual(len(info.confusables_detected), 1)
        self.assertEqual(info.confusables_detected[0]["char"], "\u0430")
        self.assertEqual(info.confusables_detected[0]["latin_lookalike"], "a")

    def test_legitimate_idns_not_flagged_as_mixed_script(self):
        # Single-script native IDNs must NOT be flagged as deceptive mixed-script
        legitimate_idns = [
            "https://xn--mnchen-3ya.de",  # German münchen.de (Latin with umlaut)
            "https://xn--fiqs8s.cn",      # Chinese 中国.cn (Han script)
            "https://café.fr",            # French café.fr (Latin)
        ]
        for u in legitimate_idns:
            info = parse_domain_info(u)
            self.assertTrue(info.is_valid_syntax)
            self.assertFalse(info.is_mixed_script, f"{u} is single-script and should not be mixed-script")


class TestBrandImpersonationDetection(unittest.TestCase):
    """3. Multi-signal brand impersonation, deceptive subdomains, and typosquatting."""

    def test_official_brand_domains_identified_as_legitimate(self):
        officials = [
            "https://www.google.com",
            "https://login.microsoft.com",
            "https://apple.com/iphone",
            "https://www.paypal.com/signin",
            "https://amazon.co.uk/orders",
            "https://netflix.com/browse",
            "https://steamcommunity.com/id/player",
            "https://binance.com/trade",
        ]
        for u in officials:
            info = parse_domain_info(u)
            match = detect_brand_impersonation(info)
            self.assertTrue(match.is_official, f"{u} should be recognized as official brand domain")
            self.assertFalse(match.is_impersonation)

    def test_deceptive_subdomain_structure_detected(self):
        deceptive = [
            "https://paypal.com.account-update.attacker.com/login",
            "https://appleid.apple.com.verify-identity.net/auth",
            "https://login.microsoft.com.secure-portal.org/",
        ]
        for u in deceptive:
            info = parse_domain_info(u)
            match = detect_brand_impersonation(info)
            self.assertTrue(match.is_impersonation, f"Failed to detect deceptive subdomain: {u}")
            self.assertEqual(match.impersonation_type, "DECEPTIVE_SUBDOMAIN")
            self.assertEqual(match.severity, "HIGH")

    def test_embedded_brand_in_third_party_registrable_domain(self):
        embedded = [
            "https://paypal-security-verification.com/login",
            "https://amazon-account-support.org/help",
            "https://binance-kyc-verify.io/auth",
            "https://netflix-billing-update.net/card",
        ]
        for u in embedded:
            info = parse_domain_info(u)
            match = detect_brand_impersonation(info)
            self.assertTrue(match.is_impersonation, f"Failed to detect embedded brand: {u}")
            self.assertEqual(match.impersonation_type, "EMBEDDED_BRAND")
            self.assertEqual(match.severity, "HIGH")

    def test_typosquatting_and_character_substitutions(self):
        typos = [
            ("https://paypa1.com", "PayPal", "TYPOSQUAT"),
            ("https://arnazon.com", "Amazon", "TYPOSQUAT"),
            ("https://g00gle.com", "Google", "TYPOSQUAT"),
            ("https://micros0ft.com", "Microsoft", "TYPOSQUAT"),
            ("https://netfl1x.com", "Netflix", "TYPOSQUAT"),
        ]
        for u, exp_brand, exp_type in typos:
            info = parse_domain_info(u)
            match = detect_brand_impersonation(info)
            self.assertTrue(match.is_impersonation, f"Failed to detect typosquat: {u}")
            self.assertEqual(match.matched_brand, exp_brand)
            self.assertEqual(match.impersonation_type, exp_type)

    def test_homoglyph_brand_impersonation_detected(self):
        # xn--pple-43d.com -> Cyrillic 'a' + 'pple.com'
        url = "https://xn--pple-43d.com"
        info = parse_domain_info(url)
        match = detect_brand_impersonation(info)
        self.assertTrue(match.is_impersonation)
        self.assertEqual(match.matched_brand, "Apple")
        self.assertEqual(match.impersonation_type, "HOMOGLYPH_BRAND_IMPERSONATION")
        self.assertEqual(match.severity, "HIGH")


class TestDNSResolutionOutcomes(unittest.TestCase):
    """4. Granular classification of DNS outcomes."""

    def test_valid_dns_resolution_returns_pass(self):
        outcome = resolve_dns_outcome("example.com")
        self.assertEqual(outcome.outcome, "RESOLVED")
        self.assertEqual(outcome.status, "PASS")
        self.assertGreaterEqual(len(outcome.resolved_ips), 1)

    def test_nxdomain_returns_explicit_warn(self):
        # Non-existent domain must NOT be silently treated as safe or as an SSRF error
        outcome = resolve_dns_outcome("nonexistent-domain-test-12345xyz-impossible.com")
        self.assertEqual(outcome.outcome, "NXDOMAIN")
        self.assertEqual(outcome.status, "WARN")
        self.assertIn("NXDOMAIN", outcome.evidence)

    def test_simulated_timeout_returns_error(self):
        def timeout_resolver(host):
            raise TimeoutError("Simulated DNS timeout")

        outcome = resolve_dns_outcome("timeout-test.com", custom_resolver=timeout_resolver)
        self.assertEqual(outcome.outcome, "TIMEOUT")
        self.assertEqual(outcome.status, "ERROR")

    def test_simulated_temporary_failure_returns_error(self):
        def servfail_resolver(host):
            raise RuntimeError("SERVFAIL from root server")

        outcome = resolve_dns_outcome("servfail-test.com", custom_resolver=servfail_resolver)
        self.assertEqual(outcome.outcome, "TEMPORARY_FAILURE")
        self.assertEqual(outcome.status, "ERROR")


class TestEvaluationMatrixAndMetrics(unittest.TestCase):
    """5. Labeled evaluation dataset with precision, recall, and false-positive calculations."""

    # Ground-truth test dataset: (url, expected_category, is_malicious_or_threat)
    DATASET: List[Tuple[str, str, bool]] = [
        # Legitimate Popular Domains (Negative / Clean)
        ("https://www.google.com", "LEGITIMATE", False),
        ("https://apple.com/iphone", "LEGITIMATE", False),
        ("https://login.microsoft.com", "LEGITIMATE", False),
        ("https://www.paypal.com/signin", "LEGITIMATE", False),
        ("https://amazon.co.uk", "LEGITIMATE", False),
        ("https://netflix.com/browse", "LEGITIMATE", False),
        ("https://steamcommunity.com", "LEGITIMATE", False),
        ("https://binance.com", "LEGITIMATE", False),
        ("https://bbc.co.uk/news", "LEGITIMATE", False),
        ("https://github.io", "LEGITIMATE", False),
        ("https://example.com", "LEGITIMATE", False),
        
        # Legitimate IDN domains (Negative / Clean)
        ("https://xn--mnchen-3ya.de", "LEGITIMATE_IDN", False),
        ("https://xn--fiqs8s.cn", "LEGITIMATE_IDN", False),
        ("https://café.fr", "LEGITIMATE_IDN", False),
        
        # Legitimate direct IP literal (Negative / Clean)
        ("http://1.1.1.1", "LEGITIMATE_IP", False),
        ("https://[2606:4700:4700::1111]", "LEGITIMATE_IP", False),

        # Deceptive Subdomain Impersonation (Positive / Threat)
        ("https://paypal.com.account-update.attacker.com/login", "DECEPTIVE_SUBDOMAIN", True),
        ("https://login.microsoft.com.security-verify.net/auth", "DECEPTIVE_SUBDOMAIN", True),
        ("https://appleid.apple.com.recover-access.org/", "DECEPTIVE_SUBDOMAIN", True),
        ("https://amazon.com.order-tracking.phishing-hub.com/", "DECEPTIVE_SUBDOMAIN", True),

        # Brand Embedded in 3rd-party Domain (Positive / Threat)
        ("https://paypal-security-verification.com/login", "EMBEDDED_BRAND", True),
        ("https://amazon-account-support.org/help", "EMBEDDED_BRAND", True),
        ("https://binance-kyc-verify.io/login", "EMBEDDED_BRAND", True),
        ("https://netflix-billing-update.net/card", "EMBEDDED_BRAND", True),
        ("https://google-drive-security-check.com/file", "EMBEDDED_BRAND", True),

        # Typosquatting / Character Substitution (Positive / Threat)
        ("https://paypa1.com/checkout", "TYPOSQUAT", True),
        ("https://arnazon.com/deals", "TYPOSQUAT", True),
        ("https://g00gle.com/search", "TYPOSQUAT", True),
        ("https://micros0ft.com/office", "TYPOSQUAT", True),
        ("https://netfl1x.com/watch", "TYPOSQUAT", True),

        # Mixed-Script Homoglyph Attack (Positive / Threat)
        ("https://xn--pple-43d.com", "HOMOGLYPH", True),
        ("https://xn--googl-3we.com", "HOMOGLYPH", True),

        # Unresolvable Non-Existent Domain (Unresolved / Inconclusive Signal)
        ("https://nonexistent-domain-test-12345xyz-impossible.com", "NXDOMAIN", False),
        ("https://nxdomain-fake-test-domain-999.com", "NXDOMAIN", False),
    ]

    def test_detection_evaluation_metrics(self):
        tp = 0  # Threat correctly detected
        fp = 0  # Clean domain falsely flagged as threat
        tn = 0  # Clean domain correctly passed
        fn = 0  # Threat missed
        nx_count = 0

        for url, category, is_threat in self.DATASET:
            info = parse_domain_info(url)
            brand = detect_brand_impersonation(info)
            homo_check = check_homoglyph(url)
            legit_check = check_domain_legitimacy(url)

            # Determine if scanner raised a threat signal (FAIL on legitimacy or homoglyphs)
            flagged_as_threat = (
                brand.is_impersonation
                or homo_check.status == "FAIL"
                or legit_check.status == "FAIL"
            )

            is_nx = (legit_check.status == "WARN" and "NXDOMAIN" in legit_check.evidence)
            if is_nx:
                nx_count += 1

            if is_threat:
                if flagged_as_threat:
                    tp += 1
                else:
                    fn += 1
            else:
                if flagged_as_threat:
                    fp += 1
                else:
                    tn += 1

        total = len(self.DATASET)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        inconclusive_rate = nx_count / total

        # Verify high accuracy thresholds
        self.assertGreaterEqual(precision, 0.95, f"Precision was {precision:.2%}, expected >= 95%")
        self.assertGreaterEqual(recall, 0.95, f"Recall was {recall:.2%}, expected >= 95%")
        self.assertLessEqual(fpr, 0.05, f"False Positive Rate was {fpr:.2%}, expected <= 5%")
        self.assertGreaterEqual(tp, 14, "Expected at least 14 true positives detected")
        self.assertEqual(fp, 0, f"Expected 0 false positives, got {fp}")


if __name__ == "__main__":
    unittest.main()

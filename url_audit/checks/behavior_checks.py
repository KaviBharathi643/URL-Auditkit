from ..utils import CheckResult, fetch, count_redirects
from ..domain_intel import parse_domain_info, detect_brand_impersonation
import re, requests

def check_redirects(url: str):
    # (33)
    try:
        n = count_redirects(url)
        status = "WARN" if n > 2 else "PASS"
        return CheckResult(33, "Redirects and Shortened URLs", status, evidence=f"redirects={n}")
    except Exception as e:
        return CheckResult(33, "Redirects and Shortened URLs", "ERROR", evidence=f"Redirect check operational error: {str(e)[:100]}")

def check_popups_downloads(url: str):
    # (34)
    try:
        resp, html, soup = fetch(url)
        if not html:
            return CheckResult(34, "Pop-Ups or Forced Downloads", "ERROR", evidence="Could not fetch HTML content")
        poplike = bool(re.search(r"(window\.open|showModal|confirm\(|prompt\()", html, re.I))
        content_type = resp.headers.get("content-type", "").lower() if resp else ""
        downloady = bool(re.search(r"download=", html, re.I)) or ("application/octet-stream" in content_type)
        verdict = "WARN" if (poplike or downloady) else "PASS"
        return CheckResult(34, "Pop-Ups or Forced Downloads", verdict, evidence=f"popup={poplike} downloadish={downloady}")
    except Exception as e:
        return CheckResult(34, "Pop-Ups or Forced Downloads", "ERROR", evidence=f"Operational error: {str(e)[:100]}")

def check_suspicious_requests(url: str):
    # (35)
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(35, "Suspicious Login or Payment Requests", "ERROR", evidence="Could not fetch HTML content")
        text = soup.get_text(" ").lower()
        flags = any(k in text for k in ["login","password","credit card","debit card","otp","cvv","ssn"])
        return CheckResult(35, "Suspicious Login or Payment Requests", "WARN" if flags else "PASS", evidence=f"sensitive_fields={flags}")
    except Exception as e:
        return CheckResult(35, "Suspicious Login or Payment Requests", "ERROR", evidence=f"Operational error: {str(e)[:100]}")

def check_url_length(url: str):
    # (36)
    try:
        L = len(url)
        status = "WARN" if L > 120 else "PASS"
        return CheckResult(36, "URL Length and Structure", status, evidence=f"length={L}")
    except Exception as e:
        return CheckResult(36, "URL Length and Structure", "ERROR", evidence=f"Operational error: {str(e)[:100]}")

def check_homoglyph(url: str):
    # (37) Standards-aware IDN, mixed-script homoglyphs, and typosquatting analysis
    try:
        parsed = parse_domain_info(url)
        if not parsed.is_valid_syntax:
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                "ERROR",
                evidence=f"Invalid domain syntax: {parsed.syntax_error}",
                data={"error": "invalid_syntax"},
            )

        if parsed.is_ip:
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                "PASS",
                evidence=f"Direct IP address: {parsed.hostname}",
            )

        # 1. Mixed-script homoglyph attack (e.g. Cyrillic + Latin in same label)
        if parsed.is_mixed_script:
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                "FAIL",
                evidence=f"Mixed-script homoglyph attack detected: unicode={parsed.unicode_hostname} ({len(parsed.confusables_detected)} confusables)",
                data={"homoglyph": True, "mixed_script": True, "confusables": parsed.confusables_detected},
            )

        # 2. Check for brand-targeting homoglyphs or typosquatting
        brand_match = detect_brand_impersonation(parsed)
        if brand_match.impersonation_type == "HOMOGLYPH_BRAND_IMPERSONATION":
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                "FAIL",
                evidence=brand_match.details,
                data={"homoglyph": True, "brand": brand_match.matched_brand},
            )
        if brand_match.impersonation_type == "TYPOSQUAT":
            status = "FAIL" if brand_match.severity == "HIGH" else "WARN"
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                status,
                evidence=brand_match.details,
                data={"typosquat": True, "brand": brand_match.matched_brand, "severity": brand_match.severity},
            )

        # 3. Legitimate single-script IDN (e.g. münchen.de, 中国.cn)
        if parsed.is_idn:
            return CheckResult(
                37,
                "Typosquatting or Homoglyph Domains",
                "PASS",
                evidence=f"Legitimate IDN: unicode={parsed.unicode_hostname} (single-script)",
                data={"is_idn": True, "unicode": parsed.unicode_hostname},
            )

        return CheckResult(
            37,
            "Typosquatting or Homoglyph Domains",
            "PASS",
            evidence=f"Standard ASCII domain: host={parsed.hostname}",
        )
    except Exception as e:
        return CheckResult(37, "Typosquatting or Homoglyph Domains", "ERROR", evidence=f"Homoglyph check error: {str(e)[:100]}")

def check_email_links(url: str):
    # (38)
    return CheckResult(38, "Email Link Safety Advisory", "INFO", evidence="Exercise caution with unsolicited email links")

def check_mobile_friendly(url: str):
    # (39)
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(39, "Mobile Friendliness", "WARN", evidence="No HTML")
        vp = soup.find("meta", attrs={"name":"viewport"}) or soup.find("meta", attrs={"content": re.compile("width=device-width")})
        return CheckResult(39, "Mobile Friendliness", "PASS" if vp else "WARN", evidence=f"viewport_meta_present={bool(vp)}")
    except Exception as e:
        return CheckResult(39, "Mobile Friendliness", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_ads_prompts(url: str):
    # (40)
    try:
        resp, html, soup = fetch(url)
        if not html:
            return CheckResult(40, "Frequency of Unexpected Ads/Prompts", "WARN", evidence="No HTML")
        ad_patterns = ["googlesyndication.com","doubleclick.net","propellerads","onclickads","popunder","adnxs.com"]
        found = any(p in html for p in ad_patterns)
        return CheckResult(40, "Frequency of Unexpected Ads/Prompts", "INFO" if found else "PASS", evidence=f"ad_scripts_found={found}")
    except Exception as e:
        return CheckResult(40, "Frequency of Unexpected Ads/Prompts", "WARN", evidence=f"Error: {str(e)[:100]}")

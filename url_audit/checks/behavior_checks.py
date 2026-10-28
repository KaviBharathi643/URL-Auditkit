from ..utils import CheckResult, fetch, count_redirects
import re, requests

def check_redirects(url: str):
    # (33)
    try:
        n = count_redirects(url)
        status = "WARN" if n > 2 else "PASS"
        return CheckResult(33, "Redirects and Shortened URLs", status, evidence=f"redirects={n}")
    except Exception as e:
        return CheckResult(33, "Redirects and Shortened URLs", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_popups_downloads(url: str):
    # (34)
    try:
        resp, html, soup = fetch(url)
        if not html:
            return CheckResult(34, "Pop-Ups or Forced Downloads", "WARN", evidence="No HTML")
        poplike = bool(re.search(r"(window\.open|showModal|confirm\(|prompt\()", html, re.I))
        content_type = resp.headers.get("content-type", "").lower() if resp else ""
        downloady = bool(re.search(r"download=", html, re.I)) or ("application/octet-stream" in content_type)
        verdict = "WARN" if (poplike or downloady) else "PASS"
        return CheckResult(34, "Pop-Ups or Forced Downloads", verdict, evidence=f"popup={poplike} downloadish={downloady}")
    except Exception as e:
        return CheckResult(34, "Pop-Ups or Forced Downloads", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_suspicious_requests(url: str):
    # (35)
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(35, "Suspicious Login or Payment Requests", "WARN", evidence="No HTML")
        text = soup.get_text(" ").lower()
        flags = any(k in text for k in ["login","password","credit card","debit card","otp","cvv","ssn"])
        return CheckResult(35, "Suspicious Login or Payment Requests", "INFO" if flags else "PASS", evidence=f"sensitive_fields={flags}")
    except Exception as e:
        return CheckResult(35, "Suspicious Login or Payment Requests", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_url_length(url: str):
    # (36)
    try:
        L = len(url)
        status = "WARN" if L > 120 else "PASS"
        return CheckResult(36, "URL Length and Structure", status, evidence=f"length={L}")
    except Exception as e:
        return CheckResult(36, "URL Length and Structure", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_homoglyph(url: str):
    # (37)
    try:
        url.encode("ascii")
        non_ascii = False
    except (UnicodeEncodeError, UnicodeDecodeError):
        non_ascii = True
    except Exception as e:
        return CheckResult(37, "Typosquatting or Homoglyph Domains", "WARN", evidence=f"Error: {str(e)[:100]}")
    return CheckResult(37, "Typosquatting or Homoglyph Domains", "WARN" if non_ascii else "PASS", evidence=f"non_ascii={non_ascii}")

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

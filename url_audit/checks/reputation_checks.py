from ..utils import CheckResult, http_json
from ..security import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    get_safe_session,
)
import os, requests, dns.resolver, time, base64
from urllib.parse import urlparse


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _domain_from_url(url: str) -> str:
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not host:
            return ""
        try:
            import tldextract
            ext = tldextract.extract(host)
            return ".".join([ext.domain, ext.suffix]) if ext.suffix else host
        except Exception:
            return host
    except Exception:
        return ""


def _lookup_free_blacklists(url: str, domain: str):
    """Use free threat-intel sources (URLhaus + PhishTank) as fallback signals."""
    free_hits = []
    free_notes = []
    client = get_safe_session()
    safe_timeout = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)

    # URLhaus URL lookup
    try:
        uh = client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=safe_timeout,
        )
        if uh.ok:
            uj = uh.json() or {}
            status = (uj.get("query_status") or "").lower()
            if status == "ok":
                free_hits.append("urlhaus:url")
            free_notes.append(f"urlhaus_url={status or 'unknown'}")
        else:
            free_notes.append(f"urlhaus_url_http={uh.status_code}")
    except Exception:
        free_notes.append("urlhaus_url=unavailable")

    # URLhaus host lookup
    if domain:
        try:
            uh_host = client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=safe_timeout,
            )
            if uh_host.ok:
                hj = uh_host.json() or {}
                status = (hj.get("query_status") or "").lower()
                if status == "ok":
                    free_hits.append("urlhaus:host")
                free_notes.append(f"urlhaus_host={status or 'unknown'}")
            else:
                free_notes.append(f"urlhaus_host_http={uh_host.status_code}")
        except Exception:
            free_notes.append("urlhaus_host=unavailable")

    # PhishTank lookup
    try:
        pt = client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "url-audit-kit/1.0"},
            timeout=safe_timeout,
        )
        if pt.ok:
            pj = pt.json() or {}
            in_db = bool(((pj.get("results") or {}).get("in_database")))
            verified = bool(((pj.get("results") or {}).get("verified")))
            valid = bool(((pj.get("results") or {}).get("valid")))
            if in_db and (verified or valid):
                free_hits.append("phishtank")
            free_notes.append(f"phishtank_in_db={in_db}")
        else:
            free_notes.append(f"phishtank_http={pt.status_code}")
    except Exception:
        free_notes.append("phishtank=unavailable")

    return free_hits, free_notes

def check_security_blacklists(url: str):
    """
    (25) Reputation in Security Databases (VirusTotal with URLhaus/PhishTank fallback).
    """
    key = os.getenv("VIRUSTOTAL_API_KEY")
    domain = _domain_from_url(url)
    if not key:
        free_hits, free_notes = _lookup_free_blacklists(url, domain)
        if free_hits:
            return CheckResult(
                25,
                "Reputation in Security Databases (VirusTotal)",
                "FAIL",
                evidence=f"free_blacklist_hits={','.join(free_hits)} {' '.join(free_notes)}".strip(),
            )
        all_unavailable = all("unavailable" in note or "http" in note for note in free_notes)
        if all_unavailable and free_notes:
            return CheckResult(
                25,
                "Reputation in Security Databases (VirusTotal)",
                "ERROR",
                evidence=f"Threat intel feeds unavailable (VT key missing, free feeds offline): {' '.join(free_notes)}".strip(),
            )
        return CheckResult(
            25,
            "Reputation in Security Databases (VirusTotal)",
            "PASS",
            evidence=f"Clean in free threat intel databases (URLhaus, PhishTank); {' '.join(free_notes)}".strip(),
        )

    headers = {"x-apikey": key}
    client = get_safe_session()
    vt_timeout = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
    vt_poll_interval = _env_int("VT_POLL_INTERVAL_SECONDS", 2)
    vt_max_analysis_polls = _env_int("VT_MAX_ANALYSIS_POLLS", 3)
    vt_max_url_polls = _env_int("VT_MAX_URL_POLLS", 3)

    # VT url_id is base64url of the original URL, WITHOUT '=' padding
    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    except Exception as e:
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "ERROR", evidence=f"base64url error: {e}")

    # 1) Submit URL for analysis
    try:
        submit = client.post("https://www.virustotal.com/api/v3/urls",
                             headers=headers, data={"url": url}, timeout=vt_timeout)
        if not submit.ok:
            # Fall back to free feeds before erroring out
            free_hits, free_notes = _lookup_free_blacklists(url, domain)
            if free_hits:
                return CheckResult(
                    25,
                    "Reputation in Security Databases (VirusTotal)",
                    "FAIL",
                    evidence=f"vt_submit_{submit.status_code} free_blacklist_hits={','.join(free_hits)}",
                )
            return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "ERROR",
                               evidence=f"VirusTotal submit error {submit.status_code}: {submit.text[:120]}")
        analysis_id = (submit.json().get("data") or {}).get("id")
        if not analysis_id:
            return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "ERROR", evidence="No analysis ID returned by VirusTotal")
    except Exception as e:
        free_hits, free_notes = _lookup_free_blacklists(url, domain)
        if free_hits:
            return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "FAIL",
                               evidence=f"vt_error free_blacklist_hits={','.join(free_hits)}")
        return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "ERROR", evidence=f"VirusTotal operational error: {e}")

    # 2) Poll analyses/{analysis_id} until completed
    analyses_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    completed = False
    last_err = None
    for _ in range(vt_max_analysis_polls):
        time.sleep(vt_poll_interval)
        try:
            r = client.get(analyses_url, headers=headers, timeout=vt_timeout)
            if not r.ok:
                last_err = f"analyses {r.status_code}"
                continue
            status = ((r.json().get("data") or {}).get("attributes") or {}).get("status")
            if (status or "").lower() == "completed":
                completed = True
                break
            last_err = f"analysis status={status or 'unknown'}"
        except Exception as e:
            last_err = f"analyses exception: {e}"

    # 3) Poll urls/{url_id} for consolidated last_analysis_stats
    urls_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    for _ in range(vt_max_url_polls):
        time.sleep(vt_poll_interval)
        try:
            g = client.get(urls_url, headers=headers, timeout=vt_timeout)
            if not g.ok:
                last_err = f"urls {g.status_code}"
                continue
            attrs = ((g.json().get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats")
            if stats:
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                harmless = int(stats.get("harmless", 0) or 0)
                undetected = int(stats.get("undetected", 0) or 0)
                evidence = (f"malicious_engines={malicious} suspicious={suspicious} "
                            f"harmless={harmless} undetected={undetected}")
                status = "FAIL" if (malicious > 0 or suspicious > 0) else "PASS"
                return CheckResult(25, "Reputation in Security Databases (VirusTotal)", status, evidence=evidence, data=stats)
            last_err = "consolidated stats not ready"
        except Exception as e:
            last_err = f"urls exception: {e}"

    # Fallback to free blacklists if VT did not complete
    free_hits, free_notes = _lookup_free_blacklists(url, domain)
    if free_hits:
        return CheckResult(
            25,
            "Reputation in Security Databases (VirusTotal)",
            "FAIL",
            evidence=f"vt_incomplete free_blacklist_hits={','.join(free_hits)} {' '.join(free_notes)}".strip(),
        )
    return CheckResult(25, "Reputation in Security Databases (VirusTotal)", "ERROR",
                       evidence=last_err or "VirusTotal timeout awaiting consolidated stats")


def check_google_safe_browsing(url: str):
    # (25b) Google Safe Browsing v4
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return CheckResult(25, "Google Safe Browsing", "SKIP", evidence="GOOGLE_SAFE_BROWSING_API_KEY not configured")
    body = {
        "client": {"clientId": "url-audit-kit", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION","THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        client = get_safe_session()
        r = client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body, timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
        )
        if not r.ok:
            return CheckResult(25, "Google Safe Browsing", "ERROR", evidence=f"Google Safe Browsing API error: HTTP {r.status_code}")
        j = r.json() or {}
        matches = j.get("matches", [])
        if matches:
            return CheckResult(25, "Google Safe Browsing", "FAIL", evidence=f"matches={len(matches)}", data=matches)
        return CheckResult(25, "Google Safe Browsing", "PASS", evidence="no matches (clean)")
    except Exception as e:
        return CheckResult(25, "Google Safe Browsing", "ERROR", evidence=f"Google Safe Browsing operational error: {e}")

def check_search_visibility(url: str):
    # (26) Google via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(26, "Search Engine Visibility", "SKIP", evidence="Set SERPAPI_API_KEY for SERP check")
    try:
        r = requests.get("https://serpapi.com/search",
                         params={"engine": "google", "q": url, "api_key": key},
                         timeout=20)
        if r.ok:
            j = r.json()
            organic = j.get("organic_results", [])
            status = "INFO" if organic else "WARN"
            return CheckResult(26, "Search Engine Visibility", status, evidence=f"organic_results={len(organic)}")
        return CheckResult(26, "Search Engine Visibility", "WARN", evidence=f"SERP API error: {r.status_code}")
    except Exception as e:
        return CheckResult(26, "Search Engine Visibility", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_social_mentions(url: str):
    # (27) SerpAPI: social sites
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(27, "Social Media/Official Mentions", "SKIP", evidence="Set SERPAPI_API_KEY")
    try:
        domain = _domain_from_url(url)
        if not domain:
            return CheckResult(27, "Social Media/Official Mentions", "WARN", evidence="Could not extract domain")
        q = f'site:twitter.com OR site:x.com OR site:facebook.com OR site:linkedin.com "{domain}"'
        r = requests.get("https://serpapi.com/search",
                         params={"engine": "google", "q": q, "api_key": key},
                         timeout=20)
        if r.ok:
            j = r.json()
            organic = j.get("organic_results", [])
            return CheckResult(27, "Social Media/Official Mentions", "INFO", evidence=f"hits={len(organic)}")
        return CheckResult(27, "Social Media/Official Mentions", "WARN", evidence=f"SERP API error: {r.status_code}")
    except Exception as e:
        return CheckResult(27, "Social Media/Official Mentions", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_wayback(url: str):
    # (28) Wayback Machine presence
    try:
        data = http_json("http://archive.org/wayback/available", params={"url": url})
        if not data:
            return CheckResult(28, "Historical Records (Wayback)", "INFO", evidence="No archive data available")
        archived = bool(data.get("archived_snapshots", {}).get("closest"))
        return CheckResult(28, "Historical Records (Wayback)", "INFO", evidence=f"archived={archived}", data=data)
    except Exception as e:
        return CheckResult(28, "Historical Records (Wayback)", "INFO", evidence=f"Error: {str(e)[:100]}")

def check_news_reviews(url: str):
    # (29) Google News via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(29, "News/Reviews about Domain", "SKIP", evidence="Set SERPAPI_API_KEY")
    try:
        domain = _domain_from_url(url)
        if not domain:
            return CheckResult(29, "News/Reviews about Domain", "WARN", evidence="Could not extract domain")
        q = f'{domain} reviews OR scam OR fraud OR rating'
        r = requests.get("https://serpapi.com/search",
                         params={"engine": "google_news", "q": q, "api_key": key},
                         timeout=20)
        if r.ok:
            items = r.json().get("news_results", [])
            return CheckResult(29, "News/Reviews about Domain", "INFO", evidence=f"news_results={len(items)}")
        return CheckResult(29, "News/Reviews about Domain", "WARN", evidence=f"SERP API error: {r.status_code}")
    except Exception as e:
        return CheckResult(29, "News/Reviews about Domain", "WARN", evidence=f"Error: {str(e)[:100]}")

def _dns_query(name: str) -> bool:
    try:
        if not name:
            return False
        dns.resolver.resolve(name, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False
    except Exception:
        return False

def check_blacklists_email_filters(url: str):
    # (30) Spamhaus DBL + SURBL via DNS (no API key required)
    try:
        domain = _domain_from_url(url)
        if not domain:
            return CheckResult(30, "Blacklist Status in Email/URL Filters", "WARN", evidence="Could not extract domain")
        # Spamhaus DBL lookup: query domain.dbl.spamhaus.org; any A response => listed
        s_listed = _dns_query(f"{domain}.dbl.spamhaus.org")
        # SURBL lookup: query domain.multi.surbl.org; A response => listed
        u_listed = _dns_query(f"{domain}.multi.surbl.org")

        evidence = f"spamhaus_dbl={s_listed} surbl={u_listed}"
        if s_listed or u_listed:
            return CheckResult(30, "Blacklist Status in Email/URL Filters", "FAIL", evidence=evidence)
        return CheckResult(30, "Blacklist Status in Email/URL Filters", "PASS", evidence=evidence)
    except Exception as e:
        return CheckResult(30, "Blacklist Status in Email/URL Filters", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_user_community_feedback(url: str):
    # (31) Forums via SerpAPI (optional)
    key = os.getenv("SERPAPI_API_KEY")
    if not key:
        return CheckResult(31, "User Community Feedback", "SKIP", evidence="Set SERPAPI_API_KEY")
    try:
        domain = _domain_from_url(url)
        if not domain:
            return CheckResult(31, "User Community Feedback", "WARN", evidence="Could not extract domain")
        q = f'site:reddit.com OR site:stackexchange.com OR site:quora.com "{domain}"'
        r = requests.get("https://serpapi.com/search",
                         params={"engine": "google", "q": q, "api_key": key},
                         timeout=20)
        if r.ok:
            organic = r.json().get("organic_results", [])
            return CheckResult(31, "User Community Feedback", "INFO", evidence=f"threads_found={len(organic)}")
        return CheckResult(31, "User Community Feedback", "WARN", evidence=f"SERP API error: {r.status_code}")
    except Exception as e:
        return CheckResult(31, "User Community Feedback", "WARN", evidence=f"Error: {str(e)[:100]}")

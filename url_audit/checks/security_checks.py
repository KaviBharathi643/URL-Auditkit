import os
import ssl
import socket
import json
import time
from functools import lru_cache
from datetime import datetime, timezone
from typing import Tuple, Optional

import requests

from ..utils import CheckResult, domain_parts


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

# -------------------------------
# Helpers
# -------------------------------

@lru_cache(maxsize=512)
def _resolve_host(url: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return None, None
        ip = socket.gethostbyname(host)
        return host, ip
    except (socket.gaierror, socket.timeout, OSError):
        return None, None
    except Exception:
        return None, None

def _get_cert(host: str, port: int = 443):
    """
    Return (peercert_dict, peercert_binary) using stdlib ssl.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info = ssock.getpeercert()
                return info, der
    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError) as e:
        raise e

def _parse_not_after(peercert_info) -> Optional[datetime]:
    """
    peercert_info is ssl.SSLSocket.getpeercert() result (dict) where 'notAfter' is like 'May 10 12:00:00 2026 GMT'
    """
    try:
        na = peercert_info.get("notAfter")
        if not na:
            return None
        # Example: 'May 10 12:00:00 2026 GMT'
        dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _parse_subject_common_name(peercert_info) -> Optional[str]:
    try:
        subj = peercert_info.get("subject") or []
        # subject is a tuple of tuples like ((('commonName','example.com'),), (('organizationName','...'),))
        for item in subj:
            for pair in item:
                if pair[0].lower() in ("commonname", "cn"):
                    return pair[1]
        return None
    except Exception:
        return None

def _parse_issuer(peercert_info) -> Optional[str]:
    try:
        issuer = peercert_info.get("issuer") or []
        parts = []
        for item in issuer:
            for pair in item:
                k = pair[0].lower()
                v = pair[1]
                if k in ("organizationname", "commonname", "countryname", "stateorprovincename"):
                    parts.append(v)
        return " ".join(parts) if parts else None
    except Exception:
        return None


# -------------------------------
# Checks (IDs 9–16 group)
# -------------------------------

def check_ssl_validity(url: str) -> CheckResult:
    # (9) SSL/TLS Certificate Validity
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence="no host")
        info, _ = _get_cert(host, 443)
        not_after = _parse_not_after(info)
        cn = _parse_subject_common_name(info)
        if not_after:
            days_left = (not_after - datetime.now(timezone.utc)).days
            status = "PASS" if days_left > 14 else "WARN"
            return CheckResult(9, "SSL/TLS Certificate Validity", status, evidence=f"subject={cn} expires_in_days={days_left}")
        return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence=f"subject={cn} no expiry parsed")
    except Exception as e:
        return CheckResult(9, "SSL/TLS Certificate Validity", "WARN", evidence=str(e))


def check_https_presence(url: str) -> CheckResult:
    # (10) Presence of HTTPS
    try:
        scheme = url.split(":", 1)[0].lower()
        return CheckResult(10, "Presence of HTTPS", "PASS" if scheme == "https" else "WARN", evidence=f"scheme={scheme}")
    except Exception as e:
        return CheckResult(10, "Presence of HTTPS", "WARN", evidence=str(e))


def check_certificate_issuer(url: str) -> CheckResult:
    # (11) Certificate Issuer (Reputable CA)
    try:
        _, host, _ = domain_parts(url)
        if not host:
            return CheckResult(11, "Certificate Issuer (Reputable CA)", "WARN", evidence="no host")
        info, _ = _get_cert(host, 443)
        issuer = _parse_issuer(info)
        status = "PASS" if issuer else "WARN"
        return CheckResult(11, "Certificate Issuer (Reputable CA)", status, evidence=f"issuer={issuer}")
    except Exception as e:
        return CheckResult(11, "Certificate Issuer (Reputable CA)", "WARN", evidence=str(e))


def check_security_headers(url: str):
    # (12) Security Headers (CSP/HSTS/XFO)
    results = []
    try:
        r = requests.get(url, timeout=20, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        # CSP
        csp_present = "content-security-policy" in headers
        results.append(CheckResult(12, "Security Header: Content-Security-Policy", "PASS" if csp_present else "WARN", evidence=f"Content-Security-Policy present={csp_present}"))
        # HSTS
        hsts_present = "strict-transport-security" in headers
        results.append(CheckResult(12, "Security Header: Strict-Transport-Security", "PASS" if hsts_present else "WARN", evidence=f"Strict-Transport-Security present={hsts_present}"))
        # X-Frame-Options
        xfo_present = "x-frame-options" in headers
        results.append(CheckResult(12, "Security Header: X-Frame-Options", "PASS" if xfo_present else "WARN", evidence=f"X-Frame-Options present={xfo_present}"))

    except Exception as e:
        results.append(CheckResult(12, "Security Header: Content-Security-Policy", "WARN", evidence=str(e)))
        results.append(CheckResult(12, "Security Header: Strict-Transport-Security", "WARN", evidence=str(e)))
        results.append(CheckResult(12, "Security Header: X-Frame-Options", "WARN", evidence=str(e)))
    return results


def check_ip_reputation(url: str) -> CheckResult:
    # (13) IP Reputation & Hosting – simple AbuseIPDB score if key provided
    try:
        host, ip = _resolve_host(url)
        if not ip:
            return CheckResult(13, "IP Reputation & Hosting", "WARN", evidence="could not resolve host")
        abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        score = None
        if abuse_key:
            q = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": abuse_key, "Accept": "application/json"},
                timeout=20,
            )
            if q.ok:
                score = (q.json().get("data") or {}).get("abuseConfidenceScore")
        status = "PASS" if (score is None or (isinstance(score, int) and score < 25)) else "WARN"
        return CheckResult(13, "IP Reputation & Hosting", status, evidence=f"ip={ip} score={score if score is not None else 0}")
    except Exception as e:
        return CheckResult(13, "IP Reputation & Hosting", "WARN", evidence=str(e))


def check_server_geolocation(url: str) -> CheckResult:
    # (14) Geolocation of Server via ipinfo if available
    try:
        host, ip = _resolve_host(url)
        if not ip:
            return CheckResult(14, "Geolocation of Server", "WARN", evidence="could not resolve host")
        token = os.getenv("IPINFO_TOKEN")
        if token:
            r = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": token}, timeout=15)
            if r.ok:
                country = (r.json().get("country") or "unknown")
                return CheckResult(14, "Geolocation of Server", "INFO", evidence=f"country={country}", data=r.json())
        return CheckResult(14, "Geolocation of Server", "INFO", evidence="country=unknown")
    except Exception as e:
        return CheckResult(14, "Geolocation of Server", "WARN", evidence=str(e))


def check_hosting_provider(url: str) -> CheckResult:
    # (15) Hosting Provider Legitimacy via ipinfo org if available
    try:
        host, ip = _resolve_host(url)
        if not ip:
            return CheckResult(15, "Hosting Provider Legitimacy", "WARN", evidence="could not resolve host")
        token = os.getenv("IPINFO_TOKEN")
        if token:
            r = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": token}, timeout=15)
            if r.ok:
                org = r.json().get("org")
                return CheckResult(15, "Hosting Provider Legitimacy", "INFO", evidence=f"org={org}", data=r.json())
        return CheckResult(15, "Hosting Provider Legitimacy", "INFO", evidence="org=unknown")
    except Exception as e:
        return CheckResult(15, "Hosting Provider Legitimacy", "WARN", evidence=str(e))


# ---- Page Load Speed (16): PSI first, GTmetrix fallback ----
def check_page_load_speed(url: str):
    """
    (16) Page Load Speed
    Strategy:
      A) Try Google PageSpeed Insights v5 (desktop, then mobile). Uses PAGESPEED_API_KEY if set (optional).
      B) If PSI fails for both, fall back to GTmetrix v2 (if GTMETRIX_API_KEY is set).
    You can disable GTmetrix fallback by setting DISABLE_GTMETRIX=1 in .env
    """
    psi_timeout = _env_int("PAGESPEED_TIMEOUT_SECONDS", 12)
    gtmetrix_submit_timeout = _env_int("GTMETRIX_SUBMIT_TIMEOUT_SECONDS", 15)
    gtmetrix_poll_timeout = _env_int("GTMETRIX_POLL_TIMEOUT_SECONDS", 10)
    gtmetrix_poll_interval = _env_int("GTMETRIX_POLL_INTERVAL_SECONDS", 2)
    gtmetrix_max_polls = _env_int("GTMETRIX_MAX_POLLS", 6)

    def _psi_once(strategy: str):
        try:
            psi_params = {"url": url, "strategy": strategy, "category": "performance"}
            psi_key = os.getenv("PAGESPEED_API_KEY")  # optional, but increases quota
            if psi_key:
                psi_params["key"] = psi_key

            psi = requests.get(
                "https://www.googleapis.com/pagespeedonline/v5/runPagespeed",
                params=psi_params,
                timeout=psi_timeout,
            )
            if psi.ok:
                j = psi.json()
                lh = (j.get("lighthouseResult") or {})
                cats = (lh.get("categories") or {})
                perf = (cats.get("performance") or {}).get("score")
                audits = (lh.get("audits") or {})
                fcp = (audits.get("first-contentful-paint") or {}).get("displayValue")
                lcp = (audits.get("largest-contentful-paint") or {}).get("displayValue")
                tbt = (audits.get("total-blocking-time") or {}).get("displayValue")
                cls = (audits.get("cumulative-layout-shift") or {}).get("displayValue")

                bits = [f"strategy={strategy}"]
                if isinstance(perf, (int, float)):
                    bits.append(f"Performance={int(perf * 100)}")
                if fcp: bits.append(f"FCP={fcp}")
                if lcp: bits.append(f"LCP={lcp}")
                if tbt: bits.append(f"TBT={tbt}")
                if cls: bits.append(f"CLS={cls}")

                return CheckResult(16, "Page Load Speed", "INFO", evidence=", ".join(bits), data=j)
            else:
                # Capture concise PSI error for evidence
                return None, f"PSI({strategy}) {psi.status_code}: {psi.text[:160]}"
        except Exception as e:
            return None, f"PSI({strategy}) exception: {e}"

    # Try PSI (desktop then mobile)
    psi_res = _psi_once("desktop")
    if isinstance(psi_res, CheckResult):
        return psi_res
    desktop_err = psi_res[1] if psi_res else None

    psi_res = _psi_once("mobile")
    if isinstance(psi_res, CheckResult):
        return psi_res
    mobile_err = psi_res[1] if psi_res else None

    # If we’re here, PSI failed both; optionally fall back to GTmetrix
    if os.getenv("DISABLE_GTMETRIX") == "1":
        err = desktop_err or mobile_err or "PSI unavailable"
        return CheckResult(16, "Page Load Speed", "WARN", evidence=err)

    key = os.getenv("GTMETRIX_API_KEY")
    if not key:
        err = desktop_err or mobile_err or "PSI unavailable"
        return CheckResult(16, "Page Load Speed", "WARN", evidence=err)

    headers_post = {
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    headers_get = {"Accept": "application/vnd.api+json"}
    primary_location = os.getenv("GTMETRIX_LOCATION")
    secondary_location = os.getenv("GTMETRIX_LOCATION_SECONDARY")

    def _build_payload(loc: str = None):
        attributes = {"url": url}
        if loc:
            attributes["location"] = loc
        return {"data": {"type": "test", "attributes": attributes}}

    def _run_once(payload):
        try:
            r = requests.post(
                "https://gtmetrix.com/api/2.0/tests",
                auth=(key, "random"),
                headers=headers_post,
                json=payload,
                timeout=gtmetrix_submit_timeout,
            )
            if not r.ok:
                return CheckResult(16, "Page Load Speed", "WARN",
                                   evidence=f"GTmetrix submit {r.status_code}: {r.text[:160]}")
            j = r.json()
            data_obj = j.get("data", {}) if isinstance(j, dict) else {}
            poll = (data_obj.get("links") or {}).get("self")
            test_id = data_obj.get("id")
            if not poll and test_id:
                poll = f"https://gtmetrix.com/api/2.0/tests/{test_id}"
            if not poll:
                return CheckResult(16, "Page Load Speed", "WARN", evidence="GTmetrix: no poll URL")

            # Bound polling time to avoid long-running scans.
            for _ in range(gtmetrix_max_polls):
                time.sleep(gtmetrix_poll_interval)
                g = requests.get(
                    poll,
                    auth=(key, "random"),
                    headers=headers_get,
                    timeout=gtmetrix_poll_timeout,
                )
                if not g.ok:
                    continue
                dj = g.json()
                attrs = (dj.get("data") or {}).get("attributes") or {}
                state = attrs.get("state") or attrs.get("status")
                if state == "completed":
                    pagespeed = attrs.get("pagespeed_score")
                    yslow = attrs.get("yslow_score")
                    bits = []
                    if pagespeed is not None: bits.append(f"PageSpeed={pagespeed}")
                    if yslow is not None: bits.append(f"YSlow={yslow}")
                    return CheckResult(16, "Page Load Speed", "INFO", evidence=", ".join(bits) or "completed", data=dj)
                if state == "error":
                    detail_raw = (attrs.get("error") or attrs.get("error_message") or "unknown error")
                    detail = str(detail_raw).lower()
                    # Quiet the Lighthouse edge-case: treat "did not paint any content" as INFO
                    if "did not paint any content" in detail:
                        return CheckResult(16, "Page Load Speed", "INFO", evidence=f"GTmetrix note: {detail_raw}")
                    return CheckResult(16, "Page Load Speed", "WARN", evidence=f"GTmetrix error: {detail_raw}")
            return CheckResult(16, "Page Load Speed", "WARN", evidence="GTmetrix: timeout polling result")
        except Exception as e:
            return CheckResult(16, "Page Load Speed", "WARN", evidence=f"GTmetrix exception: {e}")

    # First attempt
    result = _run_once(_build_payload(primary_location))
    # Retry once on likely-transient errors
    transient = ("read timeout", "connect timeout", "server busy", "temporary", "temporarily", "gateway timeout", "queued", "timeout")
    if result.status == "WARN" and any(m in (result.evidence or "").lower() for m in transient):
        time.sleep(3)
        return _run_once(_build_payload(secondary_location or primary_location))
    return result

def check_mozilla_observatory(url: str) -> CheckResult:
    """
    Mozilla HTTP Observatory:
      - Kick off a fresh scan (hidden, rescan)
      - Poll /analyze until FINISHED (or a short timeout)
      - Return INFO with grade/score when available
    """
    import time
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return CheckResult(17, "Mozilla Observatory", "WARN", evidence="no host")

        base = "https://http-observatory.security.mozilla.org/api/v1"

        # Start or refresh a scan; 'hidden' keeps it off the public leaderboard
        attempts = 0
        last_err = None
        while attempts < 3:
            attempts += 1
            start = requests.post(
                f"{base}/analyze",
                params={"host": host, "hidden": "true", "rescan": "true"},
                timeout=30
            )
            if start.ok:
                break
            code = start.status_code
            body = start.text[:160]
            # transient upstream issues – don’t alarm the user
            if code in (429, 502, 503, 504):
                last_err = f"transient {code}: {body}"
                time.sleep(2 * attempts)  # small backoff then retry
                continue
            return CheckResult(17, "Mozilla Observatory", "WARN",
                               evidence=f"start {code}: {body}")

        if not start.ok:
            # after retries, still transient → mark as INFO (non-blocking)
            return CheckResult(17, "Mozilla Observatory", "INFO",
                               evidence=last_err or "transient error")

        last_err = None
        # Poll for result
        for _ in range(20):  # ~60s total
            time.sleep(3)
            r = requests.get(f"{base}/analyze", params={"host": host}, timeout=30)
            if not r.ok:
                last_err = f"poll {r.status_code}: {r.text[:160]}"
                continue

            j = r.json() or {}
            state = (j.get("state") or "").upper()
            grade = j.get("grade")
            score = j.get("score")

            if state == "FINISHED":
                ev = []
                if grade: ev.append(f"grade={grade}")
                if isinstance(score, int): ev.append(f"score={score}")
                return CheckResult(17, "Mozilla Observatory", "INFO",
                                   evidence=", ".join(ev) or "finished",
                                   data=j)

            if state in ("FAILED", "ABORTED"):
                return CheckResult(17, "Mozilla Observatory", "WARN",
                                   evidence=f"state={state}")

            last_err = f"state={state or 'unknown'}"

        return CheckResult(17, "Mozilla Observatory", "WARN",
                           evidence=last_err or "timeout")
    except Exception as e:
        return CheckResult(17, "Mozilla Observatory", "WARN", evidence=str(e))

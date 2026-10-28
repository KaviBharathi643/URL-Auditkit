import os, re, socket, ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract
import dns.resolver

TIMEOUT = 15

def get_env(name: str, default: Optional[str]=None) -> Optional[str]:
    v = os.getenv(name, default)
    return v if v not in ("", None) else None

@dataclass
class CheckResult:
    id: int
    name: str
    status: str  # PASS | WARN | FAIL | SKIP | INFO
    evidence: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

def fetch(url: str) -> Tuple[Optional[requests.Response], Optional[str], Optional[BeautifulSoup]]:
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "URL-Audit-Kit/1.0"})
        html = resp.text if resp.content else ""
        soup = BeautifulSoup(html, "lxml") if html else None
        return resp, html, soup
    except Exception:
        return None, None, None

def head(url: str) -> Optional[requests.Response]:
    try:
        return requests.head(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": "URL-Audit-Kit/1.0"})
    except Exception:
        return None

def get_cert_chain(hostname: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

_EXTRACTOR = tldextract.TLDExtract(fallback_to_snapshot=True)

def domain_parts(url: str):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        ext = _EXTRACTOR(host)
    except Exception:
        ext = tldextract.TLDExtract(suffix_list_urls=())(host)
    return parsed, host, ext

def txt_records(domain: str) -> List[str]:
    out = []
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            out.extend([b.decode("utf-8") if isinstance(b, bytes) else str(b) for b in rdata.strings])
    except Exception:
        pass
    return out

def mx_records(domain: str) -> List[str]:
    try:
        return [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX")]
    except Exception:
        return []

def whois_lookup(domain: str):
    try:
        import whois
        return whois.whois(domain)
    except Exception:
        return None

def http_json(url: str, params=None, headers=None):
    try:
        r = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None

def post_json(url: str, json_body=None, headers=None):
    try:
        r = requests.post(url, json=json_body, headers=headers, timeout=TIMEOUT)
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None

def normalize_status(ok: bool, warn: bool=False, skip: bool=False) -> str:
    if skip:
        return "SKIP"
    if ok and not warn:
        return "PASS"
    if warn and ok:
        return "WARN"
    return "FAIL"

def has_security_header(headers: dict, key: str) -> bool:
    return any(h.lower() == key.lower() for h in headers.keys())

def count_redirects(url: str) -> int:
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return len(r.history)
    except Exception:
        return 0

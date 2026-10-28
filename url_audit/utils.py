import os, re, socket, ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract
import dns.resolver

from .security import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_SCAN_DEADLINE,
    InvalidURLError,
    RedirectSecurityError,
    SSRFError,
    URLSecurityError,
    create_default_ssl_context,
    get_safe_session,
    resolve_and_validate_destination,
    safe_request,
    safe_socket_create_connection,
    validate_url,
)

TIMEOUT = int(DEFAULT_CONNECT_TIMEOUT + DEFAULT_READ_TIMEOUT)

# Configure controlled DNS resolver limits
_DEFAULT_DNS_LIFETIME = 3.0

def get_env(name: str, default: Optional[str]=None) -> Optional[str]:
    v = os.getenv(name, default)
    return v if v not in ("", None) else None

@dataclass
class CheckResult:
    id: int
    name: str
    status: str  # PASS | WARN | FAIL | ERROR | SKIP | INFO
    evidence: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

def fetch(url: str) -> Tuple[Optional[requests.Response], Optional[str], Optional[BeautifulSoup]]:
    try:
        resp, _ = safe_request("GET", url, allow_redirects=True)
        html = resp.text if resp.content else ""
        soup = BeautifulSoup(html, "lxml") if html else None
        return resp, html, soup
    except Exception:
        return None, None, None

def head(url: str) -> Optional[requests.Response]:
    try:
        resp, _ = safe_request("HEAD", url, allow_redirects=True)
        return resp
    except Exception:
        return None

def get_cert_chain(hostname: str, port: int = 443):
    try:
        ctx = create_default_ssl_context()
        sock, _ = safe_socket_create_connection(
            hostname=hostname,
            port=port,
            timeout=DEFAULT_CONNECT_TIMEOUT,
            ssl_context=ctx,
            server_hostname=hostname,
        )
        with sock:
            cert = sock.getpeercert()
            return cert
    except Exception:
        return None

def domain_parts(url: str):
    from collections import namedtuple
    from .domain_intel import parse_domain_info

    info = parse_domain_info(url)
    parsed = urlparse(url)
    host = info.hostname
    ExtResult = namedtuple("ExtractResult", ["subdomain", "domain", "suffix"])
    ext = ExtResult(subdomain=info.subdomain, domain=info.domain, suffix=info.suffix)
    return parsed, host, ext

def txt_records(domain: str) -> List[str]:
    out = []
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return out
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DEFAULT_DNS_LIFETIME
        for rdata in resolver.resolve(clean_domain, "TXT"):
            out.extend([b.decode("utf-8") if isinstance(b, bytes) else str(b) for b in rdata.strings])
    except Exception:
        pass
    return out

def mx_records(domain: str) -> List[str]:
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DEFAULT_DNS_LIFETIME
        return [str(r.exchange).rstrip(".") for r in resolver.resolve(clean_domain, "MX")]
    except Exception:
        return []

def whois_lookup(domain: str):
    clean_domain = (domain or "").strip().lower()
    if not clean_domain:
        return None
    try:
        # Pre-validate domain is not an SSRF / internal target
        resolve_and_validate_destination(clean_domain, 43)
        import whois
        return whois.whois(clean_domain)
    except Exception:
        return None

def http_json(url: str, params=None, headers=None):
    try:
        client = get_safe_session()
        r = client.get(url, params=params, headers=headers, timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT))
        if r.ok:
            return r.json()
    except Exception:
        return None
    return None

def post_json(url: str, json_body=None, headers=None):
    try:
        client = get_safe_session()
        r = client.post(url, json=json_body, headers=headers, timeout=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT))
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
        _, chain = safe_request("GET", url, allow_redirects=True)
        return max(0, len(chain) - 1)
    except Exception:
        return 0

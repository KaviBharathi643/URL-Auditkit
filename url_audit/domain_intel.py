"""Domain Intelligence, IDN Normalization, and Phishing Analysis for URL Audit Kit.

Provides:
- Standards-aware domain parsing via Public Suffix List (PSL)
- RFC-compliant IDN and Punycode normalization and validation
- Confusable character & mixed-script homograph detection
- Multi-signal brand impersonation, typosquatting & deceptive subdomain detection
- Granular DNS outcome classification (RESOLVED, NXDOMAIN, TIMEOUT, TEMPORARY_FAILURE, NO_ANSWER)
"""

from __future__ import annotations

import ipaddress
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import idna
import tldextract
import dns.resolver
import dns.exception

from .security import parse_ip_safe


# ---------------------------------------------------------------------------
# Configurable Protected Brands & Official Domains
# ---------------------------------------------------------------------------

DEFAULT_BRAND_PROFILES: Dict[str, Dict[str, Any]] = {
    "google": {
        "name": "Google",
        "official_domains": {
            "google.com",
            "google.co.uk",
            "google.ca",
            "google.de",
            "google.fr",
            "google.com.au",
            "gmail.com",
            "googleblog.com",
            "withgoogle.com",
            "gstatic.com",
            "googleapis.com",
        },
        "keywords": ["google", "gmail", "googledrive"],
    },
    "apple": {
        "name": "Apple",
        "official_domains": {
            "apple.com",
            "icloud.com",
            "apple-support.com",
            "me.com",
            "apple.co",
            "apple.news",
        },
        "keywords": ["apple", "icloud", "appleid"],
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": {
            "microsoft.com",
            "live.com",
            "office.com",
            "outlook.com",
            "azure.com",
            "microsoftonline.com",
            "bing.com",
            "msn.com",
            "sharepoint.com",
            "office365.com",
        },
        "keywords": ["microsoft", "office365", "onedrive", "outlook", "azure", "mslive"],
    },
    "paypal": {
        "name": "PayPal",
        "official_domains": {
            "paypal.com",
            "paypal.me",
            "paypal-communication.com",
            "paypal-community.com",
        },
        "keywords": ["paypal", "paypalme"],
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": {
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.fr",
            "amazon.co.jp",
            "amazon.ca",
            "aws.amazon.com",
            "amazon.com.au",
            "media-amazon.com",
            "primevideo.com",
        },
        "keywords": ["amazon", "primevideo"],
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": {
            "netflix.com",
            "netflixinvestor.com",
            "nflxext.com",
            "nflximg.net",
            "nflxvideo.net",
        },
        "keywords": ["netflix", "nflx"],
    },
    "steam": {
        "name": "Steam",
        "official_domains": {
            "steampowered.com",
            "steamcommunity.com",
            "valvesoftware.com",
            "steamstatic.com",
        },
        "keywords": ["steam", "steampowered", "steamcommunity"],
    },
    "binance": {
        "name": "Binance",
        "official_domains": {
            "binance.com",
            "binance.org",
            "binance.us",
            "binance.me",
            "binance.vision",
        },
        "keywords": ["binance"],
    },
}

# High-risk security/credential terminology frequently combined with brand phishing
SUSPICIOUS_PHISHING_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "verify",
    "verification",
    "security",
    "account",
    "update",
    "recovery",
    "recover",
    "password",
    "wallet",
    "banking",
    "authenticate",
    "auth",
    "confirm",
    "confirmation",
    "portal",
    "billing",
    "support",
    "helpdesk",
    "unlock",
    "secure",
    "checkpoint",
    "kyc",
}

# Confusable homoglyphs mapping Cyrillic/Greek/other lookalikes to Latin letters
CONFUSABLE_HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # Cyrillic small a
    "\u0441": "c",  # Cyrillic small es
    "\u0435": "e",  # Cyrillic small ie
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0455": "s",  # Cyrillic small dze
    "\u0445": "x",  # Cyrillic small ha
    "\u0443": "y",  # Cyrillic small u
    "\u0456": "i",  # Cyrillic small Byelorussian-Ukrainian i
    "\u0458": "j",  # Cyrillic small je
    "\u0491": "g",  # Cyrillic small ghe with upturn
    # Cyrillic uppercase
    "\u0410": "A",
    "\u0412": "B",
    "\u0421": "C",
    "\u0415": "E",
    "\u041d": "H",
    "\u0406": "I",
    "\u0408": "J",
    "\u041a": "K",
    "\u041c": "M",
    "\u041e": "O",
    "\u0420": "P",
    "\u0422": "T",
    "\u0425": "X",
    # Greek lowercase
    "\u03b1": "a",  # Greek small alpha
    "\u03bf": "o",  # Greek small omicron
    "\u03bd": "v",  # Greek small nu
    "\u03c1": "p",  # Greek small rho
    "\u03c4": "t",  # Greek small tau
    "\u03b9": "i",  # Greek small iota
    "\u03ba": "k",  # Greek small kappa
    "\u03c5": "u",  # Greek small upsilon
    "\u03c7": "x",  # Greek small chi
    # Greek uppercase
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
}

# Visual typosquatting leet-speak substitutions
VISUAL_LEET_SUBSTITUTIONS: List[Tuple[str, str]] = [
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("4", "a"),
    ("5", "s"),
    ("8", "b"),
    ("vv", "w"),
    ("rn", "m"),
    ("cl", "d"),
]

_PSL_EXTRACTOR = tldextract.TLDExtract(fallback_to_snapshot=True, include_psl_private_domains=True)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ParsedDomainInfo:
    """Detailed domain structure parsed according to the Public Suffix List (PSL)."""
    raw_input: str
    hostname: str                 # Lowercase Punycode / ASCII representation
    unicode_hostname: str         # Lowercase U-label Unicode representation
    is_ip: bool                   # True if host is an IPv4 or IPv6 address literal
    ip_version: Optional[int] = None
    is_valid_syntax: bool = True
    syntax_error: Optional[str] = None
    
    # Domain structure (empty for IP literals)
    subdomain: str = ""           # e.g. "login.paypal.com"
    domain: str = ""              # e.g. "attacker" (SLD label)
    suffix: str = ""              # e.g. "co.uk" (Public Suffix)
    registrable_domain: str = ""  # e.g. "attacker.co.uk" (eTLD+1)
    
    # IDN & Script metadata
    is_idn: bool = False          # Hostname contains non-ASCII characters or xn--
    is_punycode: bool = False     # Hostname uses Punycode encoding
    labels: List[str] = field(default_factory=list)
    unicode_labels: List[str] = field(default_factory=list)
    label_scripts: List[Set[str]] = field(default_factory=list)
    is_mixed_script: bool = False
    confusables_detected: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BrandMatchResult:
    """Outcome of brand impersonation and phishing analysis."""
    is_impersonation: bool
    is_official: bool
    matched_brand: Optional[str] = None
    impersonation_type: Optional[str] = None  # e.g. "DECEPTIVE_SUBDOMAIN", "EMBEDDED_BRAND", "TYPOSQUAT", "HOMOGLYPH"
    severity: str = "NONE"                    # "NONE", "LOW", "MEDIUM", "HIGH"
    details: str = ""
    security_keywords_found: List[str] = field(default_factory=list)
    similarity_score: float = 0.0


@dataclass
class DNSOutcome:
    """Granular classification of DNS resolution outcome."""
    outcome: str                  # "RESOLVED", "NXDOMAIN", "TIMEOUT", "TEMPORARY_FAILURE", "NO_ANSWER", "INVALID_HOST"
    status: str                   # "PASS", "WARN", "ERROR"
    resolved_ips: List[str] = field(default_factory=list)
    evidence: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 1. Standards-Aware Domain Parsing & IDN Normalization
# ---------------------------------------------------------------------------

def _get_char_script(char: str) -> str:
    """Returns the primary Unicode script family for a character."""
    if char.isdigit() or char in "-_.":
        return "COMMON"
    try:
        name = unicodedata.name(char, "")
    except ValueError:
        return "UNKNOWN"
    
    first_word = name.split()[0] if name else "UNKNOWN"
    if first_word in {"LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "DEVANAGARI", "HIRAGANA", "KATAKANA", "BENGALI", "THAI"}:
        return first_word
    if "CJK" in name or "IDEOGRAPH" in name:
        return "HAN"
    return first_word


def _extract_host_string(input_str: str) -> str:
    """Extracts raw host string from a URL or bare domain input."""
    s = (input_str or "").strip()
    if "://" in s:
        parsed = urlparse(s)
        return parsed.hostname or ""
    # Strip any path or port from bare domain
    if "/" in s:
        s = s.split("/", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[-1]
    if ":" in s and not s.startswith("["):
        # Handle port on ipv4/domain
        s = s.split(":", 1)[0]
    return s.strip("[]")


def parse_domain_info(input_str: str) -> ParsedDomainInfo:
    """Parses a URL or hostname into its PSL components, IDN forms, and script metadata.
    
    Guarantees:
    - IP literals (IPv4/IPv6) are isolated and NOT treated as DNS domains.
    - Public suffixes with multiple dots (.co.uk, .github.io) are correctly recognized.
    - Malformed hostname syntax is rejected before analysis.
    - Unicode and Punycode conversions are safe and standards-aware (UTS 46).
    """
    raw_host = _extract_host_string(input_str)
    if not raw_host:
        return ParsedDomainInfo(
            raw_input=input_str,
            hostname="",
            unicode_hostname="",
            is_ip=False,
            is_valid_syntax=False,
            syntax_error="Empty hostname",
        )

    # 1. Check for IP literals (IPv4 or IPv6)
    direct_ip = parse_ip_safe(raw_host)
    if direct_ip is not None:
        ip_str = str(direct_ip)
        return ParsedDomainInfo(
            raw_input=input_str,
            hostname=ip_str,
            unicode_hostname=ip_str,
            is_ip=True,
            ip_version=direct_ip.version,
            is_valid_syntax=True,
            subdomain="",
            domain="",
            suffix="",
            registrable_domain="",
        )

    # 2. Syntax validation for DNS hostnames
    clean_host = raw_host.strip().rstrip(".")
    if len(clean_host) > 253:
        return ParsedDomainInfo(
            raw_input=input_str,
            hostname=clean_host,
            unicode_hostname=clean_host,
            is_ip=False,
            is_valid_syntax=False,
            syntax_error=f"Hostname exceeds maximum 253 characters ({len(clean_host)})",
        )

    # Reject consecutive dots or invalid punctuation
    if ".." in clean_host:
        return ParsedDomainInfo(
            raw_input=input_str,
            hostname=clean_host,
            unicode_hostname=clean_host,
            is_ip=False,
            is_valid_syntax=False,
            syntax_error="Hostname contains consecutive dots (empty label)",
        )

    # 3. IDNA & Punycode conversion
    is_punycode = "xn--" in clean_host.lower()
    has_non_ascii = any(ord(c) >= 128 for c in clean_host)
    is_idn = is_punycode or has_non_ascii

    try:
        # Canonicalize to Punycode A-label
        ascii_host = idna.encode(clean_host, uts46=True).decode("ascii").lower()
        # Canonicalize to Unicode U-label
        unicode_host = idna.decode(ascii_host).lower()
    except (idna.IDNAError, UnicodeError, ValueError) as exc:
        return ParsedDomainInfo(
            raw_input=input_str,
            hostname=clean_host,
            unicode_hostname=clean_host,
            is_ip=False,
            is_valid_syntax=False,
            syntax_error=f"IDNA normalization failed: {exc}",
            is_idn=is_idn,
            is_punycode=is_punycode,
        )

    # Validate label lengths
    labels = ascii_host.split(".")
    unicode_labels = unicode_host.split(".")
    for lbl in labels:
        if not lbl or len(lbl) > 63:
            return ParsedDomainInfo(
                raw_input=input_str,
                hostname=ascii_host,
                unicode_hostname=unicode_host,
                is_ip=False,
                is_valid_syntax=False,
                syntax_error=f"Hostname label '{lbl}' exceeds 63 characters or is empty",
                is_idn=is_idn,
                is_punycode=is_punycode,
            )
        if lbl.startswith("-") or lbl.endswith("-"):
            return ParsedDomainInfo(
                raw_input=input_str,
                hostname=ascii_host,
                unicode_hostname=unicode_host,
                is_ip=False,
                is_valid_syntax=False,
                syntax_error=f"Hostname label '{lbl}' has invalid leading/trailing hyphen",
                is_idn=is_idn,
                is_punycode=is_punycode,
            )

    # 4. Public Suffix List (PSL) extraction
    try:
        extracted = _PSL_EXTRACTOR(ascii_host)
        subdomain = extracted.subdomain
        domain = extracted.domain
        suffix = extracted.suffix
        registrable_domain = f"{domain}.{suffix}" if (domain and suffix) else domain
    except Exception:
        subdomain = ""
        domain = ascii_host
        suffix = ""
        registrable_domain = ascii_host

    # 5. Script & Confusable Analysis per label
    label_scripts: List[Set[str]] = []
    is_mixed_script = False
    confusables_detected: List[Dict[str, Any]] = []

    for u_label in unicode_labels:
        scripts: Set[str] = set()
        for ch in u_label:
            scr = _get_char_script(ch)
            if scr != "COMMON":
                scripts.add(scr)
            # Detect confusable character
            if ch in CONFUSABLE_HOMOGLYPH_MAP:
                confusables_detected.append({
                    "char": ch,
                    "latin_lookalike": CONFUSABLE_HOMOGLYPH_MAP[ch],
                    "codepoint": f"U+{ord(ch):04X}",
                    "name": unicodedata.name(ch, "UNKNOWN"),
                })
        label_scripts.append(scripts)
        # A single label containing Latin mixed with Cyrillic or Greek is a deceptive homoglyph
        if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
            is_mixed_script = True

    return ParsedDomainInfo(
        raw_input=input_str,
        hostname=ascii_host,
        unicode_hostname=unicode_host,
        is_ip=False,
        ip_version=None,
        is_valid_syntax=True,
        syntax_error=None,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registrable_domain=registrable_domain,
        is_idn=is_idn,
        is_punycode=is_punycode,
        labels=labels,
        unicode_labels=unicode_labels,
        label_scripts=label_scripts,
        is_mixed_script=is_mixed_script,
        confusables_detected=confusables_detected,
    )


# ---------------------------------------------------------------------------
# 2. String Similarity & Typosquatting Analysis
# ---------------------------------------------------------------------------

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        dp[i][0] = i
    for j in range(len2 + 1):
        dp[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,       # deletion
                dp[i][j - 1] + 1,       # insertion
                dp[i - 1][j - 1] + cost  # substitution
            )

    return dp[len1][len2]


def normalize_visual_leet(text: str) -> str:
    """Replaces common visually confusable leet substitutions (e.g. 0->o, 1->l, rn->m)."""
    normalized = text.lower()
    for pattern, replacement in VISUAL_LEET_SUBSTITUTIONS:
        normalized = normalized.replace(pattern, replacement)
    return normalized


def transliterate_confusables(text: str) -> str:
    """Replaces Cyrillic and Greek lookalikes with Latin letters."""
    return "".join(CONFUSABLE_HOMOGLYPH_MAP.get(c, c) for c in text)


# ---------------------------------------------------------------------------
# 3. Brand Impersonation & Phishing Detection
# ---------------------------------------------------------------------------

def detect_brand_impersonation(
    parsed: ParsedDomainInfo,
    brand_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
) -> BrandMatchResult:
    """Evaluates domain structure for brand impersonation, deceptive subdomains, and typosquatting.
    
    Signals evaluated:
    - Official domain verification (PASS/legitimate).
    - Brand name embedded in third-party registrable domain.
    - Deceptive subdomain structure (e.g. paypal.com.account-update.attacker.com).
    - Typosquatting and character substitutions (paypa1, arnazon, g00gle, micros0ft).
    - Whole-script and mixed-script homoglyphs targeting brand names.
    - Correlation with credential/banking phishing keywords.
    """
    if parsed.is_ip or not parsed.is_valid_syntax or not parsed.registrable_domain:
        return BrandMatchResult(is_impersonation=False, is_official=False)

    profiles = brand_profiles or DEFAULT_BRAND_PROFILES
    domain_label = parsed.domain.lower()
    subdomain_str = parsed.subdomain.lower()
    registrable = parsed.registrable_domain.lower()

    # Search for credential / security phishing keywords anywhere in host
    full_host_text = f"{subdomain_str} {domain_label}".replace("-", " ").replace(".", " ")
    tokens = set(full_host_text.split())
    security_keywords_found = sorted(tokens.intersection(SUSPICIOUS_PHISHING_KEYWORDS))

    # Also check if any security keyword is a substring in tokens (e.g. "accountupdate")
    for kw in SUSPICIOUS_PHISHING_KEYWORDS:
        if any(kw in tok and tok != kw for tok in tokens):
            if kw not in security_keywords_found:
                security_keywords_found.append(kw)

    # 1. First, check if domain is an official brand asset
    for brand_key, profile in profiles.items():
        official_domains = {d.lower() for d in profile.get("official_domains", set())}
        if registrable in official_domains:
            return BrandMatchResult(
                is_impersonation=False,
                is_official=True,
                matched_brand=profile["name"],
                severity="NONE",
                details=f"Official {profile['name']} domain ({registrable})",
                security_keywords_found=security_keywords_found,
                similarity_score=1.0,
            )

    # 2. Check for Homoglyph Brand Impersonation (Transliteration Match)
    transliterated_label = transliterate_confusables(parsed.unicode_hostname)
    for brand_key, profile in profiles.items():
        brand_name = profile["name"]
        for kw in profile.get("keywords", [brand_key]):
            if kw in transliterated_label and kw not in parsed.hostname:
                details = f"Homoglyph brand impersonation targeting {brand_name} (confusables detected)"
                return BrandMatchResult(
                    is_impersonation=True,
                    is_official=False,
                    matched_brand=brand_name,
                    impersonation_type="HOMOGLYPH_BRAND_IMPERSONATION",
                    severity="HIGH",
                    details=details,
                    security_keywords_found=security_keywords_found,
                    similarity_score=0.95,
                )

    # 3. Check for Deceptive Subdomain Structure
    # e.g. "paypal.com.account-update.attacker.com"
    if subdomain_str:
        subdomain_tokens = set(subdomain_str.replace("-", ".").split("."))
        for brand_key, profile in profiles.items():
            brand_name = profile["name"]
            official_domains = {d.lower() for d in profile.get("official_domains", set())}
            
            # Check if official domain or brand keyword is in subdomain
            has_brand_subdomain = any(
                off in subdomain_str or brand_key in subdomain_tokens
                for off in official_domains
            )
            if has_brand_subdomain:
                severity = "HIGH" if security_keywords_found else "MEDIUM"
                details = (
                    f"Deceptive subdomain structure: {brand_name} appears in subdomain "
                    f"of unrelated domain '{registrable}'"
                )
                if security_keywords_found:
                    details += f" alongside phishing keywords ({', '.join(security_keywords_found)})"
                return BrandMatchResult(
                    is_impersonation=True,
                    is_official=False,
                    matched_brand=brand_name,
                    impersonation_type="DECEPTIVE_SUBDOMAIN",
                    severity=severity,
                    details=details,
                    security_keywords_found=security_keywords_found,
                    similarity_score=0.90,
                )

    # 4. Check for Brand Name Embedded in Third-Party Registrable Domain
    # e.g. "paypal-security-update.com", "verify-appleid.net"
    domain_tokens = set(domain_label.replace("-", " ").split())
    for brand_key, profile in profiles.items():
        brand_name = profile["name"]
        for kw in profile.get("keywords", [brand_key]):
            # Embedded as whole token or clear substring with hyphens
            if kw in domain_tokens or f"-{kw}" in domain_label or f"{kw}-" in domain_label:
                severity = "HIGH" if security_keywords_found else "MEDIUM"
                details = (
                    f"Brand keyword '{kw}' ({brand_name}) embedded in third-party registrable domain '{registrable}'"
                )
                if security_keywords_found:
                    details += f" with suspicious keywords ({', '.join(security_keywords_found)})"
                return BrandMatchResult(
                    is_impersonation=True,
                    is_official=False,
                    matched_brand=brand_name,
                    impersonation_type="EMBEDDED_BRAND",
                    severity=severity,
                    details=details,
                    security_keywords_found=security_keywords_found,
                    similarity_score=0.85,
                )

    # 5. Check for Typosquatting / Character Substitution on Registrable Domain
    # e.g. "paypa1", "g00gle", "arnazon", "micros0ft", "netfl1x"
    leet_normalized = normalize_visual_leet(domain_label)
    for brand_key, profile in profiles.items():
        brand_name = profile["name"]
        for kw in profile.get("keywords", [brand_key]):
            # Exact match after visual substitution (e.g. paypa1 -> paypal)
            if leet_normalized == kw and domain_label != kw:
                severity = "HIGH" if security_keywords_found else "MEDIUM"
                details = f"Visual typosquatting / character substitution targeting {brand_name} ('{domain_label}' -> '{kw}')"
                return BrandMatchResult(
                    is_impersonation=True,
                    is_official=False,
                    matched_brand=brand_name,
                    impersonation_type="TYPOSQUAT",
                    severity=severity,
                    details=details,
                    security_keywords_found=security_keywords_found,
                    similarity_score=0.90,
                )

            # Levenshtein distance check on root domain label
            dist = levenshtein_distance(domain_label, kw)
            if len(kw) >= 5 and dist in {1, 2}:
                # Avoid false positives for very short domain words
                sim = 1.0 - (dist / max(len(domain_label), len(kw)))
                if sim >= 0.75:
                    severity = "HIGH" if security_keywords_found else "MEDIUM"
                    details = f"Typosquatting edit distance {dist} from {brand_name} keyword '{kw}'"
                    return BrandMatchResult(
                        is_impersonation=True,
                        is_official=False,
                        matched_brand=brand_name,
                        impersonation_type="TYPOSQUAT",
                        severity=severity,
                        details=details,
                        security_keywords_found=security_keywords_found,
                        similarity_score=round(sim, 2),
                    )

    return BrandMatchResult(
        is_impersonation=False,
        is_official=False,
        security_keywords_found=security_keywords_found,
    )


# ---------------------------------------------------------------------------
# 4. Granular DNS Outcome Classification
# ---------------------------------------------------------------------------

def resolve_dns_outcome(hostname: str, timeout: float = 3.0, custom_resolver: Any = None) -> DNSOutcome:
    """Resolves DNS for a hostname and returns a granular, classified outcome.
    
    Guarantees:
    - NXDOMAIN is explicitly flagged as WARN (cannot be treated as proof of safety).
    - Temporary server errors (SERVFAIL, REFUSED) and network timeouts produce ERROR.
    - Valid resolutions return PASS with verified IP list.
    """
    import socket

    clean_host = (hostname or "").strip().rstrip(".").lower()
    if not clean_host:
        return DNSOutcome(
            outcome="INVALID_HOST",
            status="ERROR",
            evidence="Cannot resolve DNS: Hostname is empty",
        )

    # Check if host is direct IP literal
    direct_ip = parse_ip_safe(clean_host)
    if direct_ip is not None:
        return DNSOutcome(
            outcome="RESOLVED",
            status="PASS",
            resolved_ips=[str(direct_ip)],
            evidence=f"Direct IP literal: {direct_ip}",
            details={"is_ip_literal": True},
        )

    # Check for Punycode normalization
    try:
        query_host = idna.encode(clean_host, uts46=True).decode("ascii")
    except Exception:
        query_host = clean_host

    # 1. Custom resolver support (for test injection)
    if custom_resolver is not None:
        try:
            ips = custom_resolver(query_host)
            if ips:
                return DNSOutcome(
                    outcome="RESOLVED",
                    status="PASS",
                    resolved_ips=list(ips),
                    evidence=f"DNS resolved successfully: ips={', '.join(ips[:4])}",
                    details={"ip_count": len(ips)},
                )
        except Exception as exc:
            err_str = str(exc).lower()
            if "nxdomain" in err_str or "not found" in err_str:
                return DNSOutcome(
                    outcome="NXDOMAIN",
                    status="WARN",
                    evidence=f"Domain does not exist in authoritative DNS (NXDOMAIN): host={clean_host}",
                    details={"nxdomain": True},
                )
            if "timeout" in err_str:
                return DNSOutcome(
                    outcome="TIMEOUT",
                    status="ERROR",
                    evidence=f"DNS resolver timeout after {timeout}s: {exc}",
                    details={"timeout": timeout},
                )
            return DNSOutcome(
                outcome="TEMPORARY_FAILURE",
                status="ERROR",
                evidence=f"Temporary DNS server failure: {exc}",
                details={"error": str(exc)},
            )

    # 2. Native OS resolver via socket.getaddrinfo (fast, adheres to system resolver & avoids UDP drops)
    try:
        addr_infos = socket.getaddrinfo(query_host, None, proto=socket.IPPROTO_TCP)
        resolved_ips = []
        for item in addr_infos:
            ip_str = item[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        if resolved_ips:
            return DNSOutcome(
                outcome="RESOLVED",
                status="PASS",
                resolved_ips=resolved_ips,
                evidence=f"DNS resolved successfully: ips={', '.join(resolved_ips[:4])}",
                details={"ip_count": len(resolved_ips)},
            )
        return DNSOutcome(
            outcome="NO_ANSWER",
            status="WARN",
            evidence=f"No IPv4 (A) or IPv6 (AAAA) records found for domain '{clean_host}'",
            details={"no_ip_records": True},
        )

    except socket.gaierror as exc:
        errno = exc.errno
        exc_msg = str(exc).lower()

        # Check for NXDOMAIN / host not found
        is_nxdomain = (
            errno in (11001, getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5))
            or "getaddrinfo failed" in exc_msg
            or "name or service not known" in exc_msg
            or "not known" in exc_msg
        )
        if is_nxdomain:
            return DNSOutcome(
                outcome="NXDOMAIN",
                status="WARN",
                evidence=f"Domain does not exist in authoritative DNS (NXDOMAIN): host={clean_host}",
                details={"nxdomain": True, "errno": errno},
            )

        # Check for temporary server error
        is_temporary = (
            errno in (11002, getattr(socket, "EAI_AGAIN", -3))
            or "temporary failure" in exc_msg
        )
        if is_temporary:
            return DNSOutcome(
                outcome="TEMPORARY_FAILURE",
                status="ERROR",
                evidence=f"Temporary DNS server failure or nameserver error: {exc}",
                details={"temporary_failure": True, "errno": errno},
            )

        # Check for timeout
        is_timeout = (
            errno in (10060, getattr(socket, "ETIMEDOUT", 110))
            or "timeout" in exc_msg
            or "timed out" in exc_msg
        )
        if is_timeout:
            return DNSOutcome(
                outcome="TIMEOUT",
                status="ERROR",
                evidence=f"DNS resolver timeout after {timeout}s: {exc}",
                details={"timeout": timeout, "errno": errno},
            )

        return DNSOutcome(
            outcome="TEMPORARY_FAILURE",
            status="ERROR",
            evidence=f"DNS resolution failure for host '{clean_host}': {exc}",
            details={"error": str(exc), "errno": errno},
        )

    except Exception as exc:
        return DNSOutcome(
            outcome="TEMPORARY_FAILURE",
            status="ERROR",
            evidence=f"DNS operational error: {exc}",
            details={"error": str(exc)},
        )

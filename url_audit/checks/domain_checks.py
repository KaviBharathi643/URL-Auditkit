from typing import List, Optional
from ..utils import CheckResult, domain_parts, whois_lookup
import re, requests
from urllib.parse import urlparse
from datetime import datetime
from functools import lru_cache

RDAP_ENDPOINTS = [
    "https://rdap.educause.edu/domain/{domain}",  # prefer for .edu
    "https://rdap.org/domain/{domain}",
    "https://rdap.verisign.com/com/v1/domain/{domain}",  # works for many .com
]

def _rdap_first_date(obj: dict, keys: list) -> Optional[datetime]:
    """
    Tries common RDAP date locations/keys used by various registries.
    keys: list of candidate top-level keys (e.g., ["created", "registrationDate"])
    Also inspects events[] with known actions.
    """
    # 1) direct keys at top level
    from dateutil import parser as dtp
    if obj:
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str):
                try:
                    return dtp.parse(v)
                except Exception:
                    pass
        # 2) nested events
        for ev in (obj.get("events") or []):
            act = (ev.get("eventAction") or "").lower()
            if any(a in act for a in ["registration", "registered", "domain registration", "create", "created"]) and "created" in keys:
                try:
                    return dtp.parse(ev.get("eventDate"))
                except Exception:
                    pass
            if any(a in act for a in ["expiration", "expiry", "expire", "domain expiration", "auto-renew grace"]) and "expires" in keys:
                try:
                    return dtp.parse(ev.get("eventDate"))
                except Exception:
                    pass
    return None


def _safe_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return str(value)

def _domain_only(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    # fall back to tldextract if needed
    try:
        import tldextract
        ext = tldextract.extract(host)
        return ".".join([ext.domain, ext.suffix]) if ext.suffix else host
    except Exception:
        return host

@lru_cache(maxsize=512)
def _rdap_fetch(domain: str) -> Optional[dict]:
    headers = {
        "Accept": "application/rdap+json, application/json;q=0.9",
        "User-Agent": "url-audit-kit/1.0 (+https://example)"
    }
    for tmpl in RDAP_ENDPOINTS:
        try:
            r = requests.get(
                tmpl.format(domain=domain),
                headers=headers,
                timeout=20,
                allow_redirects=True
            )
            ctype = (r.headers.get("content-type") or "").lower()
            if r.ok and (ctype.startswith("application/rdap+json") or ctype.startswith("application/json")):
                return r.json()
        except Exception:
            continue
    return None


@lru_cache(maxsize=512)
def _whois_fetch(domain: str):
    try:
        return whois_lookup(domain)
    except Exception:
        return None


def _extract_rdap_ownership(rdap: dict) -> dict:
    ownership = {
        "source": "rdap",
        "registrar": "",
        "registrant_name": "",
        "registrant_org": "",
        "registrant_country": "",
        "abuse_contact": "",
        "nameservers": [],
        "statuses": [],
        "created": "",
        "updated": "",
        "expires": "",
        "events": [],
        "redacted": False,
    }
    if not isinstance(rdap, dict):
        return ownership

    ownership["statuses"] = [str(s) for s in (rdap.get("status") or []) if s]
    ownership["nameservers"] = [
        (ns.get("ldhName") or "").lower()
        for ns in (rdap.get("nameservers") or [])
        if isinstance(ns, dict) and ns.get("ldhName")
    ]

    created = _rdap_first_date(rdap, ["created", "creationDate", "registrationDate"])
    updated = _rdap_first_date(rdap, ["updated", "lastChangedDate"])
    expires = _rdap_first_date(rdap, ["expires", "expirationDate"])
    ownership["created"] = created.isoformat() if created else ""
    ownership["updated"] = updated.isoformat() if updated else ""
    ownership["expires"] = expires.isoformat() if expires else ""

    for ev in (rdap.get("events") or []):
        if not isinstance(ev, dict):
            continue
        action = _safe_str(ev.get("eventAction")).lower()
        date = _safe_str(ev.get("eventDate"))
        if action or date:
            ownership["events"].append({"action": action, "date": date})

    entities = rdap.get("entities") or []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in (entity.get("roles") or [])]

        vcard = entity.get("vcardArray")
        entries = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
        fields = {}
        for item in entries:
            if isinstance(item, list) and len(item) >= 4:
                fields[str(item[0]).lower()] = _safe_str(item[3])

        if "registrar" in roles:
            ownership["registrar"] = ownership["registrar"] or fields.get("fn") or fields.get("org") or _safe_str(entity.get("handle"))
        if "registrant" in roles:
            ownership["registrant_name"] = ownership["registrant_name"] or fields.get("fn") or _safe_str(entity.get("handle"))
            ownership["registrant_org"] = ownership["registrant_org"] or fields.get("org")
            if "redacted" in ownership["registrant_name"].lower() or "redacted" in ownership["registrant_org"].lower():
                ownership["redacted"] = True
        if "abuse" in roles:
            abuse = fields.get("email") or fields.get("fn") or _safe_str(entity.get("handle"))
            ownership["abuse_contact"] = ownership["abuse_contact"] or abuse

        if not ownership["registrant_country"]:
            adr = fields.get("adr", "")
            if " " in adr:
                ownership["registrant_country"] = adr.split()[-1]

    if not ownership["registrar"]:
        ownership["registrar"] = _safe_str(rdap.get("registrarName") or rdap.get("port43"))

    return ownership


def _extract_whois_ownership(whois_obj) -> dict:
    ownership = {
        "source": "whois",
        "registrar": "",
        "registrant_name": "",
        "registrant_org": "",
        "registrant_country": "",
        "abuse_contact": "",
        "nameservers": [],
        "statuses": [],
        "created": "",
        "updated": "",
        "expires": "",
        "events": [],
        "redacted": False,
    }
    if not whois_obj:
        return ownership

    ownership["registrar"] = _safe_str(getattr(whois_obj, "registrar", ""))
    ownership["registrant_name"] = _safe_str(getattr(whois_obj, "name", "") or getattr(whois_obj, "registrant_name", ""))
    ownership["registrant_org"] = _safe_str(getattr(whois_obj, "org", "") or getattr(whois_obj, "registrant_organization", ""))
    ownership["registrant_country"] = _safe_str(getattr(whois_obj, "country", ""))
    ownership["abuse_contact"] = _safe_str(getattr(whois_obj, "emails", "") or getattr(whois_obj, "abuse_contact_email", ""))
    ownership["nameservers"] = [str(ns).lower() for ns in (getattr(whois_obj, "name_servers", None) or []) if ns]
    ownership["statuses"] = [str(s).lower() for s in (getattr(whois_obj, "status", None) or []) if s]

    created = getattr(whois_obj, "creation_date", None)
    updated = getattr(whois_obj, "updated_date", None)
    expires = getattr(whois_obj, "expiration_date", None)
    if isinstance(created, list):
        created = created[0] if created else None
    if isinstance(updated, list):
        updated = updated[0] if updated else None
    if isinstance(expires, list):
        expires = expires[0] if expires else None
    ownership["created"] = created.isoformat() if isinstance(created, datetime) else _safe_str(created)
    ownership["updated"] = updated.isoformat() if isinstance(updated, datetime) else _safe_str(updated)
    ownership["expires"] = expires.isoformat() if isinstance(expires, datetime) else _safe_str(expires)

    if "redacted" in ownership["registrant_name"].lower() or "redacted" in ownership["registrant_org"].lower():
        ownership["redacted"] = True
    return ownership

def check_domain_legitimacy(url: str) -> CheckResult:
    # (1) Lookalike heuristic
    try:
        _, host, ext = domain_parts(url)
        if not host:
            return CheckResult(1, "Domain Name Legitimacy", "WARN", evidence="Could not extract hostname")
        suspicious = bool(re.search(r"(paypa1|faceb00k|g00gle|micr0soft|appleid|supp0rt|amaz0n|netfl1x)", host or "", re.I))
        return CheckResult(1, "Domain Name Legitimacy", "WARN" if suspicious else "PASS", evidence=f"host={host}")
    except Exception as e:
        return CheckResult(1, "Domain Name Legitimacy", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_tld(url: str) -> CheckResult:
    # (2) High-risk TLD heuristic
    try:
        _, host, ext = domain_parts(url)
        risky = {"xyz","top","tk","gq","cf","ml","ga","pw","cc"}
        tld = ext.suffix or "unknown"
        status = "WARN" if tld in risky else "PASS"
        return CheckResult(2, "Top-Level Domain (TLD)", status, evidence=f"tld={tld}")
    except Exception as e:
        return CheckResult(2, "Top-Level Domain (TLD)", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_whois_age(url: str) -> CheckResult:
    # (3) WHOIS age with RDAP fallback (handles .edu and others)
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    w = _whois_fetch(domain)
    cd = getattr(w, "creation_date", None)
    if isinstance(cd, list):
        cd = cd[0]

    # RDAP fallback if WHOIS missing/unparseable
    if not cd:
        rdap = _rdap_fetch(domain)
        try:
            from dateutil import parser as dtp
            cd = _rdap_first_date(rdap or {}, ["created", "creationDate", "registrationDate"])
        except Exception:
            cd = None

    if not cd:
        return CheckResult(3, "WHOIS and Domain Age", "WARN", evidence="WHOIS/RDAP creation date unavailable")

    try:
        from datetime import datetime, timezone
        if not isinstance(cd, datetime):
            return CheckResult(3, "WHOIS and Domain Age", "WARN", evidence="Invalid creation_date format")
        if not getattr(cd, "tzinfo", None):
            # assume UTC if naive
            cd = cd.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - cd).days
        status = "PASS" if age_days >= 90 else "WARN"
        return CheckResult(3, "WHOIS and Domain Age", status, evidence=f"age_days={age_days}")
    except Exception as e:
        return CheckResult(3, "WHOIS and Domain Age", "WARN", evidence=f"Parse error: {str(e)[:100]}")

def _has_dmarc(domain: str) -> bool:
    """
    Return True if a valid DMARC TXT record exists at _dmarc.<domain>.
    Handles split TXT strings and ignores non-DMARC TXT.
    """
    import dns.resolver
    try:
        name = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(name, "TXT")
        for rr in answers:
            parts = [s.decode("utf-8") if isinstance(s, bytes) else str(s) for s in getattr(rr, "strings", [])]
            txt = "".join(parts).strip().lower()
            if txt.startswith("v=dmarc1"):
                return True
    except Exception:
        pass
    return False

def check_dns_email_records(url: str) -> List[CheckResult]:
    # (4) SPF, DMARC, MX
    from ..utils import txt_records, mx_records
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])

    # SPF: present on root domain TXT
    txts = txt_records(domain)
    spf = any("v=spf1" in (t or "").lower() for t in txts)

    # DMARC: must exist at _dmarc.<domain> TXT and begin with v=DMARC1
    dmarc_present = _has_dmarc(domain)

    # MX
    mx = mx_records(domain)

    return [
        CheckResult(4, "DNS / Email Records - SPF", "PASS" if spf else "WARN", evidence=f"spf_present={spf}"),
        CheckResult(4, "DNS / Email Records - DMARC", "PASS" if dmarc_present else "WARN", evidence=f"dmarc_present={dmarc_present}"),
        CheckResult(4, "DNS / Email Records - MX", "PASS" if mx else "WARN", evidence=f"mx_hosts={mx}")
    ]

def check_registrar_transparency(url: str) -> CheckResult:
    # (5) Registrar details from WHOIS with RDAP fallback (.edu-friendly)
    try:
        _, host, ext = domain_parts(url)
        domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
        if not domain:
            return CheckResult(5, "Registrar Details Transparency", "WARN", evidence="Could not extract domain")
        w = _whois_fetch(domain)
        registrar = getattr(w, "registrar", None)

        if not registrar:
            rdap = _rdap_fetch(domain) or {}
            try:
                # Prefer entities with role=registrar
                ents = (rdap.get("entities") or [])
                for e in ents:
                    roles = [r.lower() for r in (e.get("roles") or [])]
                    if "registrar" in roles:
                        v = e.get("vcardArray", [])
                        if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], list):
                            for item in v[1]:
                                if item and item[0] in ("fn", "org"):
                                    registrar = item[-1]
                                    if registrar:
                                        break
                    if registrar:
                        break
                # Fallback: some RDAPs include "port43" or custom registrarName fields
                if not registrar:
                    registrar = rdap.get("port43") or rdap.get("registrarName")
            except Exception:
                pass

        status = "PASS" if registrar else "WARN"
        return CheckResult(5, "Registrar Details Transparency", status, evidence=f"registrar={registrar}")
    except Exception as e:
        return CheckResult(5, "Registrar Details Transparency", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_domain_expiry(url: str) -> CheckResult:
    # (6) Expiration via WHOIS with RDAP fallback
    _, host, ext = domain_parts(url)
    domain = ".".join([p for p in [ext.domain, ext.suffix] if p])
    w = _whois_fetch(domain)
    ed = getattr(w, "expiration_date", None)
    if isinstance(ed, list):
        ed = ed[0]

    if not ed:
        rdap = _rdap_fetch(domain) or {}
        try:
            ed = _rdap_first_date(rdap, ["expires", "expirationDate"])
        except Exception:
            ed = None

    if not ed:
        return CheckResult(6, "Domain Expiry and Renewal", "WARN", evidence="expiration_date unavailable")

    try:
        from datetime import datetime, timezone
        if not isinstance(ed, datetime):
            return CheckResult(6, "Domain Expiry and Renewal", "WARN", evidence="Invalid expiration_date format")
        if not getattr(ed, "tzinfo", None):
            ed = ed.replace(tzinfo=timezone.utc)
        days_left = (ed - datetime.now(timezone.utc)).days
        status = "WARN" if days_left < 30 else "PASS"
        return CheckResult(6, "Domain Expiry and Renewal", status, evidence=f"days_left={days_left}")
    except Exception as e:
        return CheckResult(6, "Domain Expiry and Renewal", "WARN", evidence=f"Parse error: {str(e)[:100]}")

def check_previous_ownership(url: str) -> CheckResult:
    # (7) Return ownership details + ownership/transfer history signals
    domain = _domain_only(url)
    rdap = _rdap_fetch(domain)
    whois_obj = _whois_fetch(domain)

    ownership = _extract_rdap_ownership(rdap) if rdap else _extract_whois_ownership(whois_obj)
    if not ownership.get("registrar"):
        # merge WHOIS for missing fields
        fallback = _extract_whois_ownership(whois_obj)
        for key in ("registrar", "registrant_name", "registrant_org", "registrant_country", "abuse_contact"):
            if not ownership.get(key):
                ownership[key] = fallback.get(key, "")
        if not ownership.get("nameservers"):
            ownership["nameservers"] = fallback.get("nameservers", [])
        if not ownership.get("statuses"):
            ownership["statuses"] = fallback.get("statuses", [])
        if not ownership.get("created"):
            ownership["created"] = fallback.get("created", "")
        if not ownership.get("updated"):
            ownership["updated"] = fallback.get("updated", "")
        if not ownership.get("expires"):
            ownership["expires"] = fallback.get("expires", "")
        ownership["redacted"] = bool(ownership.get("redacted") or fallback.get("redacted"))

    change_events = 0
    for ev in (ownership.get("events") or []):
        action = (ev.get("action") or "").lower()
        if any(k in action for k in ["registrant", "registrar", "ownership", "transfer", "update", "changed", "reassigned", "reregistration"]):
            change_events += 1

    has_identity = any(
        ownership.get(k)
        for k in ("registrar", "registrant_name", "registrant_org", "registrant_country")
    )
    status = "INFO" if has_identity else "WARN"
    evidence = (
        f"registrar={ownership.get('registrar') or 'unknown'} "
        f"registrant={ownership.get('registrant_name') or ownership.get('registrant_org') or 'unknown'} "
        f"country={ownership.get('registrant_country') or 'unknown'} "
        f"change_events~={change_events}"
    )
    return CheckResult(7, "Previous Domain Ownership", status, evidence=evidence, data=ownership)

def check_domain_transfers(url: str) -> CheckResult:
    # (8) Transfers via RDAP events
    domain = _domain_only(url)
    rdap = _rdap_fetch(domain)
    transfers = 0
    if rdap:
        for ev in rdap.get("events", []) or []:
            act = (ev.get("eventAction") or "").lower()
            if "transfer" in act or "transferred" in act:
                transfers += 1
    status = "INFO" if transfers > 0 else "PASS"
    return CheckResult(8, "Domain Transfer Records", status, evidence=f"transfer_events={transfers}", data={"rdap_events": rdap.get("events") if rdap else None})

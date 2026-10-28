from ..utils import CheckResult, fetch
import os, re, requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def check_content_quality(url: str):
    # (17)
    try:
        resp, html, soup = fetch(url)
        if not html:
            return CheckResult(17, "Website Content and Design Quality", "WARN", evidence="Could not fetch HTML")
        gib = bool(re.search(r"(lorem ipsum|asdfgh|qwerty|xxxxx|test test test)", html, re.I))
        return CheckResult(17, "Website Content and Design Quality", "WARN" if gib else "PASS", evidence=f"gibberish={gib}")
    except Exception as e:
        return CheckResult(17, "Website Content and Design Quality", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_spelling_errors(url: str):
    # (18)
    return CheckResult(18, "Grammar/Spelling Errors", "INFO", evidence="Analyzed via LLM Content Analysis check")

def check_brand_consistency(url: str):
    # (19)
    return CheckResult(19, "Consistency with Brand Identity", "INFO", evidence="Analyzed via LLM Content Analysis check")

def check_contact_info(url: str):
    # (20)
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(20, "Presence of Contact Information", "WARN", evidence="No HTML")
        text = soup.get_text(" ").lower()
        hit = any(k in text for k in ["contact", "phone", "email", "address", "support"])
        return CheckResult(20, "Presence of Contact Information", "PASS" if hit else "WARN", evidence=f"contact_fields_detected={hit}")
    except Exception as e:
        return CheckResult(20, "Presence of Contact Information", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_about_privacy(url: str):
    # (21) About Us / Privacy Policy Pages
    # Looks for common paths and also scans homepage/footer text for keywords to reduce false negatives.
    try:
        base = url if url.endswith("/") else url + "/"
        candidates = [
            "about", "about-us", "aboutus",
            "privacy", "privacy-policy", "policies", "legal", "terms", "terms-of-service",
        ]
        found_about = False
        found_privacy = False
        evidence_bits = []

        # quick HEAD then GET (some sites block HEAD)
        def _exists(path: str) -> bool:
            full = urljoin(base, path if path.startswith("/") else f"/{path}")
            try:
                r = requests.head(full, timeout=10, allow_redirects=True)
                if r.ok and r.status_code < 400:
                    evidence_bits.append(f"hit:{urlparse(full).path}")
                    return True
            except Exception:
                pass
            try:
                r = requests.get(full, timeout=15, allow_redirects=True)
                if r.ok and r.status_code < 400 and (r.text or "").strip():
                    evidence_bits.append(f"hit:{urlparse(full).path}")
                    return True
            except Exception:
                pass
            return False

        # path probing
        for c in candidates:
            if not found_about and c.startswith("about") and _exists(c):
                found_about = True
            if not found_privacy and any(c.startswith(p) for p in ("privacy", "policies", "legal", "terms")) and _exists(c):
                found_privacy = True
            if found_about and found_privacy:
                break

        # footer scan on homepage as fallback
        try:
            home = requests.get(base, timeout=20, allow_redirects=True)
            if home.ok:
                txt = (home.text or "")
                m = re.search(r"<footer[\s\S]*?</footer>", txt, re.I)
                zone = m.group(0) if m else txt
                if not found_about and re.search(r"\babout(\s+us)?\b", zone, re.I):
                    found_about = True
                    evidence_bits.append("footer:about")
                if not found_privacy and re.search(r"\bprivacy( policy)?\b", zone, re.I):
                    found_privacy = True
                    evidence_bits.append("footer:privacy")
        except Exception:
            pass

        status = "PASS" if (found_about and found_privacy) else "WARN"
        return CheckResult(21, "About Us / Privacy Policy Pages", status,
                           evidence=f"about={found_about} privacy={found_privacy} {' '.join(evidence_bits)}".strip())
    except Exception as e:
        return CheckResult(21, "About Us / Privacy Policy Pages", "WARN", evidence=str(e))

def check_too_good_offers(url: str):
    # (22)
    return CheckResult(22, "Too-Good-To-Be-True Offers", "INFO", evidence="See LLM analysis")

def check_logo_images(url: str):
    # (23)
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(23, "Logo/Images Authenticity", "WARN", evidence="No HTML")
        imgs = soup.find_all("img")
        return CheckResult(23, "Logo/Images Authenticity", "INFO", evidence=f"image_count={len(imgs)}")
    except Exception as e:
        return CheckResult(23, "Logo/Images Authenticity", "WARN", evidence=f"Error: {str(e)[:100]}")

def check_broken_links(url: str):
    # (24) Broken Links or Inactive Pages
    # Crawls the first page, extracts anchors, samples up to N links.
    # Only tests same-origin HTTP/HTTPS links (skip mailto:, tel:, javascript:, and fragments).
    # Uses HEAD with GET fallback. Evidence includes up to 3 example broken URLs.
    try:
        N = int(os.getenv("BROKEN_LINK_SAMPLE", "25") or "25")
        r = requests.get(url, timeout=25, allow_redirects=True)
        if not r.ok:
            return CheckResult(24, "Broken Links or Inactive Pages", "WARN",
                               evidence=f"root fetch {r.status_code}")
        soup = BeautifulSoup(r.text, "html.parser")
        anchors = soup.find_all("a")
        base = r.url  # after redirects
        origin = urlparse(base).netloc.lower()

        def _is_testable(href: str) -> bool:
            if not href:
                return False
            href = href.strip()
            if href.startswith("#"):
                return False
            if href.startswith(("mailto:", "tel:", "javascript:")):
                return False
            u = urlparse(urljoin(base, href))
            if u.scheme not in ("http", "https"):
                return False
            # same-origin only (avoid external throttling)
            return (u.netloc.lower() == origin)

        candidates = [urljoin(base, a.get("href")) for a in anchors if _is_testable(a.get("href"))]
        # de-dupe, keep order
        seen = set()
        links = []
        for c in candidates:
            if c not in seen:
                links.append(c)
                seen.add(c)
            if len(links) >= N:
                break

        broken = []

        def _is_broken(link: str) -> bool:
            # Try HEAD first
            try:
                h = requests.head(link, timeout=12, allow_redirects=True)
                if h.ok and h.status_code < 400:
                    return False
                # Some sites don’t support HEAD properly; fall back to GET
            except Exception:
                pass
            try:
                g = requests.get(link, timeout=15, allow_redirects=True)
                return not (g.ok and g.status_code < 400)
            except Exception:
                return True

        for l in links:
            if _is_broken(l):
                broken.append(l)
            if len(broken) >= 10:  # cap evidence size
                break

        status = "PASS" if len(broken) == 0 else "WARN"
        sample = broken[:3]
        ev = f"checked={len(links)} broken={len(broken)}"
        if sample:
            ev += " examples=" + ", ".join(sample)
        return CheckResult(24, "Broken Links or Inactive Pages", status, evidence=ev)
    except Exception as e:
        return CheckResult(24, "Broken Links or Inactive Pages", "WARN", evidence=str(e))

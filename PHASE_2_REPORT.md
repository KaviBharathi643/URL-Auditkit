# Phase 2 Report: Correct Status Semantics, Risk Scoring, and IOCs

**Project:** URL Audit Kit  
**Repository:** https://github.com/KaviBharathi643/URL-Auditkit  
**Phase Completed:** Phase 2 (Status Semantics, Risk Scoring, and IOC Classification)  
**Date:** October 28, 2026  
**Status:** Complete & Verified  

---

## 1. Executive Summary

In Phase 2, the URL Audit Kit scanning pipeline, risk calculation engine, persistence layer, API contract, and frontend dashboard were refactored to enforce **evidence-based security findings**. 

Prior to this phase:
1. Operational disruptions (network timeouts, DNS lookup failures, 5xx outages, HTTP 429 rate limits, and unconfigured third-party API keys) were conflated with security failures (`FAIL` or `WARN`).
2. An outage or missing API key caused benign domains (such as `https://example.com`) to be penalized with risk points and falsely labeled as malicious.
3. Private RFC 1918 IPs, loopback addresses (`127.0.0.1`), and malformed strings were being extracted as public Indicators of Compromise (IOCs).
4. Unrelated operational errors would either inflate risk scores or suppress confirmed malicious threat signals.

Following Phase 2:
- **5 standardized check statuses** (`PASS`, `WARN`, `FAIL`, `ERROR`, `SKIP`) are strictly enforced across backend checks, the scan runner, database storage, and the UI.
- **Operational errors (`ERROR`) and unexecuted checks (`SKIP`) contribute 0 risk points** and never generate malicious IOCs.
- **Four calibrated verdicts** (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`) replace ad-hoc heuristic thresholds.
- **Inconclusive handling:** Scans lacking sufficient evaluative evidence return `INCONCLUSIVE` rather than defaulting to `BENIGN`.
- **Threat resilience:** Confirmed threat signals (e.g. VirusTotal, Google Safe Browsing, expired certificates, homoglyph attacks) survive unrelated operational check failures without being downgraded.
- **Sanitized IOC pipeline:** Indicators are validated, deduplicated, classified by accurate types (`IP`, `DOMAIN`, `URL`, `ISSUER`), and all non-routable / private / cloud-metadata IPs are blocked from public threat feeds.

---

## 2. Standardized Check Statuses

The scanning engine now enforces distinct semantics for all 15 audit steps:

| Status | Definition | Risk Points Added | Threat IOCs Generated? |
|---|---|---|---|
| **`PASS`** | The check executed to completion and confirmed absence of the risk condition. | `0` | No |
| **`WARN`** | Non-critical security concern, informational warning, or mild heuristic anomaly. | `+4` | Yes (if relevant) |
| **`FAIL`** | A security flaw or threat condition was positively identified under criteria. | `+8` (`+20` if Critical) | Yes |
| **`ERROR`** | Operational failure (timeout, network drop, DNS resolution failure, 5xx server error, rate limit). | `0` | **No** |
| **`SKIP`** | Step intentionally skipped (e.g., plain HTTP skips TLS checks, unconfigured API keys). | `0` | **No** |
| **`INFO`** | Contextual/informational telemetry (e.g. hosting organization name). | `0` | No |

---

## 3. Recalibrated Risk Engine & Verdict Rules (`webapp/risk.py`)

All magic numbers and undocumented multipliers have been eliminated in favor of named, documented constants:

### 3.1 Scoring Formula

$$\text{Risk Score} = \min\left(100, \text{round}\left(\frac{\text{total points}}{\text{max points}} \times 100\right)\right)$$

Where:
- $\text{POINTS\_PASS} = 0$
- $\text{POINTS\_WARN} = 4$
- $\text{POINTS\_FAIL} = 8$
- $\text{CRITICAL\_FAIL\_BONUS} = 12$ (applied on `FAIL` for critical checks)
- $\text{POINTS\_ERROR} = 0$
- $\text{POINTS\_SKIP} = 0$
- Critical check keywords: `ssl`, `https`, `blacklist`, `virustotal`, `safe browsing`, `ip reputation`, `certificate issuer`.

### 3.2 Verdict Resolution Hierarchy

```
[ Scan Complete ]
        │
        ▼
Is there a High-Confidence Threat Match? (VirusTotal, Safe Browsing FAIL)
        │
       ├── YES ──► VERDICT = MALICIOUS
        │
        ▼
Are there 2+ Critical Security Failures? (SSL invalid, bad issuer, etc.)
        │
       ├── YES ──► VERDICT = MALICIOUS
        │
        ▼
Is Evaluative Check Count < 3 AND Failures == 0? (Insufficient Evidence)
        │
       ├── YES ──► VERDICT = INCONCLUSIVE
        │
        ▼
Evaluate Based on Score & Warnings:
        │
       ├── Score >= 75 OR Failures >= 2 ────────► VERDICT = MALICIOUS
       ├── Score >= 25 OR Warnings >= 2 ────────► VERDICT = SUSPICIOUS
       └── Score < 25 AND Errors > Conclusive ──► VERDICT = INCONCLUSIVE
       └── Score < 25 AND Sufficient Evidence ──► VERDICT = BENIGN
```

### 3.3 Key Invariants Enforced
1. **Unrelated Errors Do Not Downgrade Threats:** If VirusTotal or SSL verification confirms a threat, timeouts on WHOIS or AI analysis will never degrade `MALICIOUS` to `INCONCLUSIVE`.
2. **Zero Failures Do Not Guarantee Benign:** If 12 out of 15 checks error out or skip due to network failure, the verdict is `INCONCLUSIVE`, preventing a false sense of security.
3. **Operational Errors Add 0 Risk:** An unreachable RDAP WHOIS server or 429 rate limit adds 0 risk points.

---

## 4. Corrected IOC Classification & Extraction (`webapp/persistence.py`)

`extract_iocs()` was completely overhauled with strict validation and threat isolation:

1. **Strict Exclusion of Non-Threat Statuses:**
   - Checks with `ERROR`, `SKIP`, `PASS`, or `INFO` are explicitly excluded from generating threat IOCs.
2. **IP Sanitization:**
   - Both IPv4 and IPv6 addresses are parsed using Python's `ipaddress` module.
   - Any loopback (`127.0.0.0/8`, `::1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`), or cloud metadata (`169.254.169.254`, `fd00:ec2::254`) address is **blocked from publication**.
3. **Domain & Hostname Sanitization:**
   - Domain indicators must match RFC 1035 hostname syntax. Malformed strings or non-domain labels are rejected.
4. **Deduplication & Conflict Resolution:**
   - Identical indicators appearing across multiple checks are deduplicated.
   - If an indicator is reported by multiple checks at varying severities, the highest severity is preserved.

---

## 5. Backward Compatibility & Database Migration

1. **SQLite Database Schema:**
   - Added `error_count INTEGER NOT NULL DEFAULT 0` column to `scans` table.
   - `init_db()` inspects existing SQLite databases via `PRAGMA table_info(scans)` and applies `ALTER TABLE scans ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0` dynamically without destroying historical scan logs.
2. **API & Frontend Compatibility:**
   - API response schemas support `counts.ERROR` and `verdict: "INCONCLUSIVE"`.
   - Legacy frontend filters and risk badges support `INCONCLUSIVE` (neutral blue badge) and `ERROR` status tags (`status-error`).
   - Legacy scan records without `error_count` default to `0`.

---

## 6. Changed Files Summary

| File | Change Description |
|---|---|
| `url_audit/utils.py` | Added `ERROR` and `SKIP` to `CheckResult` type annotations. Integrated `create_default_ssl_context()` using `certifi` CA store. |
| `url_audit/security.py` | Added `create_default_ssl_context()` for cross-platform TLS certificate validation. |
| `url_audit/runner.py` | Updated `_run_step()` to catch timeouts, SSRF exceptions, and unexpected errors as `ERROR`. Updated `summarize()` to include `ERROR`. |
| `url_audit/checks/domain_checks.py` | Updated `check_whois_age()` and `check_domain_expiry()` to return `ERROR` on connection failures/timeouts and `FAIL` only on expired domains. |
| `url_audit/checks/security_checks.py` | Updated SSL checks to return `SKIP` for HTTP, `ERROR` on network drop, and `FAIL` on untrusted CA. Returns `SKIP` when API keys are unconfigured. |
| `url_audit/checks/reputation_checks.py` | Updated `check_security_blacklists()` and `check_google_safe_browsing()` to return `ERROR` on rate-limits/5xx outages, `SKIP` when keys absent, `FAIL` on detections. |
| `url_audit/checks/behavior_checks.py` | Network/fetch failures mapped to `ERROR` rather than `WARN`. |
| `url_audit/checks/llm_checks.py` | Page fetch errors mapped to `ERROR`, unconfigured NIM key mapped to `SKIP`. |
| `webapp/risk.py` | Complete rewrite using named constants, 4-verdict resolution, inconclusive checks threshold, and 0-weight error semantics. |
| `webapp/persistence.py` | Overhauled `extract_iocs()` with IP/Domain validation, private IP blocking, deduplication, and schema migration for `error_count`. |
| `webapp/main.py` | Updated status styles, summary card serialization, and report rendering to handle `ERROR` and `INCONCLUSIVE`. |
| `frontend/src/types/index.ts` | Added `'ERROR'` to `CheckStatus` and `'INCONCLUSIVE'` to `Verdict`. |
| `frontend/src/lib/risk.ts` | Added `INCONCLUSIVE` styling configuration and badge helpers. |
| `frontend/src/app/globals.css` | Added CSS classes for `.status-error` and `.verdict-inconclusive`. |
| `frontend/src/app/(soc)/history/page.tsx` | Added `INCONCLUSIVE` verdict filter option in scan history UI. |
| `tests/test_phase2_semantics.py` | 24 new unit tests covering statuses, scoring rules, error isolation, IOC extraction, and DB migration. |

---

## 7. Verification & Test Results

### 7.1 Automated Test Execution

All test suites were executed cleanly:

```bash
# 1. Phase 2 Semantics Test Suite
python -m unittest tests/test_phase2_semantics.py
# Ran 24 tests in 1.234s - OK

# 2. Entire Project Test Suite (Phase 1 Security + Phase 2 Semantics + Persistence + Risk)
python -m unittest discover -s tests
# Ran 52 tests in 16.541s - OK

# 3. Next.js Frontend Production Build Check
npm --prefix frontend run build
# Compiled successfully, 10/10 static pages generated, 0 lint/TypeScript errors.
```

### 7.2 Live Scanner Verification

We executed a live audit on `https://example.com` with third-party API keys unconfigured to observe behavior during external feed unavailability:

```json
{
  "summary_counts": {
    "PASS": 10,
    "WARN": 0,
    "FAIL": 0,
    "ERROR": 1,
    "SKIP": 3,
    "INFO": 1
  },
  "risk_score": 0,
  "risk_level": "LOW",
  "verdict": "BENIGN",
  "evaluative_checks_count": 10
}
```
**Observation:**
- Unavailable free threat feeds returned `ERROR: 1` (diagnostic message logged, 0 risk points added).
- Missing API keys (AbuseIPDB, Safe Browsing, Nvidia NIM) returned `SKIP: 3` (0 risk points added).
- Valid TLS cert, valid domain age, active expiry, and HTTPS returned `PASS: 10`.
- The domain correctly resolved to `BENIGN` with `score: 0`.

---

## 8. Unresolved Issues & Phase 3 Roadmap

While Phase 2 successfully corrected status semantics, risk calculation, and IOC isolation, the following items remain for Phase 3 and Phase 4:

1. **Domain Parsing & Phishing Heuristics (Phase 3):**
   - Complex subdomains (e.g. `paypal.com.account-verification.login.attacker.com`) require advanced Shannon entropy and brand keyword scoring.
   - IDN homoglyph punycode decoding needs expanded script-mixing detection (Cyrillic/Latin/Greek confusable sets).
2. **Concurrent Scan Execution (Phase 4):**
   - Audit steps currently run sequentially; independent checks (WHOIS, DNS, TLS, Reputation) should execute concurrently within a bounded worker pool.
3. **Total Scan Deadline Enforcement (Phase 4):**
   - Threadpool tasks must be cooperatively cancelable to respect the 12-second total audit ceiling under network lag.

---

**Phase 2 is now complete and verified.**

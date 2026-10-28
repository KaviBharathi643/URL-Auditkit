# BASELINE_AUDIT.md: URL Audit Kit Baseline System Audit

**Audit Timestamp:** 2026-10-28  
**Repository:** [https://github.com/KaviBharathi643/URL-Auditkit](https://github.com/KaviBharathi643/URL-Auditkit)  
**Baseline Phase:** Phase 0 (Pre-remediation Baseline Establishment)  
**Auditor Role:** Senior Application Security & Quality Assurance Engineer  

---

## 1. Current Architecture & Scan Flow

### 1.1 Architectural Topology
URL Audit Kit operates as a full-stack Security Operations Center (SOC) URL analysis platform composed of three primary tiers:

```
[ Next.js 14 Dashboard ] (Port 3000)
    │
    │  REST: /api/* (Rewritten to Port 8765 via next.config.mjs)
    │  WebSocket: ws://localhost:8765/ws/progress/{job_id}
    ▼
[ FastAPI Backend ] (Port 8765 / webapp)
    ├── Endpoints: POST /api/audit, GET /api/dashboard/overview, GET /api/scans, GET /api/iocs
    ├── Telemetry: _progress_channels (in-memory AsyncIO Queue per job_id)
    ├── Risk Engine: webapp/risk.py (compute_risk, STATUS_POINTS, CRITICAL_FAIL_BONUS)
    └── Persistence: webapp/persistence.py (SQLite: data/url_audit.db)
         │
         ▼ (Invoked via asyncio.to_thread)
[ Audit Engine ] (url_audit)
    ├── Orchestrator: url_audit/runner.py (run_all, CHECK_STEPS: 15 sequential steps)
    ├── Core Utilities: url_audit/utils.py (fetch, head, get_cert_chain, whois_lookup)
    ├── Check Modules:
    │   ├── domain_checks.py (Domain legitimacy, WHOIS age, domain expiry)
    │   ├── security_checks.py (SSL validity, HTTPS presence, certificate issuer, IP reputation, hosting provider)
    │   ├── reputation_checks.py (VirusTotal, Google Safe Browsing, search visibility)
    │   ├── behavior_checks.py (Redirects, suspicious requests, URL length, homoglyph)
    │   └── llm_checks.py / nim_analyzers.py (AI threat summaries via NVIDIA NIM / Ollama)
    └── Database Store: data/url_audit.db (scans, scan_checks, iocs)
```

### 1.2 Scan Flow Execution Lifecycle
1. **Ingestion:** User submits `url`, optional `job_id`, and `scan_mode` to `POST /api/audit`.
2. **Channel Initialization:** If `job_id` is supplied, an `asyncio.Queue` is registered in `_progress_channels` and a start event (`type: start`) is pushed.
3. **Execution Delegate:** FastAPI schedules `run_all(clean_url, progress_callback)` inside `asyncio.to_thread()`.
4. **Step-by-Step Execution:** `runner.py` iterates through 15 tuples in `CHECK_STEPS` sequentially. On each step, `progress_callback` pushes percentage and label through the WebSocket queue to the client.
5. **AI Synthesis:** `_run_ai_analysis()` is dispatched to NVIDIA NIM or Ollama (if configured).
6. **Risk Computation:** `compute_risk()` evaluates all check results and produces `risk_score` (0–100), `risk_level` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), and `verdict` (`BENIGN`/`SUSPICIOUS`/`MALICIOUS`).
7. **Persistence:** `persist_scan()` writes the scan master record, granular check records, and automatically extracted IOCs into SQLite with foreign key cascading.
8. **Completion Event:** A `complete` payload is sent through WebSocket and the channel is scheduled for discard.

---

## 2. Inventory of Outbound Network Requests & Controls

All external requests made by the audit engine were analyzed for destination URL, DNS resolution, redirect behavior, and timeout controls:

| Component / Function | Destination / Protocol | Redirect Policy | Timeout Control | SSRF / Private IP Filter |
|---|---|---|---|---|
| `url_audit/utils.py:fetch()` | Target URL (HTTP/HTTPS GET) | Default `requests` (Follows) | 15 seconds | **None** |
| `url_audit/utils.py:head()` | Target URL (HTTP/HTTPS HEAD) | `allow_redirects=True` | 15 seconds | **None** |
| `url_audit/utils.py:get_cert_chain()` | `socket.create_connection((hostname, 443))` | N/A (TCP socket) | 15 seconds | **None** |
| `url_audit/utils.py:whois_lookup()` | `whois.whois(domain)` (Port 43) | N/A (TCP socket) | Default OS socket timeout | **None** |
| `domain_checks.py:_rdap_fetch()` | RDAP endpoints (`rdap.educause.edu`, `rdap.org`, `rdap.verisign.com`) | `allow_redirects=True` | 20 seconds | N/A (Fixed hosts) |
| `domain_checks.py:check_dns_txt()` | DNS TXT query via `dns.resolver` | N/A (UDP 53) | dnspython default | **None** |
| `security_checks.py:check_ssl_validity()` | `socket.create_connection((host, port))` | N/A (TCP socket) | 10 seconds | **None** |
| `security_checks.py:check_ip_reputation()` | `https://api.abuseipdb.com/api/v2/check` | Default `requests` | 15 seconds | N/A (Fixed API host) |
| `security_checks.py:check_hosting_provider()`| `https://ipinfo.io/{ip}/json` | Default `requests` | 15 seconds | N/A (Fixed API host) |
| `security_checks.py:check_gtmetrix()` | `https://gtmetrix.com/api/2.0/...` | Default `requests` | 15–30 seconds | N/A (Fixed API host) |
| `reputation_checks.py:_lookup_free_blacklists()`| `https://urlhaus-api.abuse.ch/v1/url/`, `https://cleanbrowsing.org` | Default `requests` | 20 seconds | N/A (Fixed API host) |
| `reputation_checks.py:check_security_blacklists()`| `https://www.virustotal.com/api/v3/urls` | Default `requests` | 15–20 seconds | N/A (Fixed API host) |
| `reputation_checks.py:check_google_safe_browsing()`| `https://safebrowsing.googleapis.com/v4/threatMatches:find` | Default `requests` | 15 seconds | N/A (Fixed API host) |
| `behavior_checks.py:check_redirects()` | Target URL via `requests.get()` | Follows redirect chain | 15 seconds | **None (No per-hop validation)** |
| `nim_analyzers.py:_post()` | NVIDIA NIM endpoint | Default `requests` | 90 seconds (env configured) | N/A (Fixed API host) |

### Key Control Gap Findings:
1. **Zero Egress Validation:** No check performs IP address range validation before opening sockets or issuing HTTP requests.
2. **Redirect SSRF Bypass:** `check_redirects()` and `fetch()` allow automated redirects without re-checking the destination IP at intermediate hops.
3. **Cumulative Sequential Blocking:** If 4 checks encounter non-routable IPs with 15s timeouts, the sequential loop blocks for 60 seconds.

---

## 3. Existing Test Suite Execution & Baseline Status

The existing automated test suite in `tests/` was executed using the standard Python test runner:

```bash
python -m unittest discover -s tests
```

### Execution Output:
```text
...
----------------------------------------------------------------------
Ran 3 tests in 0.048s

OK
```

### Existing Test Inventory:
1. `tests/test_persistence.py::PersistenceTests::test_persist_and_fetch_scan` — Validates scan record insertion, foreign-key check associations, and IOC retrieval.
2. `tests/test_risk.py::RiskScoringTests::test_risk_level_thresholds` — Validates categorical mapping for score thresholds (0, 24, 25, 49, 50, 74, 75).
3. `tests/test_risk.py::RiskScoringTests::test_critical_check_failure_adds_bonus` — Validates that a failure in a critical check adds the 12-point bonus.

### Test Coverage Deficits:
- **No Ingress Validation Tests:** Zero tests for malformed schemes (`javascript:`, `file:`, `data:`, empty host).
- **No SSRF / Private IP Tests:** Zero tests asserting that private IPs (`127.0.0.1`, `10.0.0.1`, `169.254.169.254`) are blocked.
- **No Concurrency Tests:** Zero tests assessing thread pool behavior under concurrent requests.
- **No Phishing Subdomain or IDNA Tests:** Zero tests evaluating lookalike domains or punycode decoding.

---

## 4. Confirmed Defects & Empirical Evidence

### Defect 1: Unrestricted Server-Side Request Forgery (SSRF) & Worker DoS
- **Location:** `webapp/main.py:278`, `url_audit/utils.py:24`, `url_audit/checks/security_checks.py:44`
- **Evidence:** Scanning `http://169.254.169.254/latest/meta-data/` or `http://192.168.1.1` forces the backend to issue live socket and HTTP requests to private infrastructure. Because the addresses are non-routable in test environments, requests hung for 60,000+ ms and caused read timeouts.
- **Severity:** **CRITICAL**

### Defect 2: Crashed Checks Inverted into Security "FAIL" (False Positive Flaw)
- **Location:** `url_audit/runner.py:55-64`, `webapp/persistence.py:125-136`
- **Evidence:** When `reputation_checks.py::check_google_safe_browsing()` encountered an unhandled `requests.exceptions.ConnectionError` (due to DNS glitch), `runner.py` wrapped the exception as:
  ```python
  CheckResult(1010, "Google Safe Browsing", "FAIL", evidence="check crashed: NameResolutionError...")
  ```
  `persistence.py` mapped this `"FAIL"` on a critical check into a **`CRITICAL` Indicator of Compromise**, spuriously scoring `https://wikipedia.org` as **MEDIUM / SUSPICIOUS** with a Critical IOC.
- **Severity:** **HIGH**

### Defect 3: Leetspeak-Only Phishing Detection Blind Spot (False Negative Flaw)
- **Location:** `url_audit/checks/domain_checks.py:220`
- **Evidence:** The heuristic regex only tests 8 specific leetspeak strings:
  ```python
  r"(paypa1|faceb00k|g00gle|micr0soft|appleid|supp0rt|amaz0n|netfl1x)"
  ```
  Testing `https://login.paypal.com.account-verification-security.com` yielded **Score 17 (LOW / BENIGN)** because `paypal` was spelled correctly as a subdomain on an attacker domain.
- **Severity:** **HIGH**

### Defect 4: Punycode / Homoglyph ASCII Bypass (False Negative Flaw)
- **Location:** `url_audit/checks/behavior_checks.py:50-57`
- **Evidence:** `check_homoglyph()` executes:
  ```python
  url.encode("ascii")
  non_ascii = False
  ```
  Punycode-encoded international domains (`https://xn--pple-43d.com`, spoofing `аpple.com`) are valid ASCII. The check returned `PASS` with `non_ascii=False`, classifying the spoof as **BENIGN**.
- **Severity:** **HIGH**

### Defect 5: Raw IP Addresses Misclassified as "DOMAIN" IOCs
- **Location:** `webapp/persistence.py:183-199`
- **Evidence:** `extract_iocs()` calls `_domain_from_url(target_url)` which returns `urlparse(url).hostname`. When scanning `http://8.8.8.8` or `http://1.1.1.1`, the raw IP was inserted into the `iocs` table with `indicator_type="DOMAIN"`.
- **Severity:** **MEDIUM**

### Defect 6: Malformed URLs Scored as BENIGN
- **Location:** `webapp/main.py:278-326`, `webapp/risk.py:51-82`
- **Evidence:** Submitting `https://`, `javascript:alert(1)`, or `file:///etc/passwd` resulted in `HTTP 200 OK` with risk scores between 21 and 23, returning an official verdict of **BENIGN** instead of `HTTP 400 Bad Request`.
- **Severity:** **MEDIUM**

---

## 5. Potential Risks Requiring Verification During Remediation

1. **DNS Rebinding Attacks:** Validating IP at request creation time could be bypassed by DNS rebinding (TTL=0) if the client resolves DNS again during fetch.
2. **RDAP Endpoint Rate Limiting:** Fallback RDAP requests (`rdap.verisign.com`, `rdap.org`) can become throttled during high-frequency scanning.
3. **Frontend Compatibility with New Statuses:** If an `"ERROR"` status or `"INCONCLUSIVE"` verdict is added, ensure `frontend/src/types/index.ts`, `risk.ts`, and badge renderers in `ScannerPage` and `ReportsPage` handle them gracefully without UI breaks.

---

## 6. Files Likely to Require Modification

| Component | File Path | Scope of Remediation |
|---|---|---|
| Ingress / API | `webapp/main.py` | Add URL syntax validation, early scheme rejection, SSRF IP gate, and timeout protection. |
| Risk Scoring | `webapp/risk.py` | Distinguish operational `ERROR` from security `FAIL`; calibrate scoring weights; support `INCONCLUSIVE` verdict. |
| Persistence & IOCs | `webapp/persistence.py` | Fix IP vs DOMAIN categorization using `ipaddress`; ignore `ERROR` status for IOC generation; filter loopback indicators. |
| Runner | `url_audit/runner.py` | Catch check exceptions as `ERROR` instead of `FAIL`; prepare for bounded async concurrency. |
| Network Utils | `url_audit/utils.py` | Add IP validation helpers; clamp connection timeouts; implement SSRF-safe request wrapper. |
| Domain Checks | `url_audit/checks/domain_checks.py` | Add subdomain brand impersonation heuristics; parse registrable domains correctly via `tldextract`. |
| Behavior Checks | `url_audit/checks/behavior_checks.py` | Implement true IDNA decoding (`decode('idna')`) and homoglyph detection for punycode domains. |
| Reputation Checks | `url_audit/checks/reputation_checks.py` | Wrap external API calls in safe try/except blocks to prevent unhandled socket/network crashes. |
| Frontend Types / Display | `frontend/src/types/index.ts`, `frontend/src/lib/risk.ts` | Support `ERROR` check status and `INCONCLUSIVE` verdict styling without breaking existing schemas. |

---

## 7. Existing API Contracts & Database Compatibility Constraints

### 7.1 Database Compatibility Constraints
- The SQLite database schema (`scans`, `scan_checks`, `iocs`) in `data/url_audit.db` must **not** be deleted or dropped.
- Table structures:
  - `scans` table: Columns `risk_score` (INTEGER), `risk_level` (TEXT), `verdict` (TEXT), `pass_count`, `warn_count`, `fail_count`, `info_count`, `skip_count`.
  - `scan_checks` table: `status` (TEXT), `risk_level` (TEXT), `name` (TEXT), `evidence` (TEXT).
  - `iocs` table: `indicator` (TEXT), `indicator_type` (TEXT), `severity` (TEXT).
- Compatibility rule: Adding a new status code (e.g., `ERROR`) to `scan_checks.status` or a new verdict (e.g., `INCONCLUSIVE`) to `scans.verdict` is backwards-compatible at the SQLite column level, but must be accompanied by non-breaking frontend mapping.

### 7.2 API Contracts (Must Be Preserved)
1. `POST /api/audit`:
   - Inputs: Form data `url` (str), optional `job_id` (str), optional `scan_mode` (`scan` | `deep` | `sandbox`).
   - Expected Output (HTTP 200): JSON containing `results`, `grouped_results`, `summary_cards`, `target_url`, `total_checks`, `scan_id`, `risk_score`, `risk_level`, `verdict`, `duration_ms`, `created_at`, `ioc_count`.
   - Expected Output on Invalid Ingress (HTTP 400): `{"error": "<descriptive message>"}`.
2. `WS /ws/progress/{job_id}`:
   - Message schema: `{"type": "start"|"progress"|"complete"|"error", "step": int, "total": int, "percent": int, "label": str, "message"?: str}`.
3. `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/iocs`, `GET /api/dashboard/overview`, `GET /api/threat-intelligence/map`:
   - All response schemas, query parameters (`page`, `page_size`, `q`, `range`), and filter contracts must remain fully intact.

---

## 8. Prioritized Implementation Plan (Phases 1–5)

```
Phase 1: Contain Security Risks
  ├── 1.1 Strict URL Gateway Validation (Reject non-http/https, malformed, empty schemes with 400)
  ├── 1.2 SSRF Protection Layer (DNS pre-resolution, RFC 1918 / Link-Local / Loopback filtering)
  ├── 1.3 Safe Egress Transport Wrapper (Redirect hop validation, 4s socket timeout clamping)
  └── 1.4 Global Scan Deadline Guard (12s total timeout)

Phase 2: Fix Verdict Correctness
  ├── 2.1 Introduce Tri-State 'ERROR' Status (Operational failures isolated from malicious findings)
  ├── 2.2 Fix IOC Classification (Distinguish IP addresses from DOMAIN indicators)
  ├── 2.3 Exclude Operational Errors from Critical IOC Generation
  └── 2.4 Calibrate Risk Scoring Engine (Support INCONCLUSIVE verdict for unresolvable targets)

Phase 3: Improve Detection Capabilities
  ├── 3.1 IDNA Punycode Decoding & Homoglyph Heuristic (Catch Unicode script spoofs)
  ├── 3.2 Subdomain Brand Impersonation Heuristic (Catch deceptive brand subdomains)
  └── 3.3 Enhanced Threat Reputation Error Handling (Protect Safe Browsing & VirusTotal calls)

Phase 4: Improve Performance & Concurrency
  ├── 4.1 Bounded Asynchronous Task Pool (asyncio.gather with semaphore for 15 checks)
  ├── 4.2 Resource Cleanup on WebSocket Disconnect
  └── 4.3 Optimize Latency from ~35s down to <3.5s per scan

Phase 5: Validate the Fixes
  ├── 5.1 Unit Tests for SSRF, URL Validation, IDNA, and IOC Classification
  ├── 5.2 API Integration & WebSocket Telemetry Tests
  └── 5.3 Re-execution of the 59-Case Test Matrix (Zero DoS, Zero False Positives, Verified True Positives)
```

---
*End of Baseline Audit Report. Ready to proceed to Phase 1 upon user authorization.*

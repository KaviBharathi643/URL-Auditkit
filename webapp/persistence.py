from __future__ import annotations

import contextlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "url_audit.db"

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "US": (37.0902, -95.7129),
    "CA": (56.1304, -106.3468),
    "MX": (23.6345, -102.5528),
    "BR": (-14.2350, -51.9253),
    "AR": (-38.4161, -63.6167),
    "GB": (55.3781, -3.4360),
    "FR": (46.2276, 2.2137),
    "DE": (51.1657, 10.4515),
    "NL": (52.1326, 5.2913),
    "ES": (40.4637, -3.7492),
    "IT": (41.8719, 12.5674),
    "SE": (60.1282, 18.6435),
    "NO": (60.4720, 8.4689),
    "PL": (51.9194, 19.1451),
    "RU": (61.5240, 105.3188),
    "TR": (38.9637, 35.2433),
    "IN": (20.5937, 78.9629),
    "CN": (35.8617, 104.1954),
    "JP": (36.2048, 138.2529),
    "KR": (35.9078, 127.7669),
    "SG": (1.3521, 103.8198),
    "AU": (-25.2744, 133.7751),
    "NZ": (-40.9006, 174.8860),
    "ZA": (-30.5595, 22.9375),
    "EG": (26.8206, 30.8025),
    "NG": (9.0820, 8.6753),
    "AE": (23.4241, 53.8478),
    "SA": (23.8859, 45.0792),
}

COUNTRY_ALIASES: Dict[str, str] = {
    "UNITED STATES": "US",
    "UNITED KINGDOM": "GB",
    "SOUTH KOREA": "KR",
    "RUSSIA": "RU",
}

CRITICAL_IOC_CHECK_KEYWORDS = (
    "blacklist",
    "safe browsing",
    "ssl",
    "https",
    "ip reputation",
)

VALID_SCAN_SORT_FIELDS = {
    "created_at": "created_at",
    "risk_score": "risk_score",
    "target_url": "target_url",
    "verdict": "verdict",
}

VALID_IOC_SORT_FIELDS = {
    "created_at": "i.created_at",
    "severity": "i.severity",
    "indicator": "i.indicator",
    "indicator_type": "i.indicator_type",
}


def _db_path() -> Path:
    raw = os.getenv("URL_AUDIT_DB_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    return DEFAULT_DB_PATH


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        # SQLite generated fallback format.
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def _normalize_country(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    upper = text.upper()
    if len(upper) == 2 and upper.isalpha():
        return upper
    return COUNTRY_ALIASES.get(upper, "")


def _country_from_check(check: Dict[str, Any]) -> str:
    data = check.get("data") if isinstance(check.get("data"), dict) else {}
    from_data = str(data.get("country") or "").strip()
    if from_data:
        return _normalize_country(from_data)

    evidence = str(check.get("evidence") or "")
    marker = "country="
    if marker in evidence.lower():
        parts = evidence.split()
        for part in parts:
            if part.lower().startswith(marker):
                value = part.split("=", 1)[1].strip(",")
                return _normalize_country(value)
    return ""


def _severity_from_check(name: str, status: str) -> str:
    normalized_status = (status or "").upper()
    check_name = (name or "").lower()
    is_critical = any(keyword in check_name for keyword in CRITICAL_IOC_CHECK_KEYWORDS)

    if normalized_status == "FAIL":
        return "CRITICAL" if is_critical else "HIGH"
    if normalized_status == "WARN":
        return "HIGH" if is_critical else "MEDIUM"
    if normalized_status == "INFO":
        return "LOW"
    return "LOW"


def _domain_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _add_ioc(
    results: List[Dict[str, Any]],
    seen: set,
    *,
    indicator: str,
    indicator_type: str,
    severity: str,
    source_check: str,
    country: str,
    created_at: str,
) -> None:
    text = (indicator or "").strip()
    if not text:
        return

    key = (
        text.lower(),
        indicator_type.upper(),
        severity.upper(),
        source_check.lower(),
        country.upper(),
    )
    if key in seen:
        return
    seen.add(key)
    results.append(
        {
            "indicator": text,
            "indicator_type": indicator_type.upper(),
            "severity": severity.upper(),
            "source_check": source_check,
            "country": country.upper(),
            "created_at": created_at,
        }
    )


def extract_iocs(target_url: str, checks: Sequence[Dict[str, Any]], created_at: str) -> List[Dict[str, Any]]:
    iocs: List[Dict[str, Any]] = []
    seen = set()
    domain = _domain_from_url(target_url)

    if domain:
        _add_ioc(
            iocs,
            seen,
            indicator=domain,
            indicator_type="DOMAIN",
            severity="LOW",
            source_check="Target URL",
            country="",
            created_at=created_at,
        )

    for check in checks:
        name = str(check.get("name") or "Unknown Check")
        status = str(check.get("status") or "WARN").upper()
        evidence = str(check.get("evidence") or "")
        lower_name = name.lower()
        country = _country_from_check(check)
        severity = _severity_from_check(name, status)

        if status in {"FAIL", "WARN"} and ("blacklist" in lower_name or "safe browsing" in lower_name):
            _add_ioc(
                iocs,
                seen,
                indicator=target_url,
                indicator_type="URL",
                severity="CRITICAL" if status == "FAIL" else "HIGH",
                source_check=name,
                country=country,
                created_at=created_at,
            )

        payload_blob = f"{evidence} {json.dumps(check.get('data', {}), default=str)}"
        for ip in IP_PATTERN.findall(payload_blob):
            _add_ioc(
                iocs,
                seen,
                indicator=ip,
                indicator_type="IP",
                severity=severity,
                source_check=name,
                country=country,
                created_at=created_at,
            )

        if status in {"FAIL", "WARN"} and "homoglyph" in lower_name and domain:
            _add_ioc(
                iocs,
                seen,
                indicator=domain,
                indicator_type="DOMAIN",
                severity="HIGH",
                source_check=name,
                country=country,
                created_at=created_at,
            )

        if status in {"FAIL", "WARN"} and "certificate issuer" in lower_name:
            issuer_match = re.search(r"issuer=([^,]+)", evidence, flags=re.IGNORECASE)
            if issuer_match:
                _add_ioc(
                    iocs,
                    seen,
                    indicator=issuer_match.group(1).strip(),
                    indicator_type="ISSUER",
                    severity=severity,
                    source_check=name,
                    country=country,
                    created_at=created_at,
                )

    return iocs


@contextlib.contextmanager
def _connect() -> Any:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_mode TEXT NOT NULL DEFAULT 'scan',
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                total_checks INTEGER NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                warn_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0,
                skip_count INTEGER NOT NULL DEFAULT 0,
                ai_verdict TEXT,
                ai_summary TEXT,
                threat_report_json TEXT,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                check_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT,
                section TEXT,
                evidence TEXT,
                details TEXT,
                data_json TEXT,
                summary TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_check TEXT NOT NULL,
                country TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
            CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
            CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
            CREATE INDEX IF NOT EXISTS idx_scan_checks_scan_id ON scan_checks(scan_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_scan_id ON iocs(scan_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
            CREATE INDEX IF NOT EXISTS idx_iocs_country ON iocs(country);
            """
        )


def persist_scan(
    *,
    target_url: str,
    scan_mode: str,
    prepared_results: Sequence[Dict[str, Any]],
    counts: Dict[str, int],
    risk_score: int,
    risk_level: str,
    verdict: str,
    threat_report: Optional[Dict[str, Any]],
    duration_ms: int,
    created_at: Optional[str] = None,
) -> Tuple[int, int]:
    ts = created_at or _utc_now_iso()
    ai_verdict = str((threat_report or {}).get("verdict") or "").upper() or None
    ai_summary = (threat_report or {}).get("executive_summary")
    threat_report_json = json.dumps(threat_report, default=str) if threat_report else None

    iocs = extract_iocs(target_url, prepared_results, ts)

    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                target_url, scan_mode, risk_score, risk_level, verdict, total_checks,
                pass_count, warn_count, fail_count, info_count, skip_count,
                ai_verdict, ai_summary, threat_report_json, duration_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_url,
                scan_mode,
                int(risk_score),
                risk_level,
                verdict,
                int(sum(counts.values())),
                int(counts.get("PASS", 0)),
                int(counts.get("WARN", 0)),
                int(counts.get("FAIL", 0)),
                int(counts.get("INFO", 0)),
                int(counts.get("SKIP", 0)),
                ai_verdict,
                ai_summary,
                threat_report_json,
                int(duration_ms),
                ts,
            ),
        )
        scan_id = int(cursor.lastrowid)

        conn.executemany(
            """
            INSERT INTO scan_checks (
                scan_id, check_id, name, status, risk_level, section,
                evidence, details, data_json, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    int(check.get("id", 0)),
                    str(check.get("name", "")),
                    str(check.get("status", "WARN")),
                    str(check.get("risk_level", "")),
                    str(check.get("section", "")),
                    str(check.get("evidence", "")),
                    str(check.get("details", "")),
                    json.dumps(check.get("data", {}), default=str),
                    str(check.get("summary", "")),
                )
                for check in prepared_results
            ],
        )

        conn.executemany(
            """
            INSERT INTO iocs (
                scan_id, indicator, indicator_type, severity, source_check, country, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    ioc["indicator"],
                    ioc["indicator_type"],
                    ioc["severity"],
                    ioc["source_check"],
                    ioc["country"],
                    ioc["created_at"],
                )
                for ioc in iocs
            ],
        )

    return scan_id, len(iocs)


def _range_since(range_value: str) -> str:
    now = datetime.now(timezone.utc)
    window = (range_value or "24h").strip().lower()
    if window == "7d":
        since = now - timedelta(days=7)
    elif window == "30d":
        since = now - timedelta(days=30)
    else:
        since = now - timedelta(hours=24)
    return since.isoformat()


def _scan_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "target_url": row["target_url"],
        "scan_mode": row["scan_mode"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "verdict": row["verdict"],
        "total_checks": row["total_checks"],
        "pass_count": row["pass_count"],
        "warn_count": row["warn_count"],
        "fail_count": row["fail_count"],
        "info_count": row["info_count"],
        "skip_count": row["skip_count"],
        "ai_verdict": row["ai_verdict"],
        "ai_summary": row["ai_summary"],
        "duration_ms": row["duration_ms"],
        "created_at": row["created_at"],
    }


def _build_page(total: int, page: int, page_size: int) -> Dict[str, int]:
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_dashboard_overview(range_value: str = "24h") -> Dict[str, Any]:
    since = _range_since(range_value)
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, target_url, risk_score, risk_level, verdict, created_at
            FROM scans
            WHERE created_at >= ?
            ORDER BY created_at DESC
            """,
            (since,),
        ).fetchall()

    total_scans = len(rows)
    malicious = 0
    suspicious = 0
    safe = 0
    distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    activity: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "malicious": 0, "safe": 0})

    bucket_by_hour = (range_value or "24h").lower() == "24h"
    for row in rows:
        risk_level = str(row["risk_level"]).upper()
        distribution[risk_level] = distribution.get(risk_level, 0) + 1

        if risk_level in {"HIGH", "CRITICAL"}:
            malicious += 1
        elif risk_level == "MEDIUM":
            suspicious += 1
        else:
            safe += 1

        dt = _parse_iso(row["created_at"])
        bucket = dt.strftime("%Y-%m-%d %H:00") if bucket_by_hour else dt.strftime("%Y-%m-%d")
        activity[bucket]["total"] += 1
        if risk_level in {"HIGH", "CRITICAL"}:
            activity[bucket]["malicious"] += 1
        if risk_level == "LOW":
            activity[bucket]["safe"] += 1

    return {
        "range": range_value,
        "totals": {
            "total_scans": total_scans,
            "malicious_urls": malicious,
            "suspicious_domains": suspicious,
            "safe_urls": safe,
        },
        "threat_distribution": [
            {"label": label, "value": value}
            for label, value in distribution.items()
        ],
        "scan_activity": [
            {"bucket": bucket, **counts}
            for bucket, counts in sorted(activity.items())
        ],
        "recent_scans": [
            {
                "id": row["id"],
                "target_url": row["target_url"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "verdict": row["verdict"],
                "created_at": row["created_at"],
            }
            for row in rows[:10]
        ],
    }


def list_scans(
    *,
    page: int = 1,
    page_size: int = 20,
    q: str = "",
    risk: str = "",
    status: str = "",
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> Dict[str, Any]:
    page = max(page, 1)
    page_size = max(1, min(page_size, 200))
    offset = (page - 1) * page_size

    where = ["1=1"]
    params: List[Any] = []

    if q.strip():
        where.append("target_url LIKE ?")
        params.append(f"%{q.strip()}%")

    if risk.strip():
        values = [v.strip().upper() for v in risk.split(",") if v.strip()]
        if values:
            where.append(f"risk_level IN ({','.join(['?'] * len(values))})")
            params.extend(values)

    if status.strip():
        values = [v.strip().upper() for v in status.split(",") if v.strip()]
        if values:
            where.append(f"verdict IN ({','.join(['?'] * len(values))})")
            params.extend(values)

    order_field = VALID_SCAN_SORT_FIELDS.get(sort_by, "created_at")
    direction = "ASC" if sort_order.lower() == "asc" else "DESC"
    where_sql = " AND ".join(where)

    with _connect() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM scans WHERE {where_sql}",
                params,
            ).fetchone()[0]
        )

        rows = conn.execute(
            f"""
            SELECT *
            FROM scans
            WHERE {where_sql}
            ORDER BY {order_field} {direction}
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()

    return {
        "items": [_scan_row_to_dict(row) for row in rows],
        **_build_page(total, page, page_size),
    }


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None

        checks = conn.execute(
            """
            SELECT check_id, name, status, risk_level, section, evidence, details, data_json, summary
            FROM scan_checks
            WHERE scan_id = ?
            ORDER BY check_id ASC, id ASC
            """,
            (scan_id,),
        ).fetchall()

        iocs = conn.execute(
            """
            SELECT id, indicator, indicator_type, severity, source_check, country, created_at
            FROM iocs
            WHERE scan_id = ?
            ORDER BY id DESC
            """,
            (scan_id,),
        ).fetchall()

    scan = _scan_row_to_dict(row)
    scan["summary_cards"] = [
        {"status": "PASS", "count": scan["pass_count"]},
        {"status": "WARN", "count": scan["warn_count"]},
        {"status": "FAIL", "count": scan["fail_count"]},
        {"status": "INFO", "count": scan["info_count"]},
        {"status": "SKIP", "count": scan["skip_count"]},
    ]
    scan["checks"] = [
        {
            "id": r["check_id"],
            "name": r["name"],
            "status": r["status"],
            "risk_level": r["risk_level"],
            "section": r["section"],
            "evidence": r["evidence"],
            "details": r["details"],
            "data": json.loads(r["data_json"] or "{}"),
            "summary": r["summary"],
        }
        for r in checks
    ]
    scan["iocs"] = [dict(item) for item in iocs]
    return scan


def get_scan_report(scan_id: int) -> Optional[Dict[str, Any]]:
    scan = get_scan(scan_id)
    if not scan:
        return None

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for check in scan["checks"]:
        grouped[check.get("section") or "Additional Checks"].append(check)

    threat_report = None
    with _connect() as conn:
        row = conn.execute("SELECT threat_report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row and row["threat_report_json"]:
        try:
            threat_report = json.loads(row["threat_report_json"])
        except json.JSONDecodeError:
            threat_report = None

    recommendations: List[str] = []
    if isinstance(threat_report, dict):
        raw_recommendations = threat_report.get("recommendations")
        if isinstance(raw_recommendations, list):
            recommendations = [str(item) for item in raw_recommendations if item]

    if not recommendations:
        if scan["risk_level"] in {"HIGH", "CRITICAL"}:
            recommendations.extend(
                [
                    "Block or sandbox this URL before end-user access.",
                    "Add related indicators to watchlists and alerting rules.",
                    "Escalate to incident response for containment validation.",
                ]
            )
        elif scan["risk_level"] == "MEDIUM":
            recommendations.extend(
                [
                    "Review suspicious findings before allowing unrestricted access.",
                    "Monitor this domain and related infrastructure for behavior changes.",
                ]
            )
        else:
            recommendations.append("No high-risk indicators detected. Continue routine monitoring.")

    return {
        "scan": scan,
        "scan_summary": {
            "target_url": scan["target_url"],
            "scan_mode": scan["scan_mode"],
            "risk_score": scan["risk_score"],
            "risk_level": scan["risk_level"],
            "verdict": scan["verdict"],
            "created_at": scan["created_at"],
            "duration_ms": scan["duration_ms"],
            "total_checks": scan["total_checks"],
        },
        "indicators_of_compromise": scan["iocs"],
        "domain_intelligence": grouped.get("Domain Intelligence", []),
        "risk_assessment": {
            "pass_count": scan["pass_count"],
            "warn_count": scan["warn_count"],
            "fail_count": scan["fail_count"],
            "info_count": scan["info_count"],
            "skip_count": scan["skip_count"],
            "risk_score": scan["risk_score"],
            "risk_level": scan["risk_level"],
        },
        "recommendations": recommendations,
        "grouped_checks": [{"name": name, "checks": checks} for name, checks in grouped.items()],
        "threat_report": threat_report,
    }


def list_iocs(
    *,
    page: int = 1,
    page_size: int = 20,
    q: str = "",
    indicator_type: str = "",
    severity: str = "",
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> Dict[str, Any]:
    page = max(page, 1)
    page_size = max(1, min(page_size, 200))
    offset = (page - 1) * page_size

    where = ["1=1"]
    params: List[Any] = []

    if q.strip():
        where.append("i.indicator LIKE ?")
        params.append(f"%{q.strip()}%")
    if indicator_type.strip():
        values = [v.strip().upper() for v in indicator_type.split(",") if v.strip()]
        if values:
            where.append(f"i.indicator_type IN ({','.join(['?'] * len(values))})")
            params.extend(values)
    if severity.strip():
        values = [v.strip().upper() for v in severity.split(",") if v.strip()]
        if values:
            where.append(f"i.severity IN ({','.join(['?'] * len(values))})")
            params.extend(values)

    order_field = VALID_IOC_SORT_FIELDS.get(sort_by, "i.created_at")
    direction = "ASC" if sort_order.lower() == "asc" else "DESC"
    where_sql = " AND ".join(where)

    with _connect() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM iocs i WHERE {where_sql}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT i.*, s.target_url, s.risk_level, s.risk_score
            FROM iocs i
            JOIN scans s ON s.id = i.scan_id
            WHERE {where_sql}
            ORDER BY {order_field} {direction}
            LIMIT ? OFFSET ?
            """,
            [*params, page_size, offset],
        ).fetchall()

    return {
        "items": [dict(row) for row in rows],
        **_build_page(total, page, page_size),
    }


def get_threat_map(range_value: str = "24h") -> Dict[str, Any]:
    since = _range_since(range_value)
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT country, severity, COUNT(*) AS count
            FROM iocs
            WHERE created_at >= ? AND country IS NOT NULL AND country != ''
            GROUP BY country, severity
            """,
            (since,),
        ).fetchall()

    agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
    for row in rows:
        country_code = _normalize_country(str(row["country"]))
        if not country_code:
            continue
        sev = str(row["severity"]).lower()
        agg[country_code]["count"] += int(row["count"])
        if sev in agg[country_code]:
            agg[country_code][sev] += int(row["count"])

    points = []
    for country, counts in agg.items():
        coords = COUNTRY_COORDS.get(country)
        if not coords:
            continue
        points.append(
            {
                "country": country,
                "lat": coords[0],
                "lng": coords[1],
                **counts,
            }
        )

    return {
        "range": range_value,
        "points": sorted(points, key=lambda item: item["count"], reverse=True),
    }


def get_top_malicious_domains(limit: int = 20) -> Dict[str, Any]:
    limit = max(1, min(limit, 200))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT indicator AS domain, COUNT(*) AS hits, MAX(created_at) AS last_seen
            FROM iocs
            WHERE indicator_type = 'DOMAIN'
              AND severity IN ('HIGH', 'CRITICAL')
            GROUP BY indicator
            ORDER BY hits DESC, last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


def get_ip_reputation(limit: int = 20) -> Dict[str, Any]:
    limit = max(1, min(limit, 200))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                indicator AS ip,
                COUNT(*) AS sightings,
                MAX(created_at) AS last_seen,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_hits,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_hits,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_hits
            FROM iocs
            WHERE indicator_type = 'IP'
            GROUP BY indicator
            ORDER BY critical_hits DESC, high_hits DESC, sightings DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}

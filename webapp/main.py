import asyncio
import os
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.websockets import WebSocketDisconnect

from url_audit.runner import run_all, summarize, total_steps
from webapp.persistence import (
    get_dashboard_overview,
    get_ip_reputation,
    get_scan,
    get_scan_report,
    get_threat_map,
    get_top_malicious_domains,
    init_db,
    list_iocs,
    list_scans,
    persist_scan,
)
from webapp.risk import compute_risk

SECTION_RULES: List[Dict[str, object]] = [
    {
        "section": "Domain Intelligence",
        "patterns": [
            "domain name legitimacy",
            "whois",
            "domain expiry",
            "domain transfer",
            "domain ownership",
            "domain",
        ],
    },
    {
        "section": "Security Posture",
        "patterns": [
            "ssl",
            "https",
            "certificate",
            "ip reputation",
            "hosting provider",
            "security",
        ],
    },
    {
        "section": "Reputation & Trust",
        "patterns": [
            "blacklist",
            "safe browsing",
            "reputation",
        ],
    },
    {
        "section": "Behavioural Signals",
        "patterns": [
            "redirect",
            "suspicious requests",
            "url length",
            "homoglyph",
        ],
    },
    {
        "section": "AI Observations",
        "patterns": ["ai content analysis", "ai"],
    },
]

load_dotenv(override=True)

app = FastAPI(
    title="URL Audit Kit API",
    description="SOC-grade URL security audit APIs with persistence and telemetry",
)

_default_frontend = os.getenv("FRONTEND_APP_URL", "http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8765",
        "http://127.0.0.1:8765",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

STATUS_STYLES: Dict[str, Dict[str, str]] = {
    "PASS": {"badge": "success", "icon": "verified"},
    "WARN": {"badge": "warning", "icon": "report"},
    "FAIL": {"badge": "danger", "icon": "dangerous"},
    "INFO": {"badge": "info", "icon": "info"},
    "SKIP": {"badge": "secondary", "icon": "upcoming"},
}

_progress_lock = asyncio.Lock()
_progress_channels: Dict[str, asyncio.Queue] = {}


@app.on_event("startup")
async def _startup() -> None:
    init_db()


def _frontend_url() -> str:
    return os.getenv("FRONTEND_APP_URL", _default_frontend).rstrip("/")


async def _get_progress_queue(job_id: str) -> asyncio.Queue:
    async with _progress_lock:
        queue = _progress_channels.get(job_id)
        if queue is None:
            queue = asyncio.Queue()
            _progress_channels[job_id] = queue
        return queue


async def _discard_progress_queue(job_id: str) -> None:
    async with _progress_lock:
        _progress_channels.pop(job_id, None)


async def _schedule_discard(job_id: str, delay: float = 120.0) -> None:
    await asyncio.sleep(delay)
    await _discard_progress_queue(job_id)


def _lookup_section(name: str) -> str:
    lower_name = (name or "").lower()
    for rule in SECTION_RULES:
        patterns = rule.get("patterns") or []
        for pattern in patterns:
            if isinstance(pattern, str) and pattern in lower_name:
                return str(rule.get("section", "Additional Checks"))
    return "Additional Checks"


def _status_to_risk(status: str) -> str:
    mapping = {
        "PASS": "LOW",
        "INFO": "LOW",
        "WARN": "MEDIUM",
        "FAIL": "HIGH",
        "SKIP": "LOW",
    }
    return mapping.get((status or "").upper(), "MEDIUM")


def _default_summary(result: Any) -> Dict[str, str]:
    return {
        "summary_sentence": result.evidence or f"Status reported as {result.status}",
        "risk_level": _status_to_risk(result.status),
        "section": _lookup_section(result.name),
    }


def _build_summary_lookup(analysis: Dict[str, object], raw_results: List[Any]) -> Dict[str, Dict[str, str]]:
    lookup: Dict[str, Dict[str, str]] = {}
    per_check = analysis.get("per_check") if isinstance(analysis, dict) else None
    if isinstance(per_check, list):
        for entry in per_check:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not name:
                continue
            risk_value = entry.get("risk_level", "") if isinstance(entry, dict) else ""
            lookup[str(name)] = {
                "summary_sentence": str(entry.get("summary_sentence", "") if isinstance(entry, dict) else ""),
                "risk_level": str(risk_value).upper() if risk_value else "",
                "section": str(entry.get("section", _lookup_section(str(name))) if isinstance(entry, dict) else _lookup_section(str(name))),
            }

    for result in raw_results:
        lookup.setdefault(result.name, _default_summary(result))

    return lookup


def _prepare_results(
    raw_results: List[Any],
    summaries: Dict[str, Dict[str, str]],
) -> List[Dict[str, Any]]:
    prepared: List[Dict[str, Any]] = []
    for result in raw_results:
        style = STATUS_STYLES.get(result.status, {"badge": "secondary", "icon": "adjust"})
        payload_data = result.data if isinstance(result.data, dict) else {}
        details = ""
        if payload_data:
            try:
                details = json.dumps(payload_data, indent=2, default=str)
            except TypeError:
                details = str(payload_data)

        summary_info = summaries.get(result.name) or _default_summary(result)
        prepared.append(
            {
                "id": result.id,
                "name": result.name,
                "status": result.status,
                "badge": style["badge"],
                "icon": style["icon"],
                "evidence": result.evidence or "",
                "details": details,
                "data": payload_data,
                "summary": summary_info.get("summary_sentence")
                or result.evidence
                or f"Status reported as {result.status}",
                "risk_level": summary_info.get("risk_level") or _status_to_risk(result.status),
                "section": summary_info.get("section") or _lookup_section(result.name),
            }
        )
    return prepared


def _build_summary_cards(counts: Dict[str, int]) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []
    for status in ["PASS", "WARN", "FAIL", "INFO", "SKIP"]:
        style = STATUS_STYLES.get(status, {"badge": "secondary", "icon": "bi-dot"})
        cards.append(
            {
                "status": status,
                "count": counts.get(status, 0),
                "badge": style["badge"],
                "icon": style["icon"],
            }
        )
    return cards


def _group_by_section(prepared_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sections: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for item in prepared_results:
        section = str(item.get("section") or "Additional Checks")
        if section not in sections:
            sections[section] = []
            order.append(section)
        sections[section].append(item)
    return [{"name": name, "checks": sections[name]} for name in order]


async def _run_ai_analysis(raw_results: List[Any]) -> Dict[str, Any]:
    provider = os.getenv("AI_PROVIDER", "nim").lower()
    try:
        if provider == "nim":
            from url_audit.nim_analyzers import analyze_results_with_nim

            return await asyncio.to_thread(analyze_results_with_nim, raw_results)
        if provider == "ollama":
            from url_audit.llm_analyzers import analyze_results_with_llm

            return await asyncio.to_thread(analyze_results_with_llm, raw_results)
        return {"enabled": False, "error": f"Unsupported AI provider: {provider}"}
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": str(exc)}


@app.get("/", include_in_schema=False)
async def index_redirect() -> RedirectResponse:
    return RedirectResponse(url=_frontend_url(), status_code=307)


@app.post("/audit", include_in_schema=False)
async def audit_redirect() -> RedirectResponse:
    return RedirectResponse(url=f"{_frontend_url()}/scanner", status_code=307)


@app.post("/api/audit")
async def audit_json(
    url: str = Form(...),
    job_id: Optional[str] = Form(None),
    scan_mode: Optional[str] = Form("scan"),
) -> JSONResponse:
    clean_url = url.strip()
    if not clean_url:
        return JSONResponse(
            content={"error": "Please enter a URL to audit."},
            status_code=400,
        )

    mode = (scan_mode or "scan").strip().lower()
    if mode not in {"scan", "deep", "sandbox"}:
        mode = "scan"

    progress_queue: Optional[asyncio.Queue] = None
    loop = asyncio.get_running_loop()
    total = total_steps()
    started_at = time.perf_counter()

    if job_id:
        progress_queue = await _get_progress_queue(job_id)
        await progress_queue.put(
            {
                "type": "start",
                "step": 0,
                "total": total,
                "percent": 0,
                "label": "Preparing audit",
            }
        )

    def progress_callback(step_index: int, step_total: int, label: str, _: List[Any]) -> None:
        if not progress_queue:
            return
        adjusted_index = step_index if step_index <= step_total else step_total
        percent = int((adjusted_index / max(total, 1)) * 100)
        payload = {
            "type": "progress",
            "step": adjusted_index,
            "total": total,
            "percent": percent,
            "label": label,
        }
        loop.call_soon_threadsafe(progress_queue.put_nowait, payload)

    try:
        raw_results = await asyncio.to_thread(run_all, clean_url, progress_callback)
        counts = summarize(raw_results)
    except Exception as exc:  # noqa: BLE001
        if progress_queue:
            await progress_queue.put({"type": "error", "message": str(exc)})
            if job_id:
                asyncio.create_task(_schedule_discard(job_id))
        return JSONResponse(
            content={"error": f"Failed to audit URL: {exc}"},
            status_code=500,
        )

    analysis = await _run_ai_analysis(raw_results)

    summary_lookup = _build_summary_lookup(analysis, raw_results)
    prepared_results = _prepare_results(raw_results, summary_lookup)
    grouped_results = _group_by_section(prepared_results)

    threat_report = analysis.get("threat_report") if isinstance(analysis, dict) else None
    if not isinstance(threat_report, dict):
        threat_report = None

    metadata = analysis.get("metadata") if isinstance(analysis, dict) else None
    if not isinstance(metadata, dict):
        metadata = None

    analysis_error = analysis.get("error") if isinstance(analysis, dict) else None
    if analysis_error == "unparsed":
        analysis_error = "AI response could not be parsed."

    risk_meta = compute_risk(prepared_results)
    created_at = datetime.now(timezone.utc).isoformat()
    duration_ms = int((time.perf_counter() - started_at) * 1000)

    scan_id, ioc_count = persist_scan(
        target_url=clean_url,
        scan_mode=mode,
        prepared_results=prepared_results,
        counts=counts,
        risk_score=int(risk_meta["risk_score"]),
        risk_level=str(risk_meta["risk_level"]),
        verdict=str(risk_meta["verdict"]),
        threat_report=threat_report,
        duration_ms=duration_ms,
        created_at=created_at,
    )

    if progress_queue:
        await progress_queue.put(
            {
                "type": "complete",
                "step": total,
                "total": total,
                "percent": 100,
                "label": "Audit complete",
            }
        )
        if job_id:
            asyncio.create_task(_schedule_discard(job_id))

    summary_cards = _build_summary_cards(counts)
    total_checks = sum(counts.values())

    return JSONResponse(
        content={
            "results": prepared_results,
            "grouped_results": grouped_results,
            "summary_cards": summary_cards,
            "target_url": clean_url,
            "total_checks": total_checks,
            "ai_threat_report": threat_report,
            "ai_metadata": metadata,
            "ai_error": analysis_error,
            "scan_id": scan_id,
            "scan_mode": mode,
            "risk_score": risk_meta["risk_score"],
            "risk_level": risk_meta["risk_level"],
            "verdict": risk_meta["verdict"],
            "duration_ms": duration_ms,
            "created_at": created_at,
            "ioc_count": ioc_count,
        }
    )


@app.get("/api/dashboard/overview")
async def dashboard_overview(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
) -> Dict[str, Any]:
    return get_dashboard_overview(range_value=range)


@app.get("/api/scans")
async def scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    q: str = Query(""),
    risk: str = Query(""),
    status: str = Query(""),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
) -> Dict[str, Any]:
    return list_scans(
        page=page,
        page_size=page_size,
        q=q,
        risk=risk,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.get("/api/scans/{scan_id}")
async def scan_by_id(scan_id: int) -> JSONResponse:
    payload = get_scan(scan_id)
    if payload is None:
        return JSONResponse(content={"error": "Scan not found"}, status_code=404)
    return JSONResponse(content=payload)


@app.get("/api/scans/{scan_id}/report")
async def scan_report(scan_id: int) -> JSONResponse:
    payload = get_scan_report(scan_id)
    if payload is None:
        return JSONResponse(content={"error": "Scan not found"}, status_code=404)
    return JSONResponse(content=payload)


@app.get("/api/iocs")
async def iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    q: str = Query(""),
    type: str = Query("", alias="type"),
    severity: str = Query(""),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
) -> Dict[str, Any]:
    return list_iocs(
        page=page,
        page_size=page_size,
        q=q,
        indicator_type=type,
        severity=severity,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.get("/api/threat-intelligence/map")
async def threat_map(
    range: str = Query("24h", pattern="^(24h|7d|30d)$"),
) -> Dict[str, Any]:
    return get_threat_map(range_value=range)


@app.get("/api/threat-intelligence/domains")
async def threat_domains(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    return get_top_malicious_domains(limit=limit)


@app.get("/api/threat-intelligence/ip-reputation")
async def threat_ip_reputation(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    return get_ip_reputation(limit=limit)


@app.websocket("/ws/progress/{job_id}")
async def audit_progress(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    queue = await _get_progress_queue(job_id)
    try:
        while True:
            message = await queue.get()
            await websocket.send_json(message)
            if message.get("type") in {"complete", "error"}:
                break
    except WebSocketDisconnect:
        pass
    finally:
        await _discard_progress_queue(job_id)

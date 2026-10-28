import os
import json
import re
import subprocess
import shlex
from datetime import datetime
from typing import Dict, Any, Optional, Iterable, List

from urllib.parse import urlparse, urlunparse

from .utils import get_env

try:
    from ollama import Client
except Exception:  # noqa: BLE001
    Client = None

# Optional JSON auto-repair (install with: pip install json-repair)
try:
    from json_repair import repair_json
except Exception:  # noqa: BLE001
    repair_json = None


def _normalize_host(host: str) -> str:
    """Prefer IPv4 loopback when users specify localhost to avoid ::1 issues."""

    if not host:
        return "http://127.0.0.1:11434"

    parsed = urlparse(host)
    if parsed.hostname and parsed.hostname.lower() == "localhost":
        new_netloc = parsed.netloc.replace("localhost", "127.0.0.1", 1)
        return urlunparse(
            (
                parsed.scheme or "http",
                new_netloc or "127.0.0.1:11434",
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
    return host


def _client() -> Optional["Client"]:
    host = _normalize_host(get_env("OLLAMA_HOST", "http://127.0.0.1:11434"))
    return Client(host=host) if Client else None


def _extract_json_candidates(text: str) -> Iterable[str]:
    """
    Yield likely JSON blocks from a text response.
    Finds one or more {...} blocks; yields longest-first, then others.
    """
    matches = list(re.finditer(r"\{.*?\}", text, re.S))
    if not matches:
        return []
    # sort by length descending so we try the largest block first
    blocks = sorted((m.group(0) for m in matches), key=len, reverse=True)
    return blocks


def _parse_json_lenient(text: str) -> Optional[dict]:
    """
    Try parsing JSON from the model output:
    1) parse full text
    2) parse JSON-looking blocks (largest to smallest)
    3) attempt auto-repair when available
    """
    # First try the whole text as-is
    for candidate in [text, *list(_extract_json_candidates(text))]:
        # Raw
        try:
            return json.loads(candidate)
        except Exception:
            pass
        # Attempt repair, if available
        if repair_json is not None:
            try:
                fixed = repair_json(candidate)
                return json.loads(fixed)
            except Exception:
                pass
    return None


def _subprocess_fallback(model: str, prompt: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Fallback to `ollama run` to ensure we can still get an answer even if the python client fails.
    """
    try:
        cmd = f"ollama run {shlex.quote(model)} {shlex.quote(prompt)}"
        out = subprocess.check_output(
            cmd,
            shell=True,
            timeout=timeout,
            stderr=subprocess.STDOUT,
            text=True,
        )
        parsed = _parse_json_lenient(out)
        if parsed is not None:
            return {"enabled": True, **parsed, "_via": "subprocess"}
        return {"enabled": True, "raw": out, "_via": "subprocess"}
    except Exception as e:  # noqa: BLE001
        err_text = str(e)
        payload: Dict[str, Any] = {"enabled": False, "error": f"subprocess: {err_text}"}
        if _model_missing(err_text):
            payload["reason"] = "model_not_found"
        return payload


def _model_missing(message: Optional[str]) -> bool:
    if not message:
        return False
    lowered = message.lower()
    return "model" in lowered and ("not found" in lowered or "does not exist" in lowered)


def _truncate(text: str, limit: int = 220) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _status_to_risk(status: str) -> str:
    mapping = {
        "PASS": "LOW",
        "INFO": "LOW",
        "WARN": "MODERATE",
        "FAIL": "HIGH",
        "SKIP": "LOW",
    }
    return mapping.get(status.upper(), "MODERATE")


def _status_phrase(status: str) -> str:
    return {
        "PASS": "passes validation",
        "WARN": "raises warnings",
        "FAIL": "fails critical checks",
        "INFO": "provides informational insight",
        "SKIP": "was not evaluated",
    }.get(status.upper(), "status recorded")


def _text_analysis_fallback(reason: str) -> Dict[str, Any]:
    return {
        "enabled": False,
        "summary": "Local Ollama model unavailable; generated heuristic content assessment.",
        "overall_risk": "UNKNOWN",
        "grammar_issues": "UNKNOWN: LLM model not available",
        "too_good_claims": "UNKNOWN: LLM model not available",
        "credential_or_payment_risk": "UNKNOWN: LLM model not available",
        "brand_mismatch": "UNKNOWN: LLM model not available",
        "generic_content": "UNKNOWN: LLM model not available",
        "phishy_tone": "UNKNOWN: LLM model not available",
        "metadata": {
            "generator": "url-audit-kit",
            "model": "heuristic-fallback",
            "note": _truncate(reason, 200),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
    }


def _fallback_results(results: List["CheckResult"], reason: str) -> Dict[str, Any]:
    from .utils import CheckResult  # local import to avoid cycles

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
    per_check: List[Dict[str, str]] = []
    warn_checks: List[str] = []
    fail_checks: List[str] = []

    for res in results:
        if not isinstance(res, CheckResult):
            continue
        counts[res.status] = counts.get(res.status, 0) + 1
        if res.status == "WARN":
            warn_checks.append(res.name)
        if res.status == "FAIL":
            fail_checks.append(res.name)
        evidence = res.evidence or "No evidence captured"
        summary_sentence = _truncate(
            f"{res.name}: {_status_phrase(res.status)}. {evidence}",
            220,
        )
        per_check.append(
            {
                "name": res.name,
                "status": res.status,
                "summary_sentence": summary_sentence,
                "risk_level": _status_to_risk(res.status),
            }
        )

    total_checks = len(per_check)
    fail_total = counts.get("FAIL", 0)
    warn_total = counts.get("WARN", 0)

    if fail_total > 0:
        verdict = "MALICIOUS"
    elif warn_total > 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    key_findings: List[str] = []
    if fail_total:
        key_findings.append(f"{fail_total} checks failed: {', '.join(fail_checks[:3])}.")
    else:
        key_findings.append("No critical failures detected across the evaluated checks.")
    if warn_total:
        key_findings.append(
            _truncate(
                f"Warnings observed in {warn_total} checks including {', '.join(warn_checks[:3])}.",
                200,
            )
        )
    key_findings.append(
        f"Overall status mix — PASS: {counts.get('PASS', 0)}, WARN: {warn_total}, FAIL: {fail_total}."
    )

    recommendations: List[str] = []
    if fail_total:
        recommendations.append("Address failed controls immediately and validate remediation before go-live.")
    if warn_total:
        recommendations.append("Review warning checks for hardening opportunities and configure missing controls.")
    recommendations.append(
        "Install or configure the required Ollama model (e.g., run `ollama pull llama3.1:8b`) or update `OLLAMA_MODEL`."
    )

    executive_summary = _truncate(
        (
            f"Generated fallback intelligence for {total_checks} checks. "
            f"Fail={fail_total}, Warn={warn_total}, Pass={counts.get('PASS', 0)}. "
            f"Reason: {reason}."
        ),
        260,
    )

    threat_report = {
        "executive_summary": executive_summary,
        "key_findings": key_findings,
        "verdict": verdict,
        "verdict_rationale": _truncate(
            "Verdict derived from deterministic scoring in fallback mode because the configured Ollama model is unavailable.",
            260,
        ),
        "recommendations": recommendations,
    }

    metadata = {
        "generator": "url-audit-kit",
        "model": "heuristic-fallback",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "note": _truncate(reason, 200),
    }

    return {
        "enabled": False,
        "per_check": per_check,
        "threat_report": threat_report,
        "metadata": metadata,
    }


def analyze_text_with_llm(page_text: str, domain: str) -> Dict[str, Any]:
    """
    Uses a local Ollama model to judge:
    - grammar/spelling anomalies
    - too-good-to-be-true signals
    - brand consistency red flags
    - login/payment risk cues
    Returns a dict with booleans/notes and a compact summary.
    """
    model = get_env("OLLAMA_MODEL", "llama3.1:8b")
    timeout = int(get_env("OLLAMA_TIMEOUT", "60") or "60")

    prompt = f"""You are a security reviewer. Given the domain "{domain}" and this web page text:
---
{page_text[:12000]}
---
Respond ONLY with a single JSON object (no prose before/after). Use double quotes for all keys/strings.
Include 8–10 concise bullet findings with YES/NO + one-line reason.
Use exactly these keys:
  "grammar_issues", "too_good_claims", "credential_or_payment_risk",
  "brand_mismatch", "generic_content", "phishy_tone",
  "overall_risk", "summary"
Where:
- grammar_issues: "YES|NO: reason"
- too_good_claims: "YES|NO: reason"
- credential_or_payment_risk: "YES|NO: reason"
- brand_mismatch: "YES|NO: reason"
- generic_content: "YES|NO: reason"
- phishy_tone: "YES|NO: reason"
- overall_risk: "LOW|MEDIUM|HIGH"
- summary: one sentence.
"""

    # Try Python client first
    if Client:
        try:
            cli = _client()
            resp = cli.generate(
                model=model,
                prompt=prompt,
                options={"temperature": 0.1},
            )
            content = resp.get("response", "") if isinstance(resp, dict) else str(resp)
            parsed = _parse_json_lenient(content)
            if parsed is not None:
                return {"enabled": True, **parsed, "_via": "python-client"}
            # If not valid JSON, still return raw so user can see what came back
            return {"enabled": True, "raw": content, "_via": "python-client"}
        except Exception as e:  # noqa: BLE001
            py_err = str(e)
            if _model_missing(py_err):
                return _text_analysis_fallback(py_err)
            fb = _subprocess_fallback(model, prompt, timeout=timeout)
            if fb.get("enabled"):
                fb["_python_error"] = py_err
                return fb
            if _model_missing(py_err) or _model_missing(fb.get("error")):
                return _text_analysis_fallback(fb.get("error") or py_err)
            return _text_analysis_fallback(f"python-client error: {py_err}; {fb.get('error','')}")

    # Fallback directly to CLI
    fb = _subprocess_fallback(model, prompt, timeout=timeout)
    if fb.get("enabled"):
        return fb
    if _model_missing(fb.get("error")) or _model_missing(fb.get("raw")):
        return _text_analysis_fallback(fb.get("error") or fb.get("raw") or "Ollama model unavailable")
    return _text_analysis_fallback(fb.get("error") or "Local content analysis unavailable")


def _summarize_payload(results: List["CheckResult"]) -> str:
    """Serialize check results to compact JSON safe for prompts."""

    from .utils import CheckResult  # local import to avoid cycles

    def _trim(value: str, limit: int = 320) -> str:
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."

    payload = []
    for r in results:
        if not isinstance(r, CheckResult):
            continue
        data_excerpt = ""
        if r.data:
            try:
                raw = json.dumps(r.data, default=str)
            except Exception:
                raw = str(r.data)
            data_excerpt = _trim(raw, limit=420)
        payload.append(
            {
                "name": r.name,
                "status": r.status,
                "evidence": _trim(r.evidence or "", limit=220),
                "data_excerpt": data_excerpt,
            }
        )

    return json.dumps({"checks": payload}, ensure_ascii=False, separators=(",", ":"))


def analyze_results_with_llm(results: List["CheckResult"]) -> Dict[str, Any]:
    """Generate per-check summaries and an overall threat assessment via Ollama."""

    model = get_env("OLLAMA_MODEL", "llama3.1:8b")
    timeout = int(get_env("OLLAMA_TIMEOUT", "90") or "90")
    payload = _summarize_payload(results)

    prompt = (
        "You are a senior cyber threat analyst. Review the following URL audit checks and respond ONLY "
        "with JSON. For each check craft a concise professional sentence that captures the outcome. "
        "Also produce an overall threat intelligence brief.\n"
        "Input data (JSON):\n" + payload + "\n"
        "Return JSON with exactly these keys:\n"
        "  per_check: array of objects with keys name, status, summary_sentence, risk_level.\n"
        "    - summary_sentence: <=220 characters, authoritative tone.\n"
        "    - risk_level: one of LOW, MODERATE, HIGH.\n"
        "    Include every check name from the input.\n"
        "  threat_report: object with keys executive_summary, key_findings, verdict, verdict_rationale, recommendations.\n"
        "    - key_findings: array of 3-6 bullet strings.\n"
        "    - verdict: BENIGN, SUSPICIOUS, or MALICIOUS.\n"
        "    - recommendations: array of actionable bullet strings.\n"
        "  metadata: object with generator (set to 'ollama'), model, and timestamp (ISO 8601).\n"
        "Do not include any prose outside of the JSON object."
    )

    def _prepare_response(content: str) -> Dict[str, Any]:
        parsed = _parse_json_lenient(content)
        if isinstance(parsed, dict) and parsed.get("per_check"):
            return {"enabled": True, **parsed, "_via": parsed.get("_via", "python-client")}
        return {"enabled": True, "raw": content, "error": "unparsed"}

    if Client:
        try:
            cli = _client()
            resp = cli.generate(model=model, prompt=prompt, options={"temperature": 0.1})
            content = resp.get("response", "") if isinstance(resp, dict) else str(resp)
            parsed = _prepare_response(content)
            if parsed.get("per_check"):
                return parsed
        except Exception as e:  # noqa: BLE001
            py_err = str(e)
            if _model_missing(py_err):
                return _fallback_results(results, py_err)
            fb = _subprocess_fallback(model, prompt, timeout=timeout)
            if fb.get("enabled") and isinstance(fb.get("per_check"), list):
                fb["_python_error"] = py_err
                return fb
            if _model_missing(py_err) or _model_missing(fb.get("error")):
                return _fallback_results(results, fb.get("error") or py_err)
            return _fallback_results(results, f"python-client error: {py_err}; {fb.get('error','')}")

    fb = _subprocess_fallback(model, prompt, timeout=timeout)
    if isinstance(fb.get("per_check"), list):
        return fb
    if fb.get("enabled"):
        return {**fb, "error": fb.get("error") or "Failed to parse JSON"}
    if _model_missing(fb.get("error")) or _model_missing(fb.get("raw")):
        return _fallback_results(results, fb.get("error") or fb.get("raw") or "Ollama model unavailable")
    return _fallback_results(results, fb.get("error") or "LLM analysis unavailable")

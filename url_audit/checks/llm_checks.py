from ..utils import CheckResult, fetch, get_env

def _get_analyzer():
    provider = get_env("AI_PROVIDER", "nim").lower()
    if provider == "nim":
        from ..nim_analyzers import analyze_text_with_nim
        return analyze_text_with_nim
    else:
        from ..llm_analyzers import analyze_text_with_llm
        return analyze_text_with_llm

def check_llm_content_analysis(url: str) -> CheckResult:
    """
    (41) AI-powered content analysis for phishing signals
    """
    try:
        resp, html, soup = fetch(url)
        if not soup:
            return CheckResult(41, "AI Content Analysis", "SKIP", evidence="Could not fetch page content")
        
        text = soup.get_text(" ", strip=True)
        if not text or len(text) < 50:
            return CheckResult(41, "AI Content Analysis", "SKIP", evidence="Insufficient text content")
        
        from ..utils import domain_parts
        _, host, _ = domain_parts(url)
        analyze_func = _get_analyzer()
        analysis = analyze_func(text, host or "unknown")
        
        if not analysis.get("enabled"):
            reason = analysis.get("summary") or analysis.get("error") or "LLM unavailable"
            return CheckResult(41, "AI Content Analysis", "INFO", evidence=reason[:200])
        
        # Extract risk signals
        risks = []
        if "YES" in str(analysis.get("grammar_issues", "")).upper():
            risks.append("grammar")
        if "YES" in str(analysis.get("too_good_claims", "")).upper():
            risks.append("too-good-claims")
        if "YES" in str(analysis.get("credential_or_payment_risk", "")).upper():
            risks.append("credential-risk")
        if "YES" in str(analysis.get("brand_mismatch", "")).upper():
            risks.append("brand-mismatch")
        if "YES" in str(analysis.get("phishy_tone", "")).upper():
            risks.append("phishy-tone")
        
        overall = str(analysis.get("overall_risk", "LOW")).upper()
        status = "FAIL" if overall == "HIGH" else ("WARN" if overall == "MEDIUM" or risks else "PASS")
        
        evidence = f"risk={overall}"
        if risks:
            evidence += f" flags={','.join(risks)}"
        
        summary = analysis.get("summary", "")
        if summary:
            evidence += f" | {summary[:150]}"
        
        return CheckResult(41, "AI Content Analysis", status, evidence=evidence, data=analysis)
    except Exception as e:
        return CheckResult(41, "AI Content Analysis", "WARN", evidence=f"Analysis error: {str(e)[:150]}")

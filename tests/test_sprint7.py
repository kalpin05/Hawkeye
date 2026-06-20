import pytest
import sys
import os
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.ai_triage import (
    triage_findings,
    get_fallback_triage,
    build_prompt,
    call_groq,
    SEVERITY_SCORES,
)


# ── Prompt builder ────────────────────────

def test_build_prompt_contains_check():
    finding = {"check": "XSS Found", "severity": "high",
               "detail": "test", "module": "web"}
    prompt  = build_prompt(finding)
    assert "XSS Found" in prompt

def test_build_prompt_contains_severity():
    finding = {"check": "Test", "severity": "critical",
               "detail": "test", "module": "web"}
    prompt  = build_prompt(finding)
    assert "critical" in prompt

def test_build_prompt_requests_json():
    finding = {"check": "Test", "severity": "high",
               "detail": "test", "module": "web"}
    prompt  = build_prompt(finding)
    assert "JSON" in prompt or "json" in prompt


# ── Fallback triage ───────────────────────

def test_fallback_returns_dict():
    finding = {"check": "XSS Found", "severity": "high",
               "detail": "test", "module": "web"}
    result  = get_fallback_triage(finding)
    assert isinstance(result, dict)

def test_fallback_has_required_keys():
    finding = {"check": "Test", "severity": "medium", "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    for key in ["risk_score", "severity", "title", "explanation", "impact", "fix", "ai_powered"]:
        assert key in result

def test_fallback_ai_powered_false():
    finding = {"check": "Test", "severity": "low", "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    assert result["ai_powered"] is False

def test_fallback_risk_score_critical():
    finding = {"check": "Test", "severity": "critical", "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    assert result["risk_score"] == 9

def test_fallback_risk_score_info():
    finding = {"check": "Test", "severity": "info", "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    assert result["risk_score"] == 1

def test_fallback_xss_fix():
    finding = {"check": "XSS: Reflected", "severity": "high",
               "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    assert "xss" in result["fix"].lower() or "encode" in result["fix"].lower()

def test_fallback_sqli_fix():
    finding = {"check": "SQLi: Injection", "severity": "critical",
               "detail": "", "module": "web"}
    result  = get_fallback_triage(finding)
    assert "parameterized" in result["fix"].lower() or "prepared" in result["fix"].lower()


# ── Triage findings ───────────────────────

def test_triage_returns_list():
    findings = [
        {"check": "XSS Found", "severity": "high", "detail": "test", "module": "web"}
    ]
    result = triage_findings(findings)
    assert isinstance(result, list)

def test_triage_same_length():
    findings = [
        {"check": "XSS Found",  "severity": "high",   "detail": "test", "module": "web"},
        {"check": "SQLi Found", "severity": "critical","detail": "test", "module": "web"},
    ]
    result = triage_findings(findings)
    assert len(result) == len(findings)

def test_triage_adds_ai_triage_key():
    findings = [
        {"check": "XSS Found", "severity": "high", "detail": "test", "module": "web"}
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", ""):
        result = triage_findings(findings)
        assert "ai_triage" in result[0]

def test_triage_skips_info_findings():
    findings = [
        {"check": "Web Scan Complete", "severity": "info",
         "detail": "nothing found", "module": "web"},
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", ""):
        result = triage_findings(findings)
        # Info/skip findings should pass through without ai_triage key
        assert isinstance(result, list)
        assert len(result) == 1

def test_triage_fallback_when_no_key():
    findings = [
        {"check": "Port Open: 3306/MySQL", "severity": "critical",
         "detail": "MySQL exposed", "module": "network"}
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", ""):
        result = triage_findings(findings)
        assert "ai_triage" in result[0]
        assert result[0]["ai_triage"]["ai_powered"] is False

def test_triage_fallback_structure():
    findings = [
        {"check": "Missing HSTS", "severity": "high",
         "detail": "HSTS missing", "module": "headers"}
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", ""):
        result      = triage_findings(findings)
        ai_triage   = result[0]["ai_triage"]
        for key in ["risk_score", "title", "explanation", "impact", "fix"]:
            assert key in ai_triage

def test_triage_with_mock_ai():
    """Test with mocked Groq API response."""
    mock_ai_response = {
        "risk_score":   8,
        "severity":     "high",
        "title":        "Reflected XSS Vulnerability",
        "explanation":  "An attacker can inject malicious scripts into the page.",
        "impact":       "Users visiting the page may have their data stolen.",
        "fix":          "1. Encode output. 2. Add CSP header. 3. Use WAF.",
    }
    findings = [
        {"check": "XSS Found", "severity": "high", "detail": "test", "module": "web"}
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", "fake_key"):
        with patch("modules.ai_triage.call_groq", return_value=mock_ai_response):
            result = triage_findings(findings)
            assert "ai_triage" in result[0]
            assert result[0]["ai_triage"]["risk_score"] == 8
            assert result[0]["ai_triage"]["ai_powered"] is True

def test_triage_ai_fails_uses_fallback():
    """Test that fallback kicks in when AI call fails."""
    findings = [
        {"check": "SQLi Found", "severity": "critical", "detail": "test", "module": "web"}
    ]
    with patch("modules.ai_triage.GROQ_API_KEY", "fake_key"):
        with patch("modules.ai_triage.call_groq", return_value=None):
            result = triage_findings(findings)
            assert "ai_triage" in result[0]
            assert result[0]["ai_triage"]["ai_powered"] is False

def test_severity_scores_complete():
    for sev in ["critical", "high", "medium", "low", "info"]:
        assert sev in SEVERITY_SCORES
        assert isinstance(SEVERITY_SCORES[sev], int)
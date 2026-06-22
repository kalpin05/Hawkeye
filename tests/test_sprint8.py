import pytest
import sys
import os
import json

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.reporter import (
    generate_json,
    generate_html,
    generate_pdf,
    count_by_severity,
    get_risk_level,
    get_output_path,
    ensure_reports_dir,
)

# Sample findings for testing
SAMPLE_FINDINGS = [
    {
        "check":    "XSS: Reflected",
        "severity": "high",
        "detail":   "XSS found in search form",
        "module":   "web",
        "url":      "http://example.com/search",
        "ai_triage": {
            "risk_score":   7,
            "title":        "Reflected XSS Vulnerability",
            "explanation":  "An attacker can inject scripts.",
            "impact":       "User data could be stolen.",
            "fix":          "1. Encode output. 2. Add CSP. 3. Use WAF.",
            "ai_powered":   False,
        }
    },
    {
        "check":    "SQLi: MySQL Injection",
        "severity": "critical",
        "detail":   "SQL injection in login form",
        "module":   "web",
        "url":      "http://example.com/login",
    },
    {
        "check":    "Missing: HSTS",
        "severity": "high",
        "detail":   "HSTS header not set",
        "module":   "headers",
    },
    {
        "check":    "Web Scan Complete",
        "severity": "info",
        "detail":   "Scan done",
        "module":   "web",
    },
]


# ── Helpers ───────────────────────────────

def test_count_by_severity():
    counts = count_by_severity(SAMPLE_FINDINGS)
    assert counts["critical"] == 1
    assert counts["high"]     == 2
    assert counts["info"]     == 1

def test_get_risk_level_critical():
    counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert get_risk_level(counts) == "CRITICAL"

def test_get_risk_level_high():
    counts = {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0}
    assert get_risk_level(counts) == "HIGH"

def test_get_risk_level_clean():
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 3}
    assert get_risk_level(counts) == "CLEAN"

def test_ensure_reports_dir():
    ensure_reports_dir()
    reports_dir = os.path.join(ROOT, "reports")
    assert os.path.exists(reports_dir)


# ── JSON report ───────────────────────────

def test_generate_json_returns_path():
    path = generate_json(SAMPLE_FINDINGS, target="http://example.com")
    assert isinstance(path, str)
    assert path.endswith(".json")
    # Cleanup
    if os.path.exists(path): os.remove(path)

def test_generate_json_file_exists():
    path = generate_json(SAMPLE_FINDINGS, target="http://example.com")
    assert os.path.exists(path)
    if os.path.exists(path): os.remove(path)

def test_generate_json_valid_json():
    path = generate_json(SAMPLE_FINDINGS, target="http://example.com")
    with open(path) as f:
        data = json.load(f)
    assert "findings"    in data
    assert "summary"     in data
    assert "target"      in data
    assert "risk_level"  in data
    if os.path.exists(path): os.remove(path)

def test_generate_json_summary_counts():
    path = generate_json(SAMPLE_FINDINGS, target="http://example.com")
    with open(path) as f:
        data = json.load(f)
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"]     == 2
    if os.path.exists(path): os.remove(path)

def test_generate_json_risk_level():
    path = generate_json(SAMPLE_FINDINGS, target="http://example.com")
    with open(path) as f:
        data = json.load(f)
    assert data["risk_level"] == "CRITICAL"
    if os.path.exists(path): os.remove(path)

def test_generate_json_empty_findings():
    path = generate_json([], target="http://example.com")
    with open(path) as f:
        data = json.load(f)
    assert data["summary"]["total"] == 0
    assert data["risk_level"] == "CLEAN"
    if os.path.exists(path): os.remove(path)


# ── HTML report ───────────────────────────

def test_generate_html_returns_path():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    assert isinstance(path, str)
    assert path.endswith(".html")
    if os.path.exists(path): os.remove(path)

def test_generate_html_file_exists():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    assert os.path.exists(path)
    if os.path.exists(path): os.remove(path)

def test_generate_html_contains_target():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "example.com" in content
    if os.path.exists(path): os.remove(path)

def test_generate_html_contains_findings():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "XSS" in content
    assert "SQLi" in content
    if os.path.exists(path): os.remove(path)

def test_generate_html_contains_ai_triage():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "Risk Score" in content
    assert "Fix:" in content
    if os.path.exists(path): os.remove(path)

def test_generate_html_severity_colors():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "CRITICAL" in content
    assert "HIGH" in content
    if os.path.exists(path): os.remove(path)

def test_generate_html_hawkeye_branding():
    path = generate_html(SAMPLE_FINDINGS, target="http://example.com")
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "HAWKEYE" in content
    assert "Kalpin Patel" in content
    if os.path.exists(path): os.remove(path)


# ── PDF report ────────────────────────────

def test_generate_pdf_returns_path():
    path = generate_pdf(SAMPLE_FINDINGS, target="http://example.com")
    assert isinstance(path, str)
    assert os.path.exists(path)
    if os.path.exists(path): os.remove(path)

def test_generate_pdf_no_crash():
    # Should not crash even if WeasyPrint not installed
    try:
        path = generate_pdf(SAMPLE_FINDINGS, target="http://example.com")
        assert path is not None
        if os.path.exists(path): os.remove(path)
    except Exception as e:
        pytest.fail(f"generate_pdf crashed: {e}")
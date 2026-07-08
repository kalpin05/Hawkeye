import pytest
import sys
import os
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.diff_engine import (
    fingerprint,
    diff_findings,
    get_risk_trend,
    build_diff_report,
)


# ── Helpers ───────────────────────────────

FINDING_A = {
    "check":    "XSS: Reflected",
    "severity": "high",
    "detail":   "XSS found",
    "module":   "web",
    "url":      "http://example.com/search",
}

FINDING_B = {
    "check":    "SQLi: MySQL",
    "severity": "critical",
    "detail":   "SQL injection",
    "module":   "web",
    "url":      "http://example.com/login",
}

FINDING_C = {
    "check":    "Missing HSTS",
    "severity": "high",
    "detail":   "HSTS missing",
    "module":   "headers",
    "url":      "http://example.com",
}

FINDING_INFO = {
    "check":    "Pages Discovered",
    "severity": "info",
    "detail":   "Found 5 pages",
    "module":   "web",
    "url":      "",
}


# ── Fingerprint ───────────────────────────

def test_fingerprint_returns_string():
    result = fingerprint(FINDING_A)
    assert isinstance(result, str)
    assert len(result) == 32  # MD5 hex

def test_fingerprint_same_finding_same_hash():
    assert fingerprint(FINDING_A) == fingerprint(FINDING_A)

def test_fingerprint_different_findings_different_hash():
    assert fingerprint(FINDING_A) != fingerprint(FINDING_B)

def test_fingerprint_ignores_detail_changes():
    f1 = {**FINDING_A, "detail": "XSS found in search form"}
    f2 = {**FINDING_A, "detail": "XSS found via parameter injection"}
    assert fingerprint(f1) == fingerprint(f2)

def test_fingerprint_handles_empty():
    result = fingerprint({})
    assert isinstance(result, str)


# ── Diff findings ─────────────────────────

def test_diff_empty_scans():
    result = diff_findings([], [])
    assert result["new"]       == []
    assert result["fixed"]     == []
    assert result["unchanged"] == []
    assert result["worsened"]  == []

def test_diff_all_new():
    result = diff_findings([], [FINDING_A, FINDING_B])
    assert len(result["new"]) == 2
    assert len(result["fixed"]) == 0

def test_diff_all_fixed():
    result = diff_findings([FINDING_A, FINDING_B], [])
    assert len(result["fixed"]) == 2
    assert len(result["new"])   == 0

def test_diff_all_unchanged():
    result = diff_findings([FINDING_A], [FINDING_A])
    assert len(result["unchanged"]) == 1
    assert len(result["new"])       == 0
    assert len(result["fixed"])     == 0

def test_diff_one_new_one_fixed():
    result = diff_findings([FINDING_A], [FINDING_B])
    assert len(result["new"])   == 1
    assert len(result["fixed"]) == 1
    assert result["new"][0]["check"]   == FINDING_B["check"]
    assert result["fixed"][0]["check"] == FINDING_A["check"]

def test_diff_detects_worsened():
    old_finding = {**FINDING_C, "severity": "medium"}
    new_finding = {**FINDING_C, "severity": "high"}
    result      = diff_findings([old_finding], [new_finding])
    assert len(result["worsened"]) == 1
    assert result["worsened"][0]["previous_severity"] == "medium"

def test_diff_ignores_info_findings():
    result = diff_findings([FINDING_INFO], [FINDING_INFO])
    assert len(result["new"])       == 0
    assert len(result["unchanged"]) == 0

def test_diff_summary_counts():
    result = diff_findings(
        [FINDING_A],
        [FINDING_B, FINDING_C],
    )
    assert result["summary"]["new"]   == 2
    assert result["summary"]["fixed"] == 1

def test_diff_url_matters_for_fingerprint():
    f1 = {**FINDING_A, "url": "http://example.com/page1"}
    f2 = {**FINDING_A, "url": "http://example.com/page2"}
    result = diff_findings([f1], [f2])
    # Different URLs = different fingerprint = one new, one fixed
    assert len(result["new"])   == 1
    assert len(result["fixed"]) == 1


# ── Risk trend ────────────────────────────

def test_risk_trend_empty():
    result = get_risk_trend([])
    assert result == "stable"

def test_risk_trend_single_scan():
    result = get_risk_trend([{"risk_level": "HIGH"}])
    assert result == "stable"

def test_risk_trend_improving():
    scans = [
        {"risk_level": "CRITICAL"},
        {"risk_level": "HIGH"},
        {"risk_level": "MEDIUM"},
        {"risk_level": "LOW"},
        {"risk_level": "CLEAN"},
    ]
    result = get_risk_trend(scans)
    assert result == "improving"

def test_risk_trend_worsening():
    scans = [
        {"risk_level": "CLEAN"},
        {"risk_level": "LOW"},
        {"risk_level": "MEDIUM"},
        {"risk_level": "HIGH"},
    ]
    result = get_risk_trend(scans)
    assert result == "worsening"

def test_risk_trend_stable():
    scans = [
        {"risk_level": "MEDIUM"},
        {"risk_level": "MEDIUM"},
        {"risk_level": "MEDIUM"},
    ]
    result = get_risk_trend(scans)
    assert result == "stable"


# ── Build diff report ─────────────────────

def test_build_diff_report_structure():
    old_scan = {
        "id":         "scan_001",
        "findings":   [FINDING_A],
        "risk_level": "HIGH",
        "created_at": "2025-01-01T00:00:00",
        "target":     "http://example.com",
    }
    new_scan = {
        "id":         "scan_002",
        "findings":   [FINDING_A, FINDING_B],
        "risk_level": "CRITICAL",
        "created_at": "2025-01-08T00:00:00",
        "target":     "http://example.com",
    }
    result = build_diff_report(old_scan, new_scan)
    assert "generated_at"    in result
    assert "target"          in result
    assert "old_scan_id"     in result
    assert "new_scan_id"     in result
    assert "diff"            in result
    assert "risk_changed"    in result
    assert "needs_attention" in result

def test_build_diff_report_detects_new():
    old_scan = {
        "id": "old", "findings": [FINDING_A],
        "risk_level": "HIGH", "created_at": "2025-01-01",
        "target": "http://example.com",
    }
    new_scan = {
        "id": "new", "findings": [FINDING_A, FINDING_B],
        "risk_level": "CRITICAL", "created_at": "2025-01-08",
        "target": "http://example.com",
    }
    result = build_diff_report(old_scan, new_scan)
    assert result["diff"]["summary"]["new"]   == 1
    assert result["needs_attention"]          is True
    assert result["risk_changed"]             is True

def test_build_diff_report_all_fixed():
    old_scan = {
        "id": "old", "findings": [FINDING_A, FINDING_B],
        "risk_level": "CRITICAL", "created_at": "2025-01-01",
        "target": "http://example.com",
    }
    new_scan = {
        "id": "new", "findings": [],
        "risk_level": "CLEAN", "created_at": "2025-01-08",
        "target": "http://example.com",
    }
    result = build_diff_report(old_scan, new_scan)
    assert result["diff"]["summary"]["fixed"] == 2
    assert result["needs_attention"]          is False
    assert result["new_risk"]                 == "CLEAN"

def test_build_diff_report_no_changes():
    scan = {
        "id": "scan", "findings": [FINDING_A],
        "risk_level": "HIGH", "created_at": "2025-01-01",
        "target": "http://example.com",
    }
    result = build_diff_report(scan, scan)
    assert result["diff"]["summary"]["new"]       == 0
    assert result["diff"]["summary"]["fixed"]     == 0
    assert result["diff"]["summary"]["unchanged"] == 1
    assert result["needs_attention"]              is False
    assert result["risk_changed"]                 is False
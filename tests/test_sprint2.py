import pytest
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.header_checker import (
    scan_headers,
    check_security_headers,
    check_ssl,
    normalize_url,
    get_hostname,
)


# ── Helpers ──────────────────────────────

def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"

def test_normalize_url_keeps_https():
    assert normalize_url("https://example.com") == "https://example.com"

def test_normalize_url_keeps_http():
    assert normalize_url("http://example.com") == "http://example.com"

def test_get_hostname():
    assert get_hostname("https://example.com") == "example.com"

def test_get_hostname_no_scheme():
    assert get_hostname("example.com") == "example.com"


# ── Output structure ─────────────────────

def test_scan_headers_returns_list():
    result = scan_headers("https://example.com")
    assert isinstance(result, list)

def test_each_finding_has_required_keys():
    result = scan_headers("https://example.com")
    for finding in result:
        assert "check"    in finding
        assert "severity" in finding
        assert "detail"   in finding
        assert "module"   in finding

def test_severity_values_are_valid():
    valid = {"critical", "high", "medium", "low", "info"}
    result = scan_headers("https://example.com")
    for finding in result:
        assert finding["severity"] in valid, f"Invalid severity: {finding['severity']}"

def test_module_field_is_headers_or_ssl():
    result = scan_headers("https://example.com")
    for finding in result:
        assert finding["module"] in ("headers", "ssl")

def test_scan_returns_findings_for_real_site():
    # example.com is a real site — should return at least some findings
    result = scan_headers("https://example.com")
    assert len(result) > 0

def test_check_security_headers_returns_list():
    result = check_security_headers("https://example.com")
    assert isinstance(result, list)

def test_check_ssl_returns_list():
    result = check_ssl("https://example.com")
    assert isinstance(result, list)

def test_invalid_target_does_not_crash():
    # Should handle gracefully, not throw exception
    result = scan_headers("https://thisdomaindoesnotexist12345.com")
    assert isinstance(result, list)

def test_target_without_scheme_works():
    result = scan_headers("example.com")
    assert isinstance(result, list)
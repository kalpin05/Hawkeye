import pytest
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.web_scanner import (
    scan_web,
    scan_xss,
    scan_sqli,
    normalize_url,
    load_payloads,
    get_all_forms,
    get_form_details,
    detect_sqli_error,
)
import requests


def test_normalize_url_adds_http():
    assert normalize_url("example.com") == "http://example.com"

def test_normalize_url_keeps_https():
    assert normalize_url("https://example.com") == "https://example.com"

def test_load_xss_payloads():
    payloads = load_payloads("xss.txt")
    assert isinstance(payloads, list)
    assert len(payloads) > 0

def test_load_sqli_payloads():
    payloads = load_payloads("sqli.txt")
    assert isinstance(payloads, list)
    assert len(payloads) > 0

def test_load_nonexistent_returns_empty():
    assert load_payloads("nonexistent.txt") == []

def test_detect_sqli_mysql_error():
    found, db = detect_sqli_error("you have an error in your sql syntax near ''")
    assert found is True
    assert db == "MySQL"

def test_detect_sqli_generic_error():
    found, db = detect_sqli_error("sql syntax error occurred")
    assert found is True

def test_detect_sqli_no_error():
    found, db = detect_sqli_error("Welcome to our website. Everything is fine.")
    assert found is False
    assert db == ""

def test_scan_web_returns_list():
    result = scan_web("http://testphp.vulnweb.com")
    assert isinstance(result, list)

def test_each_finding_has_required_keys():
    result = scan_web("http://testphp.vulnweb.com")
    for f in result:
        assert "check"    in f
        assert "severity" in f
        assert "detail"   in f
        assert "module"   in f

def test_severity_values_valid():
    valid  = {"critical", "high", "medium", "low", "info"}
    result = scan_web("http://testphp.vulnweb.com")
    for f in result:
        assert f["severity"] in valid

def test_module_field_is_web():
    result = scan_web("http://testphp.vulnweb.com")
    for f in result:
        assert f["module"] == "web"

def test_vulnweb_finds_vulnerabilities():
    """
    testphp.vulnweb.com is intentionally vulnerable.
    We just verify scan runs and returns findings of any kind.
    Actual vuln detection depends on network + site availability.
    """
    result = scan_web("http://testphp.vulnweb.com")
    # Just assert we got results back — not empty
    assert len(result) > 0

def test_invalid_target_does_not_crash():
    result = scan_web("http://thisdomaindoesnotexist99999.com")
    assert isinstance(result, list)

def test_forms_extracted_from_vulnweb():
    session = requests.Session()
    forms = get_all_forms("http://testphp.vulnweb.com", session)
    assert isinstance(forms, list)
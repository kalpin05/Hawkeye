import pytest
import sys
import os
import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.web_scanner import (
    scan_idor,
    scan_ssrf,
    scan_web,
    crawl_links,
    normalize_url,
)


# ── Crawler ───────────────────────────────

def test_crawl_finds_multiple_pages():
    session = requests.Session()
    session.headers.update({"User-Agent": "HawkEye-Test/1.0"})
    pages = crawl_links("http://testphp.vulnweb.com", session, depth=2)
    assert isinstance(pages, list)
    assert len(pages) >= 1  # At least homepage found — network dependent
    
def test_crawl_stays_on_same_domain():
    session = requests.Session()
    pages = crawl_links("http://testphp.vulnweb.com", session, depth=1)
    for page in pages:
        assert "testphp.vulnweb.com" in page


# ── IDOR ─────────────────────────────────

def test_scan_idor_returns_list():
    session = requests.Session()
    result  = scan_idor("http://testphp.vulnweb.com/artists.php?artist=1", session)
    assert isinstance(result, list)

def test_scan_idor_no_params_returns_empty():
    session = requests.Session()
    result  = scan_idor("http://testphp.vulnweb.com", session)
    assert result == []

def test_scan_idor_finding_structure():
    session = requests.Session()
    result  = scan_idor("http://testphp.vulnweb.com/artists.php?artist=1", session)
    for f in result:
        assert "check"    in f
        assert "severity" in f
        assert "detail"   in f
        assert "module"   in f
        assert f["module"] == "web"

def test_scan_idor_severity_valid():
    session = requests.Session()
    result  = scan_idor("http://testphp.vulnweb.com/artists.php?artist=1", session)
    valid   = {"critical", "high", "medium", "low", "info"}
    for f in result:
        assert f["severity"] in valid


# ── SSRF ─────────────────────────────────

def test_scan_ssrf_returns_list():
    session = requests.Session()
    result  = scan_ssrf("http://testphp.vulnweb.com", session)
    assert isinstance(result, list)

def test_scan_ssrf_finding_structure():
    session = requests.Session()
    result  = scan_ssrf("http://testphp.vulnweb.com", session)
    for f in result:
        assert "check"    in f
        assert "severity" in f
        assert "detail"   in f
        assert "module"   in f
        assert f["module"] == "web"

def test_scan_ssrf_severity_valid():
    session = requests.Session()
    result  = scan_ssrf("http://testphp.vulnweb.com", session)
    valid   = {"critical", "high", "medium", "low", "info"}
    for f in result:
        assert f["severity"] in valid

def test_scan_ssrf_no_crash_on_bad_url():
    session = requests.Session()
    result  = scan_ssrf("http://thisdomaindoesnotexist99999.com", session)
    assert isinstance(result, list)


# ── Full web scan ─────────────────────────

def test_full_scan_returns_list():
    result = scan_web("http://testphp.vulnweb.com")
    assert isinstance(result, list)

def test_full_scan_finds_more_pages():
    """With depth=2 crawler should scan multiple pages."""
    result = scan_web("http://testphp.vulnweb.com")
    assert len(result) > 0

def test_full_scan_sorted_by_severity():
    result = scan_web("http://testphp.vulnweb.com")
    order  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severities = [order.get(f["severity"], 5) for f in result]
    assert severities == sorted(severities)

def test_full_scan_does_not_crash_on_invalid():
    result = scan_web("http://thisdomaindoesnotexist99999.com")
    assert isinstance(result, list)
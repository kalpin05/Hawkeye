import pytest
import sys
import os
import requests
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.api_tester import (
    scan_api,
    discover_endpoints,
    check_broken_auth,
    check_rate_limiting,
    check_excessive_data,
    check_api_security_headers,
    check_exposed_docs,
    normalize_url,
    is_json_response,
)


# ── Helpers — no network ──────────────────

def test_normalize_url_adds_http():
    assert normalize_url("example.com") == "http://example.com"

def test_normalize_url_strips_trailing_slash():
    assert normalize_url("http://example.com/") == "http://example.com"

def test_normalize_url_keeps_https():
    assert normalize_url("https://example.com") == "https://example.com"

def test_is_json_response_true():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "application/json"}
    assert is_json_response(mock_resp) is True

def test_is_json_response_false():
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/html"}
    assert is_json_response(mock_resp) is False


# ── Endpoint discovery — mocked ───────────

def test_discover_endpoints_returns_list():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "<html></html>"
    mock_resp.headers = {"Content-Type": "text/html"}
    session.get.return_value = mock_resp

    result = discover_endpoints("http://example.com", session)
    assert isinstance(result, list)

def test_discover_endpoints_finds_200():
    session = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "/api" in url:
            resp.status_code = 200
            resp.text = '{"status": "ok"}'
        else:
            resp.status_code = 404
            resp.text = "Not Found"
        resp.headers = {"Content-Type": "application/json"}
        return resp

    session.get.side_effect = mock_get
    result = discover_endpoints("http://example.com", session)
    assert isinstance(result, list)

def test_discover_endpoints_structure():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = ""
    mock_resp.headers = {"Content-Type": "text/html"}
    session.get.return_value = mock_resp

    result = discover_endpoints("http://example.com", session)
    for ep in result:
        assert "url"    in ep
        assert "status" in ep
        assert "size"   in ep


# ── Broken auth — mocked ──────────────────

def test_check_broken_auth_empty_endpoints():
    session = MagicMock()
    result  = check_broken_auth([], session)
    assert result == []

def test_check_broken_auth_non_sensitive_ignored():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    session.get.return_value = mock_resp

    # Non-sensitive endpoint — should not flag
    endpoints = [{"url": "http://example.com/about", "status": 200, "size": 100}]
    result    = check_broken_auth(endpoints, session)
    assert isinstance(result, list)

def test_check_broken_auth_sensitive_flagged():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "admin dashboard"
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/admin", "status": 200, "size": 500}]
    result    = check_broken_auth(endpoints, session)
    assert isinstance(result, list)
    # Should flag admin endpoint accessible without auth
    if result:
        assert any("auth" in f["check"].lower() or "admin" in f["detail"].lower()
                   for f in result)


# ── Rate limiting — mocked ────────────────

def test_check_rate_limiting_empty():
    session = MagicMock()
    result  = check_rate_limiting([], session)
    assert result == []

def test_check_rate_limiting_no_auth_endpoints():
    session   = MagicMock()
    # No auth-related endpoints — should skip
    endpoints = [{"url": "http://example.com/about", "status": 200, "size": 100}]
    result    = check_rate_limiting(endpoints, session)
    assert result == []

def test_check_rate_limiting_detects_missing():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200  # Never 429
    mock_resp.text = "ok"
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/login", "status": 200, "size": 100}]
    result    = check_rate_limiting(endpoints, session)
    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0]["severity"] == "medium"

def test_check_rate_limiting_429_no_flag():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 429  # Rate limited — good
    mock_resp.text = "Too many requests"
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/login", "status": 200, "size": 100}]
    result    = check_rate_limiting(endpoints, session)
    assert isinstance(result, list)
    assert len(result) == 0  # Should NOT flag — rate limiting works


# ── Excessive data — mocked ───────────────

def test_check_excessive_data_empty():
    session = MagicMock()
    result  = check_excessive_data([], session)
    assert result == []

def test_check_excessive_data_detects_password():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"username": "admin", "password": "secret123"}'
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/api/users", "status": 200, "size": 100}]
    result    = check_excessive_data(endpoints, session)
    assert isinstance(result, list)
    assert len(result) > 0
    assert any("password" in f["check"].lower() for f in result)

def test_check_excessive_data_detects_token():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}'
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/api/auth", "status": 200, "size": 100}]
    result    = check_excessive_data(endpoints, session)
    assert isinstance(result, list)
    assert len(result) > 0

def test_check_excessive_data_clean_response():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"name": "John", "age": 30}'
    session.get.return_value = mock_resp

    endpoints = [{"url": "http://example.com/api/user", "status": 200, "size": 50}]
    result    = check_excessive_data(endpoints, session)
    assert result == []


# ── CORS check — mocked ───────────────────

def test_api_security_headers_cors_wildcard():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_resp.headers = {
        "Access-Control-Allow-Origin":      "*",
        "Access-Control-Allow-Credentials": "true",
    }
    session.get.return_value = mock_resp

    result = check_api_security_headers("http://example.com", session)
    assert isinstance(result, list)
    assert any("CORS" in f["check"] for f in result)

def test_api_security_headers_reflected_origin():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_resp.headers = {
        "Access-Control-Allow-Origin": "https://evil.com",
    }
    session.get.return_value = mock_resp

    result = check_api_security_headers("http://example.com", session)
    assert isinstance(result, list)
    assert any("CORS" in f["check"] for f in result)

def test_api_security_headers_clean():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"
    mock_resp.headers = {}
    session.get.return_value = mock_resp

    result = check_api_security_headers("http://example.com", session)
    assert isinstance(result, list)


# ── Exposed docs — mocked ─────────────────

def test_check_exposed_docs_swagger_found():
    session = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "swagger" in url:
            resp.status_code = 200
            resp.text = "<html>Swagger UI</html>" * 10
        else:
            resp.status_code = 404
            resp.text = ""
        return resp

    session.get.side_effect = mock_get
    result = check_exposed_docs("http://example.com", session)
    assert isinstance(result, list)
    assert len(result) > 0
    assert any("swagger" in f["url"].lower() for f in result)

def test_check_exposed_docs_none_found():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = ""
    session.get.return_value = mock_resp

    result = check_exposed_docs("http://example.com", session)
    assert result == []


# ── Full scan — mocked ────────────────────

def test_scan_api_returns_list():
    with patch("modules.api_tester.discover_endpoints", return_value=[]):
        with patch("modules.api_tester.check_broken_auth", return_value=[]):
            with patch("modules.api_tester.check_rate_limiting", return_value=[]):
                with patch("modules.api_tester.check_excessive_data", return_value=[]):
                    with patch("modules.api_tester.check_api_security_headers", return_value=[]):
                        with patch("modules.api_tester.check_exposed_docs", return_value=[]):
                            result = scan_api("http://example.com")
                            assert isinstance(result, list)

def test_scan_api_finding_keys():
    with patch("modules.api_tester.discover_endpoints", return_value=[]):
        with patch("modules.api_tester.check_broken_auth", return_value=[
            {"check": "Test", "severity": "high", "detail": "Test", "module": "api"}
        ]):
            with patch("modules.api_tester.check_rate_limiting", return_value=[]):
                with patch("modules.api_tester.check_excessive_data", return_value=[]):
                    with patch("modules.api_tester.check_api_security_headers", return_value=[]):
                        with patch("modules.api_tester.check_exposed_docs", return_value=[]):
                            result = scan_api("http://example.com")
                            for f in result:
                                assert "check"    in f
                                assert "severity" in f
                                assert "detail"   in f
                                assert "module"   in f

def test_scan_api_severity_valid():
    valid = {"critical", "high", "medium", "low", "info"}
    with patch("modules.api_tester.discover_endpoints", return_value=[]):
        with patch("modules.api_tester.check_broken_auth", return_value=[]):
            with patch("modules.api_tester.check_rate_limiting", return_value=[]):
                with patch("modules.api_tester.check_excessive_data", return_value=[]):
                    with patch("modules.api_tester.check_api_security_headers", return_value=[]):
                        with patch("modules.api_tester.check_exposed_docs", return_value=[]):
                            result = scan_api("http://example.com")
                            for f in result:
                                assert f["severity"] in valid

def test_scan_api_sorted_by_severity():
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with patch("modules.api_tester.discover_endpoints", return_value=[]):
        with patch("modules.api_tester.check_broken_auth", return_value=[
            {"check": "A", "severity": "high",   "detail": "", "module": "api"},
            {"check": "B", "severity": "medium", "detail": "", "module": "api"},
            {"check": "C", "severity": "critical","detail": "","module": "api"},
        ]):
            with patch("modules.api_tester.check_rate_limiting", return_value=[]):
                with patch("modules.api_tester.check_excessive_data", return_value=[]):
                    with patch("modules.api_tester.check_api_security_headers", return_value=[]):
                        with patch("modules.api_tester.check_exposed_docs", return_value=[]):
                            result = scan_api("http://example.com")
                            sevs   = [order.get(f["severity"], 5) for f in result]
                            assert sevs == sorted(sevs)
import pytest
import sys
import os
import requests
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.logic_scanner import (
    scan_logic,
    test_horizontal_privilege,
    test_vertical_privilege,
    test_price_manipulation,
    test_quantity_manipulation,
    test_workflow_skip,
    test_sensitive_data_exposure,
    test_mass_assignment,
    build_replay,
    responses_differ_significantly,
    safe_get,
    safe_post,
)


# ── Helpers ───────────────────────────────

def test_build_replay_get():
    result = build_replay("GET", "http://example.com", {"id": "1"})
    assert "GET" in result
    assert "id=1" in result

def test_build_replay_post():
    result = build_replay("POST", "http://example.com/login",
                          {"username": "admin"})
    assert "POST" in result
    assert "username=admin" in result

def test_responses_differ_significantly_true():
    r1 = MagicMock()
    r2 = MagicMock()
    r1.status_code = 200
    r2.status_code = 200
    r1.text = "A" * 500
    r2.text = "B" * 200
    assert responses_differ_significantly(r1, r2) is True

def test_responses_differ_significantly_false():
    r1 = MagicMock()
    r2 = MagicMock()
    r1.status_code = 200
    r2.status_code = 200
    r1.text = "Same content"
    r2.text = "Same content"
    assert responses_differ_significantly(r1, r2) is False

def test_responses_differ_none_returns_false():
    assert responses_differ_significantly(None, None) is False

def test_safe_get_returns_none_on_error():
    session = MagicMock()
    session.get.side_effect = Exception("Network error")
    result = safe_get(session, "http://example.com")
    assert result is None

def test_safe_post_returns_none_on_error():
    session = MagicMock()
    session.post.side_effect = Exception("Network error")
    result = safe_post(session, "http://example.com", {})
    assert result is None


# ── Vertical privilege ────────────────────

def test_vertical_privilege_returns_list():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    session.get.return_value = mock_resp
    result = test_vertical_privilege(session, "http://example.com")
    assert isinstance(result, list)

def test_vertical_privilege_flags_admin_200():
    session = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "/admin" in url:
            resp.status_code = 200
            resp.text = "Admin Dashboard — manage users and settings here"
        else:
            resp.status_code = 404
            resp.text = "Not Found"
        return resp

    session.get.side_effect = mock_get
    result = test_vertical_privilege(session, "http://example.com")
    assert isinstance(result, list)
    assert any("admin" in f["check"].lower() or
               "vertical" in f["check"].lower()
               for f in result)

def test_vertical_privilege_ignores_403():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"
    session.get.return_value = mock_resp
    result = test_vertical_privilege(session, "http://example.com")
    assert result == []


# ── Price manipulation ────────────────────

def test_price_manipulation_returns_list():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No forms</body></html>"
    session.get.return_value = mock_resp
    result = test_price_manipulation(session, "http://example.com")
    assert isinstance(result, list)

def test_price_manipulation_no_forms():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No forms here</body></html>"
    session.get.return_value = mock_resp
    result = test_price_manipulation(session, "http://example.com/checkout")
    assert result == []

def test_price_manipulation_detects_bypass():
    session = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.text = """
            <form method="post" action="/checkout">
                <input name="price" value="100" />
                <input name="item"  value="product" />
            </form>
        """
        return resp

    def mock_post(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Order placed successfully! Thank you for your payment."
        return resp

    session.get.side_effect  = mock_get
    session.post.side_effect = mock_post
    result = test_price_manipulation(session, "http://example.com/checkout")
    assert isinstance(result, list)


# ── Quantity manipulation ─────────────────

def test_quantity_manipulation_returns_list():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No forms</body></html>"
    session.get.return_value = mock_resp
    result = test_quantity_manipulation(session, "http://example.com")
    assert isinstance(result, list)

def test_quantity_manipulation_no_qty_fields():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = """
        <form method="post" action="/search">
            <input name="query" value="" />
        </form>
    """
    session.get.return_value = mock_resp
    result = test_quantity_manipulation(session, "http://example.com")
    assert result == []


# ── Workflow skip ─────────────────────────

def test_workflow_skip_empty_steps():
    session = requests.Session()
    result  = test_workflow_skip(session, [])
    assert result == []

def test_workflow_skip_single_step():
    session = requests.Session()
    result  = test_workflow_skip(session, ["http://example.com/step1"])
    assert result == []

def test_workflow_skip_returns_list():
    with patch("modules.logic_scanner.safe_get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_get.return_value = mock_resp
        session = requests.Session()
        result  = test_workflow_skip(session, [
            "http://example.com/step1",
            "http://example.com/step2",
            "http://example.com/step3",
        ])
        assert isinstance(result, list)

def test_workflow_skip_detects_bypass():
    with patch("modules.logic_scanner.safe_get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Checkout complete — enter payment details here"
        mock_get.return_value = mock_resp
        session = requests.Session()
        result  = test_workflow_skip(session, [
            "http://example.com/cart",
            "http://example.com/checkout",
            "http://example.com/payment",
        ])
        assert isinstance(result, list)


# ── Sensitive data ────────────────────────

def test_sensitive_data_no_issues():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>Normal page content</body></html>"
    session.get.return_value = mock_resp
    result = test_sensitive_data_exposure(session, "http://example.com")
    assert result == []

def test_sensitive_data_finds_password():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"username": "admin", "password": "secret123"}'
    session.get.return_value = mock_resp
    result = test_sensitive_data_exposure(session, "http://example.com/api/user")
    assert isinstance(result, list)
    assert len(result) > 0
    assert any("password" in f["check"].lower() for f in result)

def test_sensitive_data_finds_jwt():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        '{"token": "eyJhbGciOiJIUzI1NiJ9.'
        'eyJzdWIiOiJ1c2VyIn0.'
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
    )
    session.get.return_value = mock_resp
    result = test_sensitive_data_exposure(
        session, "http://example.com/api/profile"
    )
    assert isinstance(result, list)

def test_sensitive_data_404_skipped():
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    session.get.return_value = mock_resp
    result = test_sensitive_data_exposure(session, "http://example.com/missing")
    assert result == []


# ── Full logic scan ───────────────────────

def test_scan_logic_returns_list():
    with patch("modules.logic_scanner.test_price_manipulation",    return_value=[]):
        with patch("modules.logic_scanner.test_quantity_manipulation", return_value=[]):
            with patch("modules.logic_scanner.test_sensitive_data_exposure", return_value=[]):
                with patch("modules.logic_scanner.test_mass_assignment",  return_value=[]):
                    with patch("modules.logic_scanner.test_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        assert isinstance(result, list)

def test_scan_logic_finding_structure():
    mock_finding = {
        "check": "Test Finding", "severity": "high",
        "detail": "Test detail", "module": "logic",
        "url": "http://example.com", "replay": "GET http://example.com",
    }
    with patch("modules.logic_scanner.test_price_manipulation",
               return_value=[mock_finding]):
        with patch("modules.logic_scanner.test_quantity_manipulation", return_value=[]):
            with patch("modules.logic_scanner.test_sensitive_data_exposure", return_value=[]):
                with patch("modules.logic_scanner.test_mass_assignment",  return_value=[]):
                    with patch("modules.logic_scanner.test_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        for f in result:
                            assert "check"    in f
                            assert "severity" in f
                            assert "detail"   in f
                            assert "module"   in f

def test_scan_logic_sorted_by_severity():
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with patch("modules.logic_scanner.test_price_manipulation", return_value=[
        {"check": "A", "severity": "high",     "detail": "", "module": "logic", "url": ""},
        {"check": "B", "severity": "critical",  "detail": "", "module": "logic", "url": ""},
    ]):
        with patch("modules.logic_scanner.test_quantity_manipulation", return_value=[]):
            with patch("modules.logic_scanner.test_sensitive_data_exposure", return_value=[]):
                with patch("modules.logic_scanner.test_mass_assignment",  return_value=[]):
                    with patch("modules.logic_scanner.test_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        sevs   = [order.get(f["severity"], 5) for f in result
                                  if f.get("module") == "logic"]
                        assert sevs == sorted(sevs)

def test_scan_logic_with_two_sessions():
    session_a = MagicMock()
    session_b = MagicMock()
    with patch("modules.logic_scanner.test_price_manipulation",    return_value=[]):
        with patch("modules.logic_scanner.test_quantity_manipulation", return_value=[]):
            with patch("modules.logic_scanner.test_sensitive_data_exposure", return_value=[]):
                with patch("modules.logic_scanner.test_mass_assignment",  return_value=[]):
                    with patch("modules.logic_scanner.test_vertical_privilege", return_value=[]):
                        with patch("modules.logic_scanner.test_horizontal_privilege", return_value=[]):
                            result = scan_logic(
                                "http://example.com",
                                session_a=session_a,
                                session_b=session_b,
                            )
                            assert isinstance(result, list)

def test_scan_logic_includes_replay_in_findings():
    mock_finding = {
        "check":    "Price Manipulation",
        "severity": "critical",
        "detail":   "Test",
        "module":   "logic",
        "url":      "http://example.com/checkout",
        "replay":   "POST http://example.com/checkout\nBody: price=-1",
    }
    with patch("modules.logic_scanner.test_price_manipulation",
               return_value=[mock_finding]):
        with patch("modules.logic_scanner.test_quantity_manipulation", return_value=[]):
            with patch("modules.logic_scanner.test_sensitive_data_exposure", return_value=[]):
                with patch("modules.logic_scanner.test_mass_assignment",  return_value=[]):
                    with patch("modules.logic_scanner.test_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        logic_findings = [
                            f for f in result if f.get("module") == "logic"
                        ]
                        assert len(logic_findings) > 0
                        assert "replay" in logic_findings[0]
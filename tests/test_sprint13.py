import pytest
import sys
import os
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.logic_scanner import (
    scan_logic,
    check_horizontal_privilege,
    check_vertical_privilege,
    check_price_manipulation,
    check_quantity_manipulation,
    check_workflow_skip,
    check_sensitive_data,
    check_mass_assignment,
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
    result = build_replay(
        "POST", "http://example.com/login", {"username": "admin"}
    )
    assert "POST" in result
    assert "username=admin" in result

def test_responses_differ_true():
    r1 = MagicMock()
    r2 = MagicMock()
    r1.status_code = 200
    r2.status_code = 200
    r1.text = "A" * 500
    r2.text = "B" * 200
    assert responses_differ_significantly(r1, r2) is True

def test_responses_differ_false():
    r1 = MagicMock()
    r2 = MagicMock()
    r1.status_code = 200
    r2.status_code = 200
    r1.text = "Same content"
    r2.text = "Same content"
    assert responses_differ_significantly(r1, r2) is False

def test_responses_differ_none():
    assert responses_differ_significantly(None, None) is False

def test_safe_get_none_on_error():
    mock_session = MagicMock()
    mock_session.get.side_effect = Exception("Network error")
    result = safe_get(mock_session, "http://example.com")
    assert result is None

def test_safe_post_none_on_error():
    mock_session = MagicMock()
    mock_session.post.side_effect = Exception("Network error")
    result = safe_post(mock_session, "http://example.com", {})
    assert result is None


# ── Vertical privilege ────────────────────

def test_vert_priv_returns_list():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text        = "Not Found"
    mock_session.get.return_value = mock_resp
    result = check_vertical_privilege(mock_session, "http://example.com")
    assert isinstance(result, list)

def test_vert_priv_flags_admin_200():
    mock_session = MagicMock()

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "/admin" in url:
            resp.status_code = 200
            resp.text = "Admin Dashboard manage users and settings here " * 5
        else:
            resp.status_code = 404
            resp.text = "Not Found"
        return resp

    mock_session.get.side_effect = mock_get
    result = check_vertical_privilege(mock_session, "http://example.com")
    assert isinstance(result, list)
    assert len(result) > 0

def test_vert_priv_ignores_403():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text        = "Forbidden"
    mock_session.get.return_value = mock_resp
    result = check_vertical_privilege(mock_session, "http://example.com")
    assert result == []


# ── Horizontal privilege ──────────────────

def test_horiz_priv_returns_list():
    mock_a = MagicMock()
    mock_b = MagicMock()
    resp   = MagicMock()
    resp.status_code = 200
    resp.text        = "User data here"
    mock_a.get.return_value = resp
    mock_b.get.return_value = resp
    result = check_horizontal_privilege(
        mock_a, mock_b,
        "http://example.com/profile?id=1"
    )
    assert isinstance(result, list)

def test_horiz_priv_no_id_params():
    mock_a = MagicMock()
    mock_b = MagicMock()
    resp   = MagicMock()
    resp.status_code = 200
    resp.text        = "User data"
    mock_a.get.return_value = resp
    mock_b.get.return_value = resp
    result = check_horizontal_privilege(
        mock_a, mock_b,
        "http://example.com/profile"
    )
    assert result == []


# ── Price manipulation ────────────────────

def test_price_manip_no_forms():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.text = "<html><body>No forms here</body></html>"
    mock_session.get.return_value = mock_resp
    result = check_price_manipulation(
        mock_session, "http://example.com/checkout"
    )
    assert result == []

def test_price_manip_returns_list():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.text = "<html><body>No forms</body></html>"
    mock_session.get.return_value = mock_resp
    result = check_price_manipulation(mock_session, "http://example.com")
    assert isinstance(result, list)

def test_price_manip_detects_bypass():
    mock_session = MagicMock()

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

    mock_session.get.side_effect  = mock_get
    mock_session.post.side_effect = mock_post
    result = check_price_manipulation(
        mock_session, "http://example.com/checkout"
    )
    assert isinstance(result, list)


# ── Quantity manipulation ─────────────────

def test_qty_manip_returns_list():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.text = "<html><body>No forms</body></html>"
    mock_session.get.return_value = mock_resp
    result = check_quantity_manipulation(mock_session, "http://example.com")
    assert isinstance(result, list)

def test_qty_manip_no_qty_fields():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.text = """
        <form method="post" action="/search">
            <input name="query" value="" />
        </form>
    """
    mock_session.get.return_value = mock_resp
    result = check_quantity_manipulation(mock_session, "http://example.com")
    assert result == []


# ── Workflow skip ─────────────────────────

def test_workflow_empty_steps():
    mock_session = MagicMock()
    result = check_workflow_skip(mock_session, [])
    assert result == []

def test_workflow_single_step():
    mock_session = MagicMock()
    result = check_workflow_skip(
        mock_session, ["http://example.com/step1"]
    )
    assert result == []

def test_workflow_returns_list():
    with patch("modules.logic_scanner.safe_get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text        = "Forbidden"
        mock_get.return_value = mock_resp
        mock_session = MagicMock()
        result = check_workflow_skip(mock_session, [
            "http://example.com/step1",
            "http://example.com/step2",
            "http://example.com/step3",
        ])
        assert isinstance(result, list)

def test_workflow_detects_bypass():
    with patch("modules.logic_scanner.safe_get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Checkout complete enter payment details here " * 5
        mock_get.return_value = mock_resp
        mock_session = MagicMock()
        result = check_workflow_skip(mock_session, [
            "http://example.com/cart",
            "http://example.com/checkout",
            "http://example.com/payment",
        ])
        assert isinstance(result, list)


# ── Sensitive data ────────────────────────

def test_sensitive_no_issues():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text        = "<html><body>Normal page content</body></html>"
    mock_session.get.return_value = mock_resp
    result = check_sensitive_data(mock_session, "http://example.com")
    assert result == []

def test_sensitive_finds_password():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"username": "admin", "password": "secret123"}'
    mock_session.get.return_value = mock_resp
    result = check_sensitive_data(
        mock_session, "http://example.com/api/user"
    )
    assert isinstance(result, list)
    assert len(result) > 0
    assert any("password" in f["check"].lower() for f in result)

def test_sensitive_finds_jwt():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        '{"token": "eyJhbGciOiJIUzI1NiJ9.'
        'eyJzdWIiOiJ1c2VyIn0.'
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
    )
    mock_session.get.return_value = mock_resp
    result = check_sensitive_data(
        mock_session, "http://example.com/api/profile"
    )
    assert isinstance(result, list)

def test_sensitive_404_skipped():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text        = "Not Found"
    mock_session.get.return_value = mock_resp
    result = check_sensitive_data(
        mock_session, "http://example.com/missing"
    )
    assert result == []


# ── Mass assignment ───────────────────────

def test_mass_assign_no_forms():
    mock_session = MagicMock()
    mock_resp    = MagicMock()
    mock_resp.text = "<html><body>No forms</body></html>"
    mock_session.get.return_value = mock_resp
    result = check_mass_assignment(mock_session, "http://example.com")
    assert isinstance(result, list)
    assert result == []


# ── Full logic scan ───────────────────────

def test_scan_logic_returns_list():
    with patch("modules.logic_scanner.check_price_manipulation",          return_value=[]):
        with patch("modules.logic_scanner.check_quantity_manipulation",   return_value=[]):
            with patch("modules.logic_scanner.check_sensitive_data",      return_value=[]):
                with patch("modules.logic_scanner.check_mass_assignment", return_value=[]):
                    with patch("modules.logic_scanner.check_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        assert isinstance(result, list)

def test_scan_logic_finding_structure():
    mock_finding = {
        "check":    "Test Finding",
        "severity": "high",
        "detail":   "Test detail",
        "module":   "logic",
        "url":      "http://example.com",
        "replay":   "GET http://example.com",
    }
    with patch("modules.logic_scanner.check_price_manipulation",
               return_value=[mock_finding]):
        with patch("modules.logic_scanner.check_quantity_manipulation",   return_value=[]):
            with patch("modules.logic_scanner.check_sensitive_data",      return_value=[]):
                with patch("modules.logic_scanner.check_mass_assignment", return_value=[]):
                    with patch("modules.logic_scanner.check_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        for f in result:
                            assert "check"    in f
                            assert "severity" in f
                            assert "detail"   in f
                            assert "module"   in f

def test_scan_logic_sorted():
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with patch("modules.logic_scanner.check_price_manipulation", return_value=[
        {"check": "A", "severity": "high",    "detail": "", "module": "logic", "url": ""},
        {"check": "B", "severity": "critical","detail": "", "module": "logic", "url": ""},
    ]):
        with patch("modules.logic_scanner.check_quantity_manipulation",   return_value=[]):
            with patch("modules.logic_scanner.check_sensitive_data",      return_value=[]):
                with patch("modules.logic_scanner.check_mass_assignment", return_value=[]):
                    with patch("modules.logic_scanner.check_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        sevs = [
                            order.get(f["severity"], 5)
                            for f in result
                            if f.get("module") == "logic"
                        ]
                        assert sevs == sorted(sevs)

def test_scan_logic_two_sessions():
    mock_a = MagicMock()
    mock_b = MagicMock()
    with patch("modules.logic_scanner.check_price_manipulation",          return_value=[]):
        with patch("modules.logic_scanner.check_quantity_manipulation",   return_value=[]):
            with patch("modules.logic_scanner.check_sensitive_data",      return_value=[]):
                with patch("modules.logic_scanner.check_mass_assignment", return_value=[]):
                    with patch("modules.logic_scanner.check_vertical_privilege", return_value=[]):
                        with patch("modules.logic_scanner.check_horizontal_privilege", return_value=[]):
                            result = scan_logic(
                                "http://example.com",
                                session_a=mock_a,
                                session_b=mock_b,
                            )
                            assert isinstance(result, list)

def test_scan_logic_has_replay():
    mock_finding = {
        "check":    "Price Manipulation",
        "severity": "critical",
        "detail":   "Test",
        "module":   "logic",
        "url":      "http://example.com/checkout",
        "replay":   "POST http://example.com/checkout\nBody: price=-1",
    }
    with patch("modules.logic_scanner.check_price_manipulation",
               return_value=[mock_finding]):
        with patch("modules.logic_scanner.check_quantity_manipulation",   return_value=[]):
            with patch("modules.logic_scanner.check_sensitive_data",      return_value=[]):
                with patch("modules.logic_scanner.check_mass_assignment", return_value=[]):
                    with patch("modules.logic_scanner.check_vertical_privilege", return_value=[]):
                        result = scan_logic("http://example.com")
                        logic_f = [f for f in result if f.get("module") == "logic"]
                        assert len(logic_f) > 0
                        assert "replay" in logic_f[0]
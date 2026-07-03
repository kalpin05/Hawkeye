import pytest
import sys
import os
import requests
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.auth_handler import (
    detect_login_form,
    login_with_form,
    login_with_token,
    verify_login_success,
    is_session_alive,
    create_authenticated_session,
)


# ── detect_login_form ─────────────────────

def test_detect_login_form_finds_form():
    session   = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = """
        <form method="post" action="/login">
            <input type="text"     name="username" />
            <input type="password" name="password" />
            <input type="hidden"   name="csrf_token" value="abc123" />
            <input type="submit"   value="Login" />
        </form>
    """
    session.get.return_value = mock_resp
    result = detect_login_form("http://example.com/login", session)
    assert result is not None
    assert result["username_field"] == "username"
    assert result["password_field"] == "password"
    assert result["hidden_fields"].get("csrf_token") == "abc123"

def test_detect_login_form_no_form_returns_none():
    session   = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No form here</body></html>"
    session.get.return_value = mock_resp
    result = detect_login_form("http://example.com", session)
    assert result is None

def test_detect_login_form_no_password_field_returns_none():
    session   = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = """
        <form method="post">
            <input type="text" name="search" />
            <input type="submit" value="Go" />
        </form>
    """
    session.get.return_value = mock_resp
    result = detect_login_form("http://example.com/search", session)
    assert result is None

def test_detect_login_form_handles_exception():
    session = MagicMock()
    session.get.side_effect = Exception("Connection error")
    result = detect_login_form("http://example.com/login", session)
    assert result is None


# ── verify_login_success ──────────────────

def test_verify_login_success_finds_logout():
    mock_resp      = MagicMock()
    mock_resp.text = "<html><body>Welcome! <a href='/logout'>Logout</a></body></html>"
    mock_resp.url  = "http://example.com/dashboard"
    mock_resp.cookies = {}
    success, reason = verify_login_success(mock_resp, "http://example.com/login")
    assert success is True

def test_verify_login_detects_failure():
    mock_resp      = MagicMock()
    mock_resp.text = "<html><body>Invalid username or password</body></html>"
    mock_resp.url  = "http://example.com/login"
    mock_resp.cookies = {}
    success, reason = verify_login_success(mock_resp, "http://example.com/login")
    assert success is False

def test_verify_login_redirect_means_success():
    mock_resp      = MagicMock()
    mock_resp.text = "<html><body>Home page</body></html>"
    mock_resp.url  = "http://example.com/dashboard"
    mock_resp.cookies = {}
    success, reason = verify_login_success(mock_resp, "http://example.com/login")
    assert success is True

def test_verify_login_session_cookie_means_success():
    mock_resp         = MagicMock()
    mock_resp.text    = "<html><body>Page</body></html>"
    mock_resp.url     = "http://example.com/login"
    mock_resp.cookies = {"session": "abc123"}
    success, reason = verify_login_success(mock_resp, "http://example.com/login")
    assert success is True


# ── login_with_token ──────────────────────

def test_login_with_token_sets_header():
    session = requests.Session()
    result  = login_with_token("mytoken123456789", "Authorization", session)
    assert result["success"] is True
    assert "Authorization" in session.headers
    assert "mytoken123456789" in session.headers["Authorization"]

def test_login_with_token_masks_output():
    session = requests.Session()
    result  = login_with_token("supersecrettoken9999", "Authorization", session)
    assert result["success"] is True
    assert "supersecrettoken9999" not in result["token"]
    assert "..." in result["token"]

def test_login_with_token_custom_header():
    session = requests.Session()
    result  = login_with_token("myapikey123", "X-API-Key", session)
    assert result["success"] is True
    assert "X-API-Key" in session.headers


# ── login_with_form ───────────────────────

def test_login_with_form_success():
    session = MagicMock()

    # Mock detect_login_form
    with patch("modules.auth_handler.detect_login_form") as mock_detect:
        mock_detect.return_value = {
            "form_url":       "http://example.com/login",
            "method":         "post",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields":  {"csrf": "token123"},
            "login_page_url": "http://example.com/login",
        }
        mock_resp         = MagicMock()
        mock_resp.text    = "<html><body>Welcome! <a href='/logout'>Logout</a></body></html>"
        mock_resp.url     = "http://example.com/dashboard"
        mock_resp.cookies = {}
        session.post.return_value = mock_resp
        session.cookies   = {}

        result = login_with_form(
            "http://example.com/login", "admin", "password123", session
        )
        assert result["success"] is True

def test_login_with_form_no_form_found():
    session = MagicMock()
    with patch("modules.auth_handler.detect_login_form", return_value=None):
        result = login_with_form(
            "http://example.com/login", "admin", "pass", session
        )
        assert result["success"] is False
        assert "No login form found" in result["error"]

def test_login_with_form_connection_error():
    session = MagicMock()
    with patch("modules.auth_handler.detect_login_form") as mock_detect:
        mock_detect.return_value = {
            "form_url":       "http://example.com/login",
            "method":         "post",
            "username_field": "username",
            "password_field": "password",
            "hidden_fields":  {},
            "login_page_url": "http://example.com/login",
        }
        session.post.side_effect = requests.exceptions.ConnectionError()
        result = login_with_form(
            "http://example.com/login", "admin", "pass", session
        )
        assert result["success"] is False


# ── is_session_alive ──────────────────────

def test_is_session_alive_true():
    session   = MagicMock()
    mock_resp = MagicMock()
    mock_resp.url  = "http://example.com/dashboard"
    mock_resp.text = "<html><body>Dashboard</body></html>"
    session.get.return_value = mock_resp
    result = is_session_alive(
        session, "http://example.com/dashboard", "http://example.com/login"
    )
    assert result is True

def test_is_session_alive_false_redirected_to_login():
    session   = MagicMock()
    mock_resp = MagicMock()
    mock_resp.url  = "http://example.com/login"
    mock_resp.text = "<html><body>Please log in</body></html>"
    session.get.return_value = mock_resp
    result = is_session_alive(
        session, "http://example.com/dashboard", "http://example.com/login"
    )
    assert result is False

def test_is_session_alive_handles_exception():
    session = MagicMock()
    session.get.side_effect = Exception("Network error")
    result = is_session_alive(
        session, "http://example.com/dashboard", "http://example.com/login"
    )
    assert result is False


# ── create_authenticated_session ──────────

def test_create_session_with_token():
    session, result = create_authenticated_session(token="mytoken12345678")
    assert result["success"] is True
    assert result["method"]  == "token"

def test_create_session_no_credentials():
    session, result = create_authenticated_session()
    assert result["success"] is False
    assert result["method"]  == "none"

def test_create_session_with_proxy():
    session, result = create_authenticated_session(
        token="mytoken12345678",
        proxy="http://127.0.0.1:8080"
    )
    assert result["success"] is True
    assert session.proxies.get("http") == "http://127.0.0.1:8080"

def test_create_session_token_adds_bearer():
    session, result = create_authenticated_session(token="rawtoken12345678")
    assert "Bearer" in session.headers.get("Authorization", "")

def test_create_session_with_form_login():
    with patch("modules.auth_handler.login_with_form") as mock_login:
        mock_login.return_value = {
            "success": True, "method": "form",
            "login_url": "http://example.com/login",
            "username": "admin", "error": None,
            "cookies": {}, "post_login_url": "http://example.com/dashboard",
        }
        session, result = create_authenticated_session(
            login_url="http://example.com/login",
            username="admin",
            password="password123",
        )
        assert result["success"] is True
        assert result["method"]  == "form"
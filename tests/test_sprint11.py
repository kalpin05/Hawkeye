import pytest
import sys
import os
from unittest.mock import patch, MagicMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.subdomain_enum import (
    enum_crtsh,
    enum_otx,
    enum_hackertarget,
    enum_bruteforce,
    check_dns,
    check_alive,
    extract_title,
    filter_alive,
    discover_subdomains,
    load_subdomain_wordlist,
)


def test_load_subdomain_wordlist_returns_list():
    words = load_subdomain_wordlist()
    assert isinstance(words, list)
    assert len(words) > 0

def test_extract_title_finds_title():
    html = "<html><head><title>Test Page</title></head></html>"
    assert extract_title(html) == "Test Page"

def test_extract_title_no_title_returns_empty():
    html = "<html><head></head></html>"
    assert extract_title(html) == ""

def test_extract_title_truncates_long_title():
    html = f"<title>{'A' * 200}</title>"
    result = extract_title(html)
    assert len(result) <= 80

def test_check_dns_resolves_known_domain():
    result = check_dns("google.com")
    assert result == "google.com"

def test_check_dns_fails_on_invalid():
    result = check_dns("thisdoesnotexist999999.invalid")
    assert result is None

def test_enum_crtsh_returns_set():
    with patch("modules.subdomain_enum.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com\napi.example.com"}
        ]
        mock_get.return_value = mock_resp
        result = enum_crtsh("example.com")
        assert isinstance(result, set)
        assert "www.example.com" in result
        assert "api.example.com" in result

def test_enum_crtsh_handles_failure():
    with patch("modules.subdomain_enum.requests.get", side_effect=Exception("timeout")):
        result = enum_crtsh("example.com")
        assert result == set()

def test_enum_otx_returns_set():
    with patch("modules.subdomain_enum.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "passive_dns": [{"hostname": "mail.example.com"}]
        }
        mock_get.return_value = mock_resp
        result = enum_otx("example.com")
        assert "mail.example.com" in result

def test_enum_hackertarget_returns_set():
    with patch("modules.subdomain_enum.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "blog.example.com,1.2.3.4\nshop.example.com,1.2.3.5"
        mock_get.return_value = mock_resp
        result = enum_hackertarget("example.com")
        assert "blog.example.com" in result
        assert "shop.example.com" in result

def test_enum_hackertarget_handles_error_response():
    with patch("modules.subdomain_enum.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "error check your search parameter"
        mock_get.return_value = mock_resp
        result = enum_hackertarget("example.com")
        assert result == set()

def test_enum_bruteforce_with_small_wordlist():
    result = enum_bruteforce("google.com", wordlist=["www", "thisdoesnotexist99999"])
    assert isinstance(result, set)
    # www.google.com should resolve
    assert "www.google.com" in result

def test_check_alive_returns_dict_or_none():
    result = check_alive("google.com")
    assert result is None or isinstance(result, dict)

def test_check_alive_dead_host_returns_none():
    result = check_alive("thisdoesnotexist999999.invalid")
    assert result is None

def test_filter_alive_returns_list():
    result = filter_alive({"google.com"})
    assert isinstance(result, list)

def test_discover_subdomains_returns_dict_structure():
    with patch("modules.subdomain_enum.enum_crtsh", return_value=set()):
        with patch("modules.subdomain_enum.enum_otx", return_value=set()):
            with patch("modules.subdomain_enum.enum_hackertarget", return_value=set()):
                with patch("modules.subdomain_enum.enum_bruteforce", return_value=set()):
                    with patch("modules.subdomain_enum.filter_alive", return_value=[]):
                        result = discover_subdomains("example.com")
                        assert "domain"           in result
                        assert "total_discovered" in result
                        assert "total_alive"      in result
                        assert "sources"          in result
                        assert "all_subdomains"   in result
                        assert "alive_subdomains" in result

def test_discover_subdomains_strips_scheme():
    with patch("modules.subdomain_enum.enum_crtsh", return_value=set()):
        with patch("modules.subdomain_enum.enum_otx", return_value=set()):
            with patch("modules.subdomain_enum.enum_hackertarget", return_value=set()):
                with patch("modules.subdomain_enum.enum_bruteforce", return_value=set()):
                    with patch("modules.subdomain_enum.filter_alive", return_value=[]):
                        result = discover_subdomains("https://www.example.com/path")
                        assert result["domain"] == "example.com"

def test_discover_subdomains_passive_only():
    with patch("modules.subdomain_enum.enum_crtsh", return_value={"a.example.com"}) as m1:
        with patch("modules.subdomain_enum.enum_otx", return_value=set()):
            with patch("modules.subdomain_enum.enum_hackertarget", return_value=set()):
                with patch("modules.subdomain_enum.enum_bruteforce", return_value=set()) as m2:
                    with patch("modules.subdomain_enum.filter_alive", return_value=[]):
                        discover_subdomains("example.com", active=False, passive=True)
                        m1.assert_called_once()
                        m2.assert_not_called()

def test_discover_subdomains_active_only():
    with patch("modules.subdomain_enum.enum_crtsh", return_value=set()) as m1:
        with patch("modules.subdomain_enum.enum_otx", return_value=set()):
            with patch("modules.subdomain_enum.enum_hackertarget", return_value=set()):
                with patch("modules.subdomain_enum.enum_bruteforce", return_value=set()) as m2:
                    with patch("modules.subdomain_enum.filter_alive", return_value=[]):
                        discover_subdomains("example.com", active=True, passive=False)
                        m1.assert_not_called()
                        m2.assert_called_once()

def test_discover_subdomains_always_includes_root():
    with patch("modules.subdomain_enum.enum_crtsh", return_value=set()):
        with patch("modules.subdomain_enum.enum_otx", return_value=set()):
            with patch("modules.subdomain_enum.enum_hackertarget", return_value=set()):
                with patch("modules.subdomain_enum.enum_bruteforce", return_value=set()):
                    with patch("modules.subdomain_enum.filter_alive", return_value=[]):
                        result = discover_subdomains("example.com")
                        assert "example.com" in result["all_subdomains"]
                        assert "www.example.com" in result["all_subdomains"]
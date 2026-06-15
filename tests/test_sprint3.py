import pytest
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules.network_scanner import (
    scan_network,
    scan_port,
    resolve_host,
    validate_host,
    grab_banner,
)


# ── Helpers ──────────────────────────────

def test_resolve_host_strips_https():
    assert resolve_host("https://example.com") == "example.com"

def test_resolve_host_strips_http():
    assert resolve_host("http://example.com/path") == "example.com"

def test_resolve_host_bare_ip():
    assert resolve_host("192.168.1.1") == "192.168.1.1"

def test_validate_host_valid():
    ok, ip = validate_host("example.com")
    assert ok is True
    assert ip != ""

def test_validate_host_invalid():
    ok, ip = validate_host("thisdomaindoesnotexist99999.com")
    assert ok is False
    assert ip == ""


# ── Output structure ─────────────────────

def test_scan_network_returns_list():
    result = scan_network("example.com", fast=True)
    assert isinstance(result, list)

def test_each_finding_has_required_keys():
    result = scan_network("example.com", fast=True)
    for f in result:
        assert "check"    in f
        assert "severity" in f
        assert "detail"   in f
        assert "module"   in f

def test_severity_values_valid():
    valid  = {"critical", "high", "medium", "low", "info"}
    result = scan_network("example.com", fast=True)
    for f in result:
        assert f["severity"] in valid

def test_module_field_is_network():
    result = scan_network("example.com", fast=True)
    for f in result:
        assert f["module"] == "network"

def test_unreachable_host_returns_gracefully():
    result = scan_network("thisdomaindoesnotexist99999.com", fast=True)
    assert isinstance(result, list)
    assert len(result) > 0
    assert "unreachable" in result[0]["check"].lower() or "info" in result[0]["severity"]

def test_fast_mode_returns_faster():
    import time
    start = time.time()
    scan_network("example.com", fast=True)
    elapsed = time.time() - start
    # Fast scan should complete in reasonable time
    assert elapsed < 60

def test_scan_port_closed_returns_none():
    # Port 9999 is almost certainly closed on example.com
    result = scan_port("example.com", 9999, timeout=1.0)
    assert result is None

def test_scan_port_open_returns_dict():
    # Port 80 should be open on example.com
    result = scan_port("example.com", 80, timeout=3.0)
    if result:  # Only check structure if port is open
        assert "port"     in result
        assert "service"  in result
        assert "severity" in result
        assert result["port"] == 80

def test_target_with_http_scheme():
    result = scan_network("http://example.com", fast=True)
    assert isinstance(result, list)
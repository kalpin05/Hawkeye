import pytest
from click.testing import CliRunner
import sys
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from cli.main import hawkeye   # <-- hawkeye NOT hawkeyes

runner = CliRunner()

def test_hawkeye_help():
    result = runner.invoke(hawkeye, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output

def test_scan_help():
    result = runner.invoke(hawkeye, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output

def test_scan_no_module_fails():
    result = runner.invoke(hawkeye, ["scan", "--target", "https://example.com"])
    assert result.exit_code != 0 or "Select at least one module" in result.output

def test_scan_all_flag_runs():
    result = runner.invoke(hawkeye, ["scan", "--target", "https://example.com", "--all"])
    assert result.exit_code == 0

def test_scan_headers_flag():
    result = runner.invoke(hawkeye, ["scan", "--target", "https://example.com", "--headers"])
    assert result.exit_code == 0

def test_scan_network_flag():
    result = runner.invoke(hawkeye, ["scan", "--target", "192.168.1.1", "--network"])
    assert result.exit_code == 0

def test_scan_web_flag():
    result = runner.invoke(hawkeye, ["scan", "--target", "https://example.com", "--web"])
    assert result.exit_code == 0

def test_scan_api_flag():
    result = runner.invoke(hawkeye, ["scan", "--target", "https://api.example.com", "--api"])
    assert result.exit_code == 0

def test_dashboard_command():
    result = runner.invoke(hawkeye, ["dashboard", "--port", "9090"])
    assert result.exit_code == 0

def test_version():
    result = runner.invoke(hawkeye, ["--version"])
    assert "1.0.0" in result.output
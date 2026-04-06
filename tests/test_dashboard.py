"""Tests for QUALITY.md dashboard generation."""
import sys
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import scan_project, ScanResult, Finding, CRITICAL, HIGH
from security_scanner.dashboard import generate_dashboard, write_dashboard


def test_dashboard_pass():
    result = ScanResult(scanned=10)
    md = generate_dashboard(result)
    assert "# Quality Dashboard" in md
    assert "PASS" in md
    assert "findings-0" in md


def test_dashboard_fail():
    result = ScanResult(
        findings=[Finding(rule_id="SEC-001", severity=CRITICAL, file="test.js", line=1, message="Key found")],
        scanned=5,
    )
    md = generate_dashboard(result)
    assert "FAIL" in md
    assert "SEC-001" in md


def test_dashboard_with_domains():
    result = ScanResult(
        scanned=10,
        domain_results={
            "security": {"tool": "builtin", "version": "0.3.0", "time": 0.5, "findings": 2, "passed": False},
            "lint": {"tool": "ruff", "version": "", "time": 1.2, "findings": 5, "passed": True},
        },
    )
    md = generate_dashboard(result)
    assert "Domain Summary" in md
    assert "security" in md
    assert "lint" in md


def test_dashboard_project_name():
    result = ScanResult(scanned=1)
    md = generate_dashboard(result, project_name="my-app")
    assert "my-app" in md


def test_write_dashboard():
    with tempfile.TemporaryDirectory() as td:
        result = ScanResult(scanned=1)
        path = write_dashboard(Path(td), result)
        assert path.is_file()
        assert path.name == "QUALITY.md"
        content = path.read_text()
        assert "# Quality Dashboard" in content


def test_dashboard_truncates_findings():
    findings = [
        Finding(rule_id=f"SEC-{i:03d}", severity=HIGH, file=f"file{i}.js", line=i, message=f"Issue {i}")
        for i in range(30)
    ]
    result = ScanResult(findings=findings, scanned=30)
    md = generate_dashboard(result)
    assert "and 10 more" in md

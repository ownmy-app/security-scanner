"""Tests for scan modes (full, incremental, PR) and scan_project_v2."""
import sys
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import scan_project, scan_project_v2, ScanResult
from security_scanner.config import ScanConfig


def make_project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".gitignore").write_text(".env\nnode_modules/\n")
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return tmp


def test_v2_default_matches_v1():
    """scan_project_v2 with default config should find the same issues as scan_project."""
    project = make_project({
        "src/config.ts": "const key = 'sk-aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll';",
    })
    v1 = scan_project(project)
    v2 = scan_project_v2(project)
    assert len(v2.findings) == len(v1.findings)
    assert v2.domain_results.get("security") is not None


def test_v2_specific_domain():
    project = make_project({"src/app.js": "eval(x);"})
    config = ScanConfig(domains=["security"])
    result = scan_project_v2(project, config)
    assert "security" in result.domain_results
    assert len(result.findings) > 0


def test_v2_unknown_domain_strict():
    project = make_project({"src/app.js": "const x = 1;"})
    config = ScanConfig(domains=["nonexistent"], strict=True)
    result = scan_project_v2(project, config)
    assert any("DOMAIN-UNKNOWN" in f.rule_id for f in result.findings)


def test_v2_missing_tool_strict():
    project = make_project({"src/app.js": "const x = 1;"})
    config = ScanConfig(domains=["sast"], strict=True)
    result = scan_project_v2(project, config)
    # SAST (opengrep) is likely not installed, so strict mode should flag it
    tool_missing = [f for f in result.findings if "TOOL-MISSING" in f.rule_id]
    assert len(tool_missing) > 0


def test_v2_domain_results_populated():
    project = make_project({"src/app.js": "const x = 1;"})
    config = ScanConfig(domains=["security"])
    result = scan_project_v2(project, config)
    dr = result.domain_results.get("security")
    assert dr is not None
    assert "tool" in dr
    assert "time" in dr
    assert dr["tool"] == "builtin"


def test_v2_full_mode():
    project = make_project({"src/app.js": "eval(input);"})
    config = ScanConfig(scan_mode="full")
    result = scan_project_v2(project, config)
    assert result.scanned >= 1


def test_finding_extended_fields():
    """New Finding fields have backward-compatible defaults."""
    from security_scanner.scanner import Finding
    f = Finding(rule_id="SEC-001", severity="CRITICAL", file="test.js", line=1, message="test")
    assert f.domain == "security"
    assert f.tool == "builtin"
    assert f.category == ""
    assert f.url == ""


def test_scan_result_domain_results_field():
    r = ScanResult()
    assert r.domain_results == {}
    r.domain_results["test"] = {"findings": 0}
    assert r.domain_results["test"]["findings"] == 0

"""Tests for the BuiltinSecurityDomain wrapper."""
import sys
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import scan_project, CRITICAL, HIGH
from security_scanner.domains.builtin import BuiltinSecurityDomain


def make_project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".gitignore").write_text(".env\nnode_modules/\n")
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return tmp


def test_builtin_domain_matches_scan_project():
    """BuiltinSecurityDomain must produce the same findings as scan_project."""
    project = make_project({
        "src/config.ts": "const key = 'sk-aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll';",
        "src/utils.js": "const result = eval(userInput);",
    })

    # Original scan
    original = scan_project(project)

    # Domain scan
    domain = BuiltinSecurityDomain()
    dr = domain.run(project)

    assert len(dr.findings) == len(original.findings)
    for orig, dom in zip(original.findings, dr.findings):
        assert orig.rule_id == dom.rule_id
        assert orig.severity == dom.severity
        assert orig.file == dom.file
        assert orig.line == dom.line


def test_builtin_domain_always_available():
    domain = BuiltinSecurityDomain()
    assert domain.is_available() is True


def test_builtin_domain_incremental():
    """Test incremental scanning via paths parameter."""
    project = make_project({
        "src/a.js": "const result = eval(userInput);",
        "src/b.js": "console.log('safe');",
    })

    domain = BuiltinSecurityDomain()

    # Full scan
    full = domain.run(project)
    assert any(f.rule_id == "SEC-003" for f in full.findings)

    # Incremental: only scan b.js (no findings expected)
    partial = domain.run(project, paths=[project / "src" / "b.js"])
    assert len(partial.findings) == 0


def test_builtin_domain_metadata():
    project = make_project({"src/app.js": "const x = 1;"})
    domain = BuiltinSecurityDomain()
    dr = domain.run(project)
    assert dr.domain == "security"
    assert dr.tool_name == "builtin"
    assert "scanned_files" in dr.metadata
    assert dr.metadata["scanned_files"] >= 1

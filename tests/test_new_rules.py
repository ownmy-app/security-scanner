"""Tests for SEC-005, SEC-008, SEC-012 rules."""
import sys
import json
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import (
    scan_project, check_missing_auth_middleware, check_exposed_admin_routes,
    check_dependency_confusion, HIGH, MEDIUM,
)


def make_project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".gitignore").write_text(".env\n")
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return tmp


# ── SEC-005: Missing auth on API routes ──────────────────────────────────────

def test_express_api_route_no_auth():
    project = make_project({
        "src/routes.js": "app.get('/api/users', (req, res) => { res.json([]); });"
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-005" for f in result.findings)


def test_express_api_route_with_auth():
    project = make_project({
        "src/routes.js": "app.get('/api/users', authMiddleware, (req, res) => { res.json([]); });"
    })
    result = scan_project(project)
    assert not any(f.rule_id == "SEC-005" for f in result.findings)


def test_fastapi_route_no_auth():
    project = make_project({
        "src/main.py": textwrap.dedent("""
            @app.get('/api/users')
            def get_users():
                return []
        """)
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-005" for f in result.findings)


def test_fastapi_route_with_depends():
    project = make_project({
        "src/main.py": textwrap.dedent("""
            @app.get('/api/users')
            def get_users(user=Depends(get_current_user)):
                return []
        """)
    })
    result = scan_project(project)
    assert not any(f.rule_id == "SEC-005" for f in result.findings)


# ── SEC-008: Exposed admin routes ────────────────────────────────────────────

def test_admin_route_no_auth():
    project = make_project({
        "src/routes.js": "app.get('/admin/settings', (req, res) => {});"
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-008" for f in result.findings)


def test_admin_route_with_auth():
    project = make_project({
        "src/routes.js": "app.get('/admin/settings', requireAdmin, (req, res) => {});"
    })
    result = scan_project(project)
    assert not any(f.rule_id == "SEC-008" for f in result.findings)


# ── SEC-012: Dependency confusion ────────────────────────────────────────────

def test_internal_looking_package():
    project = make_project({
        "package.json": json.dumps({
            "dependencies": {"my-company-internal-utils": "^1.0.0"},
        })
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-012" for f in result.findings)


def test_normal_package_no_flag():
    project = make_project({
        "package.json": json.dumps({
            "dependencies": {"express": "^4.0.0", "react": "^18.0.0"},
        })
    })
    result = scan_project(project)
    assert not any(f.rule_id == "SEC-012" for f in result.findings)

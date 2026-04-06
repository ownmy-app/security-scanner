"""Tests for language/framework auto-detection."""
import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.detection import ProjectContext


def _make_project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp


def test_detect_python():
    project = _make_project({
        "requirements.txt": "fastapi\nuvicorn\n",
        "main.py": "from fastapi import FastAPI",
    })
    ctx = ProjectContext(project)
    assert "python" in ctx.languages
    assert "fastapi" in ctx.frameworks
    assert ctx.has_python


def test_detect_typescript():
    project = _make_project({
        "package.json": json.dumps({
            "dependencies": {"react": "^18.0.0", "next": "^14.0.0"},
            "devDependencies": {"vitest": "^1.0.0"},
        }),
        "tsconfig.json": "{}",
        "src/app.tsx": "export default function App() {}",
    })
    ctx = ProjectContext(project)
    assert "typescript" in ctx.languages
    assert "react" in ctx.frameworks
    assert "nextjs" in ctx.frameworks
    assert "vitest" in ctx.frameworks
    assert ctx.has_javascript


def test_detect_dockerfile():
    project = _make_project({
        "Dockerfile": "FROM node:20\nCOPY . .",
        "app.js": "console.log('hello');",
    })
    ctx = ProjectContext(project)
    assert ctx.has_dockerfile


def test_detect_iac():
    project = _make_project({
        "terraform/main.tf": 'resource "aws_instance" "web" {}',
    })
    ctx = ProjectContext(project)
    assert ctx.has_iac


def test_detect_tests():
    project = _make_project({
        "tests/test_main.py": "def test_foo(): pass",
    })
    ctx = ProjectContext(project)
    assert ctx.has_tests


def test_recommended_domains():
    project = _make_project({
        "package.json": json.dumps({"dependencies": {"react": "^18"}}),
        "src/app.tsx": "export default function App() {}",
        "Dockerfile": "FROM node:20",
        "tests/app.test.tsx": "test('renders', () => {})",
    })
    ctx = ProjectContext(project)
    domains = ctx.recommended_domains()
    assert "security" in domains
    assert "lint" in domains
    assert "sca" in domains
    assert "container" in domains


def test_primary_language():
    project = _make_project({
        "main.py": "print('hello')",
        "tsconfig.json": "{}",
        "src/app.ts": "console.log('hello')",
    })
    ctx = ProjectContext(project)
    assert ctx.primary_language == "typescript"


def test_existing_tool_detection():
    project = _make_project({
        ".eslintrc.json": "{}",
        "biome.json": "{}",
        "pyproject.toml": "[tool.ruff]\nline-length = 100\n[tool.pytest.ini_options]\n",
    })
    ctx = ProjectContext(project)
    assert "eslint" in ctx.existing_tools
    assert "biome" in ctx.existing_tools
    assert "ruff" in ctx.existing_tools
    assert "pytest" in ctx.existing_tools


def test_empty_project():
    project = _make_project({})
    ctx = ProjectContext(project)
    assert len(ctx.languages) == 0
    assert ctx.primary_language == "unknown"
    domains = ctx.recommended_domains()
    assert "security" in domains
    # Duplication always recommended as a catch-all
    assert len(domains) <= 2


def test_summary():
    project = _make_project({"main.py": "pass"})
    ctx = ProjectContext(project)
    s = ctx.summary()
    assert "languages" in s
    assert "recommended_domains" in s

"""Tests for configuration loading."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.config import ScanConfig, load_config, _mini_yaml_parse, _coerce


def test_default_config():
    cfg = ScanConfig()
    assert cfg.scan_mode == "full"
    assert cfg.fail_on == "high"
    assert cfg.strict is False
    assert cfg.fix is False
    assert cfg.domains == []
    assert cfg.dashboard is False


def test_load_config_no_file():
    """Returns defaults when no config file exists."""
    with tempfile.TemporaryDirectory() as td:
        cfg = load_config(Path(td))
        assert cfg.scan_mode == "full"


def test_load_config_from_file():
    with tempfile.TemporaryDirectory() as td:
        Path(td, "ai-security-scan.yml").write_text(
            "scan_mode: incremental\n"
            "fail_on: critical\n"
            "strict: true\n"
            "domains:\n"
            "  - security\n"
            "  - lint\n"
        )
        cfg = load_config(Path(td))
        assert cfg.scan_mode == "incremental"
        assert cfg.fail_on == "critical"
        assert cfg.strict is True
        assert cfg.domains == ["security", "lint"]


def test_load_config_dotfile():
    with tempfile.TemporaryDirectory() as td:
        Path(td, ".ai-security-scan.yml").write_text("scan_mode: pr\nbase_ref: origin/develop\n")
        cfg = load_config(Path(td))
        assert cfg.scan_mode == "pr"
        assert cfg.base_ref == "origin/develop"


def test_mini_yaml_parse_scalars():
    text = """
name: test
version: 42
enabled: true
disabled: false
empty:
"""
    result = _mini_yaml_parse(text)
    assert result["name"] == "test"
    assert result["version"] == 42
    assert result["enabled"] is True
    assert result["disabled"] is False


def test_mini_yaml_parse_list():
    text = """
items:
  - alpha
  - beta
  - gamma
"""
    result = _mini_yaml_parse(text)
    assert result["items"] == ["alpha", "beta", "gamma"]


def test_coerce_types():
    assert _coerce("true") is True
    assert _coerce("false") is False
    assert _coerce("42") == 42
    assert _coerce("3.14") == 3.14
    assert _coerce("null") is None
    assert _coerce("'quoted'") == "quoted"
    assert _coerce("hello") == "hello"

"""Tests for the tool runner infrastructure."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.domains.tool_runner import ToolRunner, ToolOutput


def test_find_tool_in_path():
    runner = ToolRunner()
    # python3 should always be in PATH
    result = runner.find_tool("python3")
    assert result is not None
    assert Path(result).is_file()


def test_find_tool_not_found():
    runner = ToolRunner()
    result = runner.find_tool("nonexistent_tool_xyz_123")
    assert result is None


def test_run_tool_success():
    runner = ToolRunner()
    output = runner.run_tool(["python3", "-c", "print('hello')"])
    assert output.returncode == 0
    assert "hello" in output.stdout


def test_run_tool_failure():
    runner = ToolRunner()
    output = runner.run_tool(["python3", "-c", "raise Exception('boom')"])
    assert output.returncode != 0
    assert "boom" in output.stderr


def test_run_tool_not_found():
    runner = ToolRunner()
    output = runner.run_tool(["nonexistent_tool_xyz_123"])
    assert output.returncode == -1
    assert "not found" in output.stderr.lower()


def test_run_tool_timeout():
    runner = ToolRunner()
    output = runner.run_tool(["python3", "-c", "import time; time.sleep(10)"], timeout=1)
    assert output.returncode == -1
    assert "timed out" in output.stderr.lower()


def test_run_json_success():
    runner = ToolRunner()
    parsed, output = runner.run_json(["python3", "-c", "import json; print(json.dumps({'key': 'value'}))"])
    assert parsed == {"key": "value"}
    assert output.returncode == 0


def test_run_json_invalid():
    runner = ToolRunner()
    parsed, output = runner.run_json(["python3", "-c", "print('not json')"])
    assert parsed is None
    assert output.returncode == 0

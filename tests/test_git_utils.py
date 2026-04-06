"""Tests for git utilities."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.git_utils import (
    is_git_repo, get_current_branch, get_uncommitted_files,
    get_pr_changed_files, get_diff_content,
)


def test_is_git_repo_true():
    # The project root should be a git repo
    assert is_git_repo(Path(__file__).parent.parent) is True


def test_is_git_repo_false():
    with tempfile.TemporaryDirectory() as td:
        assert is_git_repo(Path(td)) is False


def test_get_current_branch():
    branch = get_current_branch(Path(__file__).parent.parent)
    assert isinstance(branch, str)
    # Should return something (might be HEAD in detached state)


def test_get_uncommitted_files_returns_list():
    result = get_uncommitted_files(Path(__file__).parent.parent)
    assert isinstance(result, list)


def test_get_pr_changed_files_non_git():
    with tempfile.TemporaryDirectory() as td:
        result = get_pr_changed_files(Path(td), "origin/main")
        assert result == []


def test_get_diff_content_non_git():
    with tempfile.TemporaryDirectory() as td:
        result = get_diff_content(Path(td))
        assert result == ""

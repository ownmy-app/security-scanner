"""
Git utilities for scan-mode resolution.

All functions gracefully return empty results when git is unavailable or
the project is not a git repository.
"""

import subprocess
from pathlib import Path
from typing import List, Optional


def _git(args: List[str], cwd: Path) -> Optional[str]:
    """Run a git command and return stdout, or None on failure."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def get_uncommitted_files(project_root: Path) -> List[str]:
    """Return files with uncommitted changes (staged + unstaged + untracked).

    Used by *incremental* scan mode.
    """
    files: set = set()

    # Staged changes
    out = _git(["diff", "--cached", "--name-only"], project_root)
    if out:
        files.update(line for line in out.splitlines() if line.strip())

    # Unstaged changes
    out = _git(["diff", "--name-only"], project_root)
    if out:
        files.update(line for line in out.splitlines() if line.strip())

    # Untracked files
    out = _git(["ls-files", "--others", "--exclude-standard"], project_root)
    if out:
        files.update(line for line in out.splitlines() if line.strip())

    return sorted(files)


def get_pr_changed_files(project_root: Path, base_ref: str) -> List[str]:
    """Return files changed between *base_ref* and HEAD.

    Used by *pr* scan mode.
    """
    out = _git(["diff", "--name-only", f"{base_ref}...HEAD"], project_root)
    if out:
        return [line for line in out.splitlines() if line.strip()]
    return []


def get_current_branch(project_root: Path) -> str:
    """Return the current git branch name, or empty string."""
    out = _git(["rev-parse", "--abbrev-ref", "HEAD"], project_root)
    return out.strip() if out else ""


def get_diff_content(project_root: Path, base_ref: str = "HEAD~1") -> str:
    """Return the unified diff as a string."""
    out = _git(["diff", base_ref], project_root)
    return out or ""


def is_git_repo(project_root: Path) -> bool:
    """Check if the given path is inside a git repository."""
    out = _git(["rev-parse", "--git-dir"], project_root)
    return out is not None

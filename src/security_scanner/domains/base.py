"""
Base classes for scan domains.

A Domain wraps one or more external tools (or built-in checks) under a single
quality category such as "security", "lint", or "sast".  Each domain:

  1. Reports whether it *can* run  (``is_available``).
  2. Detects which languages/files are relevant  (``detect``).
  3. Executes its checks and returns a normalised ``DomainResult``.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Re-use the canonical Finding from the core scanner module
from security_scanner.scanner import Finding


@dataclass
class DomainResult:
    """Normalised output of a single domain run."""

    domain: str
    findings: List[Finding] = field(default_factory=list)
    tool_name: str = ""
    tool_version: str = ""
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not any(
            f.severity in ("CRITICAL", "HIGH") for f in self.findings
        )


class Domain(ABC):
    """Abstract base class for a scan domain."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the required tool(s) are installed / reachable."""
        ...

    @abstractmethod
    def run(
        self,
        project_root: Path,
        paths: Optional[List[Path]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> DomainResult:
        """Execute the domain scan and return normalised results.

        Args:
            project_root: Absolute path to the project root directory.
            paths:        Optional subset of files to scan (incremental mode).
                          When *None* the domain should scan the full project.
            config:       Optional per-domain configuration overrides.
        """
        ...

"""Data models shared by agents."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class ScanPlan:
    """Output of the diff analyzer: which domains and files to focus on."""

    domains: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    priority_files: List[str] = field(default_factory=list)
    reasoning: str = ""

"""Tests for quality history tracking."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import ScanResult, Finding, CRITICAL, HIGH, MEDIUM, LOW
from security_scanner.history import (
    compute_health_score, create_snapshot, HistoryManager, QualitySnapshot,
)


def test_health_score_perfect():
    result = ScanResult(scanned=10)
    assert compute_health_score(result) == 10.0


def test_health_score_critical():
    result = ScanResult(
        findings=[Finding(rule_id="X", severity=CRITICAL, file="a", line=1, message="m")],
        scanned=1,
    )
    assert compute_health_score(result) == 8.0


def test_health_score_floor():
    findings = [
        Finding(rule_id=f"X{i}", severity=CRITICAL, file="a", line=i, message="m")
        for i in range(10)
    ]
    result = ScanResult(findings=findings, scanned=1)
    assert compute_health_score(result) == 0.0


def test_create_snapshot():
    result = ScanResult(
        findings=[
            Finding(rule_id="SEC-001", severity=CRITICAL, file="a.js", line=1, message="key"),
            Finding(rule_id="SEC-003", severity=HIGH, file="b.js", line=2, message="eval"),
        ],
        scanned=5,
    )
    snap = create_snapshot(result)
    assert snap.critical == 1
    assert snap.high == 1
    assert snap.total_findings == 2
    assert snap.scanned_files == 5
    assert snap.health_score == 7.0
    assert not snap.passed


def test_history_manager_append_and_retrieve():
    with tempfile.TemporaryDirectory() as td:
        mgr = HistoryManager(Path(td))
        result = ScanResult(scanned=1)
        snap = create_snapshot(result)
        mgr.append(snap)

        latest = mgr.get_latest()
        assert latest is not None
        assert latest.health_score == 10.0

        assert mgr.get_previous() is None  # only one snapshot


def test_history_manager_trend():
    with tempfile.TemporaryDirectory() as td:
        mgr = HistoryManager(Path(td))

        # First: good score
        snap1 = QualitySnapshot(
            timestamp=1.0, scanned_files=10, total_findings=0,
            critical=0, high=0, medium=0, low=0, health_score=10.0,
            domains={}, passed=True,
        )
        mgr.append(snap1)

        # Second: worse
        snap2 = QualitySnapshot(
            timestamp=2.0, scanned_files=10, total_findings=3,
            critical=1, high=1, medium=1, low=0, health_score=6.7,
            domains={}, passed=False,
        )
        mgr.append(snap2)

        trend = mgr.trend_indicator()
        assert "↓" in trend


def test_history_manager_pruning():
    with tempfile.TemporaryDirectory() as td:
        mgr = HistoryManager(Path(td), max_snapshots=3)
        for i in range(5):
            snap = QualitySnapshot(
                timestamp=float(i), scanned_files=1, total_findings=0,
                critical=0, high=0, medium=0, low=0, health_score=10.0,
                domains={}, passed=True,
            )
            mgr.append(snap)
        all_snaps = mgr.get_snapshots(count=100)
        assert len(all_snaps) == 3

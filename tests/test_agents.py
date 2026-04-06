"""Tests for AI agents (diff analyzer, reviewer, model registry)."""
import sys
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.scanner import scan_project, Finding, CRITICAL, HIGH, MEDIUM, LOW
from security_scanner.agents.diff_analyzer import DiffAnalyzer
from security_scanner.agents.reviewer import ReviewAgent
from security_scanner.agents.verdict import ReviewVerdict, FindingVerdict
from security_scanner.agents.models import ScanPlan
from security_scanner.agents.model_registry import ModelRegistry, PROVIDERS, UsageRecord


# ── DiffAnalyzer ─────────────────────────────────────────────────────────────

def test_diff_analyzer_python_files():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["src/main.py", "tests/test_main.py"])
    assert "security" in plan.domains
    assert "lint" in plan.domains
    assert "typecheck" in plan.domains


def test_diff_analyzer_dockerfile():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["Dockerfile", "docker-compose.yml"])
    assert "container" in plan.domains


def test_diff_analyzer_dependency_files():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["package.json", "package-lock.json"])
    assert "sca" in plan.domains


def test_diff_analyzer_iac_files():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["terraform/main.tf"])
    assert "iac" in plan.domains


def test_diff_analyzer_security_sensitive():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["src/auth/login.py", "src/middleware/guard.ts"])
    assert "src/auth/login.py" in plan.priority_files
    assert "src/middleware/guard.ts" in plan.priority_files


def test_diff_analyzer_empty():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze([])
    assert plan.domains == []
    assert plan.files == []


def test_diff_analyzer_always_includes_security():
    analyzer = DiffAnalyzer()
    plan = analyzer.analyze(["README.md"])
    # Even for non-code files, security should be included if there are changes
    assert "security" in plan.domains


# ── ReviewAgent ──────────────────────────────────────────────────────────────

def _make_findings():
    return [
        Finding(rule_id="SEC-001", severity=CRITICAL, file="src/config.ts", line=1, message="Hardcoded key"),
        Finding(rule_id="SEC-003", severity=HIGH, file="tests/test_utils.js", line=5, message="eval usage"),
        Finding(rule_id="SEC-007", severity=LOW, file="src/api.ts", line=10, message="HTTP URL"),
    ]


def test_reviewer_basic():
    from security_scanner.scanner import ScanResult
    result = ScanResult(findings=_make_findings(), scanned=3)
    reviewer = ReviewAgent()
    verdict = reviewer.review(result)
    assert isinstance(verdict, ReviewVerdict)
    assert len(verdict.finding_verdicts) == 3


def test_reviewer_test_file_suppression():
    from security_scanner.scanner import ScanResult
    result = ScanResult(findings=_make_findings(), scanned=3)
    reviewer = ReviewAgent()
    verdict = reviewer.review(result)
    # The test file finding should be marked as false positive
    test_verdicts = [v for v in verdict.finding_verdicts if "test" in v.finding.file.lower()]
    assert len(test_verdicts) > 0
    assert not test_verdicts[0].is_true_positive


def test_reviewer_critical_high_confidence():
    from security_scanner.scanner import ScanResult
    findings = [Finding(rule_id="SEC-001", severity=CRITICAL, file="src/config.ts", line=1, message="key")]
    result = ScanResult(findings=findings, scanned=1)
    reviewer = ReviewAgent()
    verdict = reviewer.review(result)
    crit = [v for v in verdict.finding_verdicts if v.finding.severity == CRITICAL]
    assert crit[0].confidence >= 0.9


def test_reviewer_risk_level():
    from security_scanner.scanner import ScanResult
    findings = [Finding(rule_id="SEC-001", severity=CRITICAL, file="src/config.ts", line=1, message="key")]
    result = ScanResult(findings=findings, scanned=1)
    reviewer = ReviewAgent()
    verdict = reviewer.review(result)
    assert verdict.risk_level == "critical"


def test_reviewer_no_findings():
    from security_scanner.scanner import ScanResult
    result = ScanResult(findings=[], scanned=1)
    reviewer = ReviewAgent()
    verdict = reviewer.review(result)
    assert verdict.risk_level == "none"
    assert len(verdict.recommended_actions) == 0


# ── ModelRegistry ────────────────────────────────────────────────────────────

def test_model_registry_providers():
    assert "anthropic" in PROVIDERS
    assert "openai" in PROVIDERS
    assert PROVIDERS["anthropic"].api_key_env == "ANTHROPIC_API_KEY"


def test_model_registry_usage_tracking():
    reg = ModelRegistry()
    reg.record_usage(UsageRecord(
        provider="anthropic", model="test", input_tokens=100,
        output_tokens=50, cost_usd=0.001, timestamp=0.0,
    ))
    assert reg.total_cost == 0.001
    assert reg.total_input_tokens == 100
    assert reg.total_output_tokens == 50


def test_model_registry_summary():
    reg = ModelRegistry()
    reg.record_usage(UsageRecord(provider="anthropic", model="test",
                                  input_tokens=100, output_tokens=50, cost_usd=0.001))
    reg.record_usage(UsageRecord(provider="openai", model="test2",
                                  input_tokens=200, output_tokens=100, cost_usd=0.002))
    summary = reg.usage_summary()
    assert summary["total_calls"] == 2
    assert summary["total_cost_usd"] == 0.003
    assert "anthropic" in summary["by_provider"]
    assert "openai" in summary["by_provider"]

"""Tests for the domain registry."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_scanner.domains import (
    register_domain, get_domain, get_all_domains, discover_domains,
)
from security_scanner.domains.base import Domain, DomainResult


def test_builtin_security_registered():
    d = get_domain("security")
    assert d is not None
    assert d.name == "security"
    assert d.is_available() is True


def test_all_domains_registered():
    domains = get_all_domains()
    expected = {
        "security", "lint", "typecheck", "sast", "sca", "iac", "container",
    }
    assert set(domains.keys()) >= expected  # may include custom plugins


def test_unknown_domain_returns_none():
    assert get_domain("nonexistent") is None


def test_discover_domains_idempotent():
    """Calling discover_domains multiple times doesn't duplicate entries."""
    before = len(get_all_domains())
    discover_domains()
    discover_domains()
    assert len(get_all_domains()) == before


def test_custom_domain_registration():
    class MockDomain(Domain):
        name = "mock"
        description = "test domain"
        def is_available(self): return True
        def run(self, project_root, paths=None, config=None):
            return DomainResult(domain="mock")

    register_domain("mock", MockDomain)
    d = get_domain("mock")
    assert d is not None
    assert d.name == "mock"
    assert d.is_available()

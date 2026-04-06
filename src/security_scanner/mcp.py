"""
MCP (Model Context Protocol) tool definitions for Claude Code integration.

Provides structured tool handlers that can be exposed via an MCP server,
enabling the AI-assisted iterative fix loop:

    AI writes code → scanner checks it → AI reads findings → AI fixes issues

All functions return JSON-serializable dicts.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def security_scan(
    project_path: str,
    mode: str = "full",
    domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run a full or incremental scan.

    MCP Tool: security_scan
    """
    from security_scanner.config import ScanConfig
    from security_scanner.scanner import scan_project_v2
    from security_scanner.reporter import format_mcp

    root = Path(project_path).resolve()
    config = ScanConfig(
        scan_mode=mode,
        domains=domains or [],
    )
    result = scan_project_v2(root, config)
    return json.loads(format_mcp(result))


def security_scan_file(
    project_path: str,
    file_path: str,
) -> Dict[str, Any]:
    """Scan a single file.

    MCP Tool: security_scan_file
    """
    from security_scanner.scanner import scan_files

    root = Path(project_path).resolve()
    result = scan_files(root, [file_path])
    return {
        "file": file_path,
        "findings": [
            {
                "rule": f.rule_id,
                "severity": f.severity,
                "line": f.line,
                "message": f.message,
                "fix": f.fix,
            }
            for f in result.findings
        ],
        "passed": result.passed,
    }


def security_scan_pr(
    project_path: str,
    base_ref: str = "origin/main",
) -> Dict[str, Any]:
    """Scan only files changed in the current PR.

    MCP Tool: security_scan_pr
    """
    from security_scanner.config import ScanConfig
    from security_scanner.scanner import scan_project_v2

    root = Path(project_path).resolve()
    config = ScanConfig(
        scan_mode="pr",
        base_ref=base_ref,
    )
    result = scan_project_v2(root, config)
    return {
        "mode": "pr",
        "base_ref": base_ref,
        "status": "pass" if result.passed else "fail",
        "findings_count": len(result.findings),
        "findings": [
            {
                "rule": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "fix": f.fix,
            }
            for f in result.findings
        ],
    }


def quality_report(project_path: str) -> Dict[str, Any]:
    """Generate a QUALITY.md dashboard.

    MCP Tool: quality_report
    """
    from security_scanner.scanner import scan_project_v2
    from security_scanner.dashboard import write_dashboard

    root = Path(project_path).resolve()
    result = scan_project_v2(root)
    path = write_dashboard(root, result)
    return {
        "dashboard_path": str(path),
        "status": "pass" if result.passed else "fail",
        "findings_count": len(result.findings),
    }


def list_domains() -> Dict[str, Any]:
    """List all available scan domains.

    MCP Tool: list_domains
    """
    from security_scanner.domains import get_all_domains

    domains = get_all_domains()
    return {
        "domains": [
            {
                "name": name,
                "description": d.description,
                "available": d.is_available(),
            }
            for name, d in sorted(domains.items())
        ]
    }


def list_tools() -> Dict[str, Any]:
    """List managed tool status.

    MCP Tool: list_tools
    """
    from security_scanner.provisioning import ToolProvisioner, MANAGED_TOOLS

    provisioner = ToolProvisioner()
    installed = provisioner.list_provisioned()
    installed_names = {n for n, v, p in installed}

    return {
        "tools": [
            {
                "name": name,
                "version": manifest.version,
                "installed": name in installed_names,
            }
            for name, manifest in sorted(MANAGED_TOOLS.items())
        ]
    }


def explain_finding(
    project_path: str,
    rule_id: str,
    file_path: str,
    line: int,
) -> Dict[str, Any]:
    """Get detailed explanation of a specific finding.

    MCP Tool: explain_finding
    """
    from security_scanner.scanner import scan_files

    root = Path(project_path).resolve()
    result = scan_files(root, [file_path])

    for f in result.findings:
        if f.rule_id == rule_id and f.line == line:
            # Read surrounding context
            context = ""
            fpath = root / file_path
            if fpath.is_file():
                try:
                    lines = fpath.read_text(errors="replace").splitlines()
                    start = max(0, line - 5)
                    end = min(len(lines), line + 5)
                    context = "\n".join(
                        f"{i+1:4d} | {lines[i]}" for i in range(start, end)
                    )
                except Exception:
                    pass

            return {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "fix": f.fix,
                "snippet": f.snippet,
                "context": context,
                "domain": f.domain,
            }

    return {"error": f"Finding {rule_id} at {file_path}:{line} not found"}


def get_status(project_path: str = ".") -> Dict[str, Any]:
    """Get project scan status: available domains, tools, config.

    MCP Tool: status
    """
    from security_scanner.domains import get_all_domains
    from security_scanner.config import load_config

    root = Path(project_path).resolve()
    config = load_config(root)
    domains = get_all_domains()

    return {
        "project": str(root),
        "domains": {
            name: {"available": d.is_available(), "description": d.description}
            for name, d in sorted(domains.items())
        },
        "config": {"scan_mode": config.scan_mode, "fail_on": config.fail_on},
    }


# ── MCP Tool Registry ────────────────────────────────────────────────────────

MCP_TOOLS = {
    "security_scan": {
        "function": security_scan,
        "description": "Run a multi-domain security and quality scan on a project.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "description": "Path to project root"},
                "mode": {"type": "string", "enum": ["full", "incremental", "pr"], "default": "full"},
                "domains": {"type": "array", "items": {"type": "string"}, "description": "Domains to run (empty = all)"},
            },
            "required": ["project_path"],
        },
    },
    "security_scan_file": {
        "function": security_scan_file,
        "description": "Scan a single file for security issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "file_path": {"type": "string", "description": "Relative path to the file"},
            },
            "required": ["project_path", "file_path"],
        },
    },
    "security_scan_pr": {
        "function": security_scan_pr,
        "description": "Scan only files changed in the current PR/branch.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "base_ref": {"type": "string", "default": "origin/main"},
            },
            "required": ["project_path"],
        },
    },
    "quality_report": {
        "function": quality_report,
        "description": "Generate a QUALITY.md dashboard in the project root.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
            },
            "required": ["project_path"],
        },
    },
    "list_domains": {
        "function": list_domains,
        "description": "List all available scan domains and their availability.",
        "input_schema": {"type": "object", "properties": {}},
    },
    "list_tools": {
        "function": list_tools,
        "description": "List managed tool binaries and their install status.",
        "input_schema": {"type": "object", "properties": {}},
    },
    "explain_finding": {
        "function": explain_finding,
        "description": "Get detailed explanation and code context for a specific finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "rule_id": {"type": "string"},
                "file_path": {"type": "string"},
                "line": {"type": "integer"},
            },
            "required": ["project_path", "rule_id", "file_path", "line"],
        },
    },
    "status": {
        "function": get_status,
        "description": "Get project scan status: available domains, tools, and config.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string", "default": "."},
            },
        },
    },
}

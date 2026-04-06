# security-scan

Built by the [Nometria](https://nometria.com) team. We help developers take apps built with AI tools (Lovable, Bolt, Base44, Replit) to production — handling deployment to AWS, security, scaling, and giving you full code ownership. [Learn more →](https://nometria.com)

> Multi-domain code quality gate for AI-generated web apps.

AI code generators (Lovable, Bolt, v0, Cursor, Copilot) frequently produce code with
hardcoded secrets, missing auth guards, SQL injection patterns, and CORS misconfigs.
This scanner catches those before they hit production — plus linting, SAST, SCA, and more.

**Zero dependencies for core security rules. Pure Python stdlib.**

---

## Quick start

```bash
pip install -e .

# One-command setup (generates config + Claude Code integration)
security-scan init

# Scan your project
security-scan .

# Scan and auto-fix lint issues
security-scan . --fix
```

---

## Commands

| Command | What it does |
|---------|-------------|
| `security-scan .` | Scan the current directory |
| `security-scan init` | Generate config, `.mcp.json`, and `.claude/CLAUDE.md` |
| `security-scan doctor` | Validate environment (config, tools, MCP) |
| `security-scan serve` | Start MCP stdio server for Claude Code |
| `security-scan tools list` | Show managed tool status |
| `security-scan tools install trivy` | Download a managed tool binary |

---

## CLI flags

```bash
security-scan [PATH] [OPTIONS]

Options:
  --format {console,json,sarif,markdown}  Output format (default: console)
  --output FILE            Write output to file
  --fail-on LEVEL          Exit 1 at this severity: critical, high, medium, low (default: high)
  --mode {full,incremental,pr}  Scan mode (default: full)
  --base-ref REF           Base branch for PR mode (default: auto-detect)
  --domains DOMAIN,...     Comma-separated domains to run (default: all available)
  --fix                    Auto-fix lint issues (ruff, eslint)
  --dashboard              Generate QUALITY.md report
  --watch                  Watch for file changes and re-scan
  --config FILE            Config file path
  --strict                 Missing tools are findings
  --no-color               Disable ANSI colors
```

---

## Security rules (SEC-001 — SEC-012)

| Rule | Severity | Catches |
|------|----------|---------|
| SEC-001 | CRITICAL | Hardcoded API keys, tokens, passwords, JWT secrets |
| SEC-002 | HIGH | `.env` file committed without `.gitignore` entry |
| SEC-003 | HIGH | Dangerous `eval()` / `exec()` usage |
| SEC-004 | HIGH | SQL injection (string interpolation in queries) |
| SEC-005 | HIGH | Missing auth middleware on API routes (Express/FastAPI) |
| SEC-006 | MEDIUM | CORS wildcard `*` in production code |
| SEC-007 | LOW | HTTP (not HTTPS) hardcoded URLs |
| SEC-008 | HIGH | Exposed admin routes without auth |
| SEC-009 | HIGH | Auth tokens stored in `localStorage` (XSS risk) |
| SEC-010 | MEDIUM | `process.env` values logged to console |
| SEC-011 | CRITICAL | Supabase `service_role` key used client-side |
| SEC-012 | MEDIUM | Dependency confusion risk in `package.json` |

---

## Scan domains

Beyond the built-in security rules, the scanner can invoke external tools:

| Domain | Tools | What it checks |
|--------|-------|---------------|
| **security** | built-in (always available) | 12 regex rules (SEC-001 — SEC-012) |
| **lint** | Ruff, ESLint, Biome, Clippy, GoLangCI-Lint | Code style and logic errors |
| **typecheck** | MyPy, Pyright, tsc | Static type errors |
| **sast** | OpenGrep / Semgrep | Security vulnerabilities via SAST rules |
| **sca** | Trivy | Dependency CVE scanning |
| **iac** | Checkov | Infrastructure-as-code misconfigurations |
| **container** | Trivy | Dockerfile misconfigurations |

Domains auto-detect which tools are installed. Missing tools are silently skipped
(or flagged with `--strict`).

```bash
# Run only security + lint
security-scan . --domains security,lint

# Run everything available
security-scan .
```

---

## Claude Code / MCP integration

The scanner integrates with Claude Code via the Model Context Protocol.

```bash
# One-time setup
security-scan init

# This generates:
#   ai-security-scan.yml    — scan configuration
#   .mcp.json               — tells Claude Code to use our MCP server
#   .claude/CLAUDE.md       — instructions for Claude
```

After `init`, restart Claude Code. Claude can then:
- Run `scan` to check the project
- Run `scan_file` to check a single file
- Run `explain` to get details on a finding
- Run `status` to see available domains and tools

---

## Configuration

Create `ai-security-scan.yml` in your project root (or run `security-scan init`):

```yaml
# Which domains to run (empty = all available)
domains: [security, lint, sca]

# Scan mode: full | incremental | pr
scan_mode: full

# Fail threshold: critical | high | medium | low
fail_on: high

# Generate QUALITY.md dashboard
dashboard: false

# Auto-fix lint issues on scan
fix: false

# Directories to skip
exclude_patterns:
  - node_modules
  - .git
  - dist
  - build

# Per-domain tool config
tool_overrides:
  lint:
    ruff:
      select: [E, F, W]
```

---

## GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nometria/security-scanner@main
        with:
          target_dir: '.'
          fail_on: 'high'
          sarif_upload: 'true'
```

Or install directly:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with: { python-version: '3.11' }
  - run: pip install ai-security-scan
  - run: security-scan . --format sarif --output results.sarif --fail-on high
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: results.sarif }
```

---

## Use as a library

```python
from security_scanner import scan_project, scan_project_v2

# Simple: built-in security rules only
result = scan_project("./my-app")
print(f"Passed: {result.passed}, Findings: {len(result.findings)}")

# Multi-domain: security + lint + sca + any installed tools
result = scan_project_v2("./my-app")
for name, info in result.domain_results.items():
    print(f"  {name}: {info['findings']} findings ({info['time']:.1f}s)")
```

---

## Project structure

```
src/security_scanner/
├── scanner.py          # Core: 12 security rules + scan_project + scan_project_v2
├── cli.py              # CLI: scan, init, doctor, serve, tools
├── config.py           # YAML config loader
├── reporter.py         # Output: console, JSON, SARIF, Markdown
├── detection.py        # Language/framework auto-detection
├── dashboard.py        # QUALITY.md generator
├── history.py          # Quality trending + health scores
├── git_utils.py        # Git diff/branch utilities
├── mcp.py              # MCP tool library (Python API)
├── mcp_server.py       # MCP stdio server (for Claude Code)
├── domains/
│   ├── builtin.py      # Wraps the 12 SEC rules as a domain
│   ├── lint.py         # Ruff, ESLint, Biome, Clippy, GoLangCI-Lint
│   ├── typecheck.py    # MyPy, Pyright, tsc
│   ├── sast.py         # OpenGrep / Semgrep
│   ├── sca.py          # Trivy (dependency vulnerabilities)
│   ├── iac.py          # Checkov (IaC misconfigs)
│   └── container.py    # Trivy (Dockerfile misconfigs)
├── provisioning/       # Managed tool download + verification
└── agents/             # Diff analysis + finding review (optional)
```

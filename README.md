# proto_gap

> **Turn your AI-generated prototype into an engineering backlog in seconds.**

`proto_gap` statically analyzes AI-generated codebases (Cursor, Lovable, v0, and similar) and produces a prioritized, actionable checklist of production-readiness gaps. No runtime execution required — point it at a repo, get a structured report covering auth, security, error handling, and more. Designed to bridge the communication gap between AI-empowered product managers and the backend engineers who have to ship it for real.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Usage Examples](#usage-examples)
- [Output Formats](#output-formats)
- [Check Categories](#check-categories)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Exit Codes](#exit-codes)
- [License](#license)

---

## Quick Start

```bash
# Install from PyPI
pip install proto_gap

# Scan a prototype repository (rich terminal output)
proto-gap ./my-prototype

# Export a Markdown checklist
proto-gap ./my-prototype --output markdown --output-file gap-report.md

# Pipe JSON findings into jq
proto-gap ./my-prototype --output json | jq '.findings[] | select(.severity == "CRITICAL")'
```

That's it. After running `proto-gap ./my-prototype` you'll see a color-coded table of findings in your terminal, sorted by severity.

---

## Features

- **Zero execution required** — pure static analysis via Python AST and regex; no dependencies are installed or code run from the target repo.
- **Seven built-in check categories** — authentication, error handling, environment config, security vulnerabilities, database migrations, logging, and test coverage.
- **Prioritized severity levels** — every finding is tagged `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` with a concrete remediation hint.
- **Three output formats** — rich color terminal table, Markdown checklist ready to paste into a GitHub issue, and machine-readable JSON for CI pipelines.
- **Extensible rule registry** — add custom regex or AST-based rules for your team's standards without touching core analyzer logic.

---

## Usage Examples

### Basic terminal scan

```bash
proto-gap ./my-prototype
```

```
┌─────────────────────────────────────────────────────────────────────┐
│                  proto_gap — Production Readiness Report            │
│  Scanned: ./my-prototype   Files: 12   Findings: 9                  │
└─────────────────────────────────────────────────────────────────────┘

 Severity   Category          File                  Finding
 ────────── ───────────────── ───────────────────── ──────────────────────────────────
 CRITICAL   Security          app.py:42             eval() called with user input
 CRITICAL   Authentication    app.py:8              Hardcoded secret key detected
 HIGH       Migrations        app.py:91             db.create_all() — no migration tool
 HIGH       Error Handling    routes.py:34          Bare except clause silences errors
 HIGH       Environment       app.py:14             DEBUG=True hardcoded in source
 MEDIUM     Logging           app.py:22             print() used instead of logger
 MEDIUM     Security          app.py:57             pickle.loads() on untrusted data
 LOW        Testing           —                     No test files found in repository
 LOW        Authentication    app.py:101            Weak hashing algorithm: MD5
```

### Export a Markdown checklist for a GitHub issue

```bash
proto-gap ./my-prototype --output markdown --output-file gap-report.md
cat gap-report.md
```

```markdown
## proto_gap — Production Readiness Checklist

**Scanned:** `./my-prototype` | **Files:** 12 | **Findings:** 9

### 🔴 CRITICAL

- [ ] **[SEC001]** `app.py:42` — `eval()` called with user input. Replace with a safe parser.
- [ ] **[AUTH001]** `app.py:8` — Hardcoded secret key. Move to environment variable.

### 🟠 HIGH

- [ ] **[MIG002]** `app.py:91` — `db.create_all()` used without a migration tool. Adopt Alembic.
...
```

### JSON output for CI integration

```bash
proto-gap ./my-prototype --output json > report.json

# Fail CI if any CRITICAL findings exist
proto-gap ./my-prototype --output json | jq -e '.summary.critical == 0'
```

```json
{
  "scanned_path": "./my-prototype",
  "file_count": 12,
  "summary": { "critical": 2, "high": 3, "medium": 2, "low": 2 },
  "findings": [
    {
      "id": "SEC001",
      "severity": "CRITICAL",
      "category": "security",
      "file": "app.py",
      "line": 42,
      "message": "eval() called with user input",
      "hint": "Replace eval() with ast.literal_eval() or a dedicated safe parser."
    }
  ]
}
```

### Scan with a custom config file

```bash
proto-gap ./my-prototype --config proto-gap.toml
```

---

## Output Formats

| Format | Flag | Best for |
|---|---|---|
| Terminal (default) | `--output terminal` | Local development, quick review |
| Markdown | `--output markdown` | GitHub issues, PRs, planning docs |
| JSON | `--output json` | CI pipelines, dashboards, tooling |

Use `--output-file <path>` with any format to write the report to a file instead of stdout.

---

## Check Categories

| Category | What It Looks For |
|---|---|
| **Authentication** | Hardcoded secrets, missing auth middleware, weak hashing (MD5/SHA1) |
| **Error Handling** | Bare `except` clauses, silent `pass` blocks, unhandled promise rejections |
| **Environment Config** | `DEBUG=True` in source, missing `.env.example`, secrets not in env vars |
| **Security** | `eval()`, `pickle`, unsafe `yaml.load`, `subprocess` shell injection, `verify=False` |
| **Migrations** | `db.create_all()` without Alembic, SQLite in production config, no migration directory |
| **Logging** | `print()` instead of a logger, `logging.basicConfig()` at module level |
| **Testing** | No test files found, `pytest.mark.skip` overuse, empty test directories |

---

## Project Structure

```
proto_gap/
├── pyproject.toml                          # Project metadata, entry points, dependencies
├── README.md                               # This file
├── proto_gap/
│   ├── __init__.py                         # Package init, version constant, top-level exports
│   ├── cli.py                              # Typer CLI entry point (proto-gap command)
│   ├── scanner.py                          # Orchestrates analyzers, aggregates findings
│   ├── analyzers.py                        # Individual static-analysis check functions
│   ├── rules.py                            # Declarative regex + AST rule registry
│   ├── models.py                           # Finding, Category, Severity, ScanReport dataclasses
│   └── renderer.py                         # Renders ScanReport to terminal, Markdown, or JSON
└── tests/
    ├── __init__.py
    ├── test_models.py                      # Unit tests for data models
    ├── test_rules.py                       # Unit tests for rule registry
    ├── test_analyzers.py                   # Unit tests for each analyzer function
    ├── test_scanner.py                     # Integration tests for the full scanner pipeline
    ├── test_renderer.py                    # Tests for all three output renderers
    └── fixtures/
        └── sample_prototype/
            ├── app.py                      # Synthetic prototype with intentional gaps
            └── requirements.txt            # Fake requirements for integration fixtures
```

---

## Configuration

`proto_gap` can be configured via a `proto-gap.toml` file in your project root or passed explicitly with `--config`.

```toml
# proto-gap.toml

[scan]
# Directories to exclude from scanning (in addition to built-in defaults)
exclude_dirs = ["migrations", "vendor", ".venv"]

# Only report findings at or above this severity level
min_severity = "medium"   # critical | high | medium | low

[rules]
# Disable specific rule IDs
disabled = ["LOG002", "ENV003"]

[custom_rules]
# Add a custom regex rule
[[custom_rules.regex]]
id = "CUSTOM001"
pattern = "TODO: remove before prod"
category = "security"
severity = "high"
message = "Found a TODO marked for removal before production"
hint = "Address or remove this TODO before deploying."
```

### CLI Flags

```
Usage: proto-gap [OPTIONS] [REPO_PATH]

Options:
  --output      [terminal|markdown|json]  Output format  [default: terminal]
  --output-file PATH                      Write report to a file
  --config      PATH                      Path to proto-gap.toml config file
  --min-severity [critical|high|medium|low]  Minimum severity to report
  --version                               Show version and exit
  --help                                  Show this message and exit
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete — no findings, or only LOW / MEDIUM findings |
| `1` | Invalid arguments or I/O error |
| `2` | Scan complete — one or more HIGH severity findings |
| `3` | Scan complete — one or more CRITICAL severity findings |

This makes `proto-gap` easy to integrate into CI pipelines:

```yaml
# .github/workflows/gap-check.yml
- name: Check production readiness
  run: proto-gap . --output json --min-severity high
  # Exits 2 or 3 if HIGH/CRITICAL findings exist, failing the workflow
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*

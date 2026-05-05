# proto_gap

> **Bridge the gap between AI-generated prototypes and production-ready code.**

`proto_gap` is a CLI tool that statically analyzes AI-generated prototype codebases (Cursor, Lovable, v0, etc.) and produces a prioritized, actionable checklist of production-readiness gaps. It scans a repository for missing authentication, error handling, database migration strategies, environment configuration, security vulnerabilities, logging, and testing coverage — then outputs a structured report in rich terminal color, Markdown, or JSON.

Designed to bridge the communication gap between AI-empowered product managers and backend engineers, `proto_gap` turns a prototype into a concrete engineering backlog in seconds.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Scanning a Repository](#scanning-a-repository)
  - [Output Formats](#output-formats)
  - [Flags and Options](#flags-and-options)
  - [Exit Codes](#exit-codes)
- [Check Categories](#check-categories)
  - [Authentication](#authentication)
  - [Error Handling](#error-handling)
  - [Environment Config](#environment-config)
  - [Security](#security)
  - [Database Migrations](#database-migrations)
  - [Logging](#logging)
  - [Testing](#testing)
- [Example Output](#example-output)
  - [Terminal Output](#terminal-output)
  - [Markdown Output](#markdown-output)
  - [JSON Output](#json-output)
- [Severity Levels](#severity-levels)
- [Rule Reference](#rule-reference)
- [Extending proto_gap](#extending-proto_gap)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Static analysis only** — no code execution required; safe to run on any repository.
- **Seven check categories** covering the most common prototype-to-production gaps.
- **Prioritized findings** with CRITICAL / HIGH / MEDIUM / LOW severity levels and actionable remediation hints.
- **Three output formats**: rich color terminal table, Markdown checklist for GitHub issues, and machine-readable JSON.
- **Extensible rule registry** — add custom pattern checks without modifying core analyzer logic.
- **CI/CD friendly** — non-zero exit codes on HIGH or CRITICAL findings; `--no-exit-codes` flag for advisory-only use.
- **Fast** — analyzes an entire prototype repository in under a second.

---

## Installation

### From PyPI (recommended)

```bash
pip install proto_gap
```

### From source

```bash
git clone https://github.com/example/proto_gap.git
cd proto_gap
pip install -e .
```

### Requirements

- Python 3.11 or higher
- No external runtime dependencies beyond `typer[all]` and `rich`

---

## Quick Start

```bash
# Scan the current directory
proto-gap .

# Scan a specific prototype directory
proto-gap ./my-prototype

# Generate a Markdown report for a GitHub issue
proto-gap ./my-prototype --output markdown --output-file production-gaps.md

# Generate machine-readable JSON for CI pipelines
proto-gap ./my-prototype --output json | jq '.summary'

# Show the version
proto-gap --version
```

---

## Usage

### Scanning a Repository

```
proto-gap [REPO_PATH] [OPTIONS]
```

`REPO_PATH` defaults to the current working directory (`.`) if not specified.

### Output Formats

`proto_gap` supports three output formats controlled by the `--output` / `-o` flag:

| Format | Description | Use case |
|--------|-------------|----------|
| `terminal` | Rich color-coded table with severity levels and detailed findings | Interactive review during development |
| `markdown` | GitHub-flavoured Markdown checklist | Pasting into GitHub issues, PRs, or planning docs |
| `json` | Machine-readable structured JSON | CI pipelines, dashboards, downstream tooling |

```bash
# Rich terminal output (default)
proto-gap ./my-app

# Markdown to stdout
proto-gap ./my-app --output markdown

# Markdown to a file
proto-gap ./my-app --output markdown --output-file gaps.md

# JSON to stdout
proto-gap ./my-app --output json

# JSON to a file
proto-gap ./my-app --output json --output-file gaps.json

# Pipe JSON to jq
proto-gap ./my-app --output json | jq '.findings[] | select(.severity == "CRITICAL")'
```

### Flags and Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `REPO_PATH` | | `.` | Path to the repository directory to analyze |
| `--output` | `-o` | `terminal` | Output format: `terminal`, `markdown`, or `json` |
| `--output-file` | `-f` | stdout | Write report to this file (for `markdown`/`json` formats) |
| `--max-file-size` | | `1000000` | Maximum file size in bytes to scan (default 1 MB) |
| `--no-exit-codes` | | `False` | Always exit with code 0 regardless of findings |
| `--version` | `-V` | | Show version and exit |
| `--help` | | | Show help and exit |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully with no CRITICAL or HIGH findings |
| `1` | Invalid arguments, permission error, or I/O failure |
| `2` | Scan completed with one or more HIGH severity findings |
| `3` | Scan completed with one or more CRITICAL severity findings |

Use `--no-exit-codes` to always exit `0` when using `proto_gap` as an advisory tool without breaking CI builds:

```bash
proto-gap ./my-app --output json --no-exit-codes > gaps.json
```

---

## Check Categories

`proto_gap` runs seven independent analysis categories against the repository. Each category uses a combination of regex pattern matching, AST inspection, and file presence checks.

### Authentication

Detects missing or insecure authentication patterns common in AI-generated prototypes.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| AUTH001 | 🔴 CRITICAL | Hardcoded JWT secrets or short application `SECRET_KEY` literals |
| AUTH002 | 🟠 HIGH | Route definitions (`@app.route`, `@router.get`) without visible auth middleware |
| AUTH003 | 🔴 CRITICAL | Hardcoded `password` or `passwd` string literals |
| AUTH004 | 🟠 HIGH | Wildcard CORS policies (`allow_origins=["*"]`) |
| AUTH005 | 🟠 HIGH | Hardcoded API tokens or long key strings |

**Why it matters:** AI-generated prototypes frequently skip authentication entirely or use placeholder secrets that end up committed to version control. These vulnerabilities are trivial to exploit and often lead to complete account takeover or data breaches.

**Common remediation patterns:**
```python
# ❌ Prototype pattern
SECRET_KEY = "hardcoded-secret"

# ✅ Production pattern
import os
SECRET_KEY = os.environ["SECRET_KEY"]  # Fail fast if missing
# or
SECRET_KEY = os.environ.get("SECRET_KEY", "")  # With default
```

---

### Error Handling

Detects poor error handling patterns that mask failures and make production debugging impossible.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| ERR001 | 🟠 HIGH | Bare `except:` clauses (catches `SystemExit`, `KeyboardInterrupt`) |
| ERR002 | 🟡 MEDIUM | `except ... : pass` — silent exception swallowing |
| ERR003 | 🟡 MEDIUM | Errors reported via `print()` instead of `logger.error()` |
| ERR004 | 🟠 HIGH | `raise Exception(...)` — generic base Exception raised directly |
| ERR005 | 🟡 MEDIUM | Functions making I/O/network calls without any `try/except` block |

**Why it matters:** Silent failures in production environments are catastrophic. A bare `except: pass` can hide database connection failures, API timeouts, and data corruption for hours before anyone notices.

**Common remediation patterns:**
```python
# ❌ Prototype pattern
try:
    result = fetch_data(url)
except:
    pass

# ✅ Production pattern
try:
    result = fetch_data(url)
except requests.Timeout as exc:
    logger.error("Fetch timed out for %s: %s", url, exc)
    raise ServiceUnavailableError("External service timeout") from exc
except requests.RequestException as exc:
    logger.exception("Unexpected error fetching %s", url)
    raise
```

---

### Environment Config

Detects hardcoded configuration values and missing environment documentation that cause deployment failures.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| ENV001 | 🟠 HIGH | `DEBUG = True` hardcoded in source code |
| ENV002 | 🟠 HIGH | Hardcoded `DATABASE_URL`, `API_KEY`, `AWS_SECRET`, etc. |
| ENV003 | 🟡 MEDIUM | Missing `.env.example` or `.env.sample` file |
| ENV004 | 🔵 LOW | Missing `.gitignore` file (risk of committing secrets) |
| ENV005 | 🟡 MEDIUM | No `os.environ.get()` usage found (missing env var pattern) |

**Why it matters:** Hardcoded configuration is one of the most common causes of production incidents. Debug mode exposes stack traces to end users. Missing `.gitignore` means `.env` files with real secrets get committed to version control.

**Common remediation patterns:**
```bash
# Create a .env.example (committed to git)
DATABASE_URL=postgresql://user:password@localhost/myapp
DEBUG=false
SECRET_KEY=
API_KEY=

# Create a .env (NOT committed to git — in .gitignore)
DATABASE_URL=postgresql://prod_user:real_password@prod-host/myapp
DEBUG=false
SECRET_KEY=super-long-random-secret-here
```

```python
# Load in application
import os
DATABASE_URL = os.environ["DATABASE_URL"]  # Required — fail fast
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"  # Optional with safe default
```

---

### Security

Detects critical security vulnerabilities commonly introduced by AI code generation.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| SEC001 | 🔴 CRITICAL | `eval()` or `exec()` with potentially user-controlled input |
| SEC002 | 🔴 CRITICAL | `subprocess.run(..., shell=True)` — shell injection risk |
| SEC003 | 🟠 HIGH | `pickle.loads()` / `pickle.load()` — unsafe deserialization |
| SEC004 | 🟠 HIGH | `yaml.load()` without explicit `Loader` — arbitrary code execution |
| SEC005 | 🟠 HIGH | `hashlib.md5()` or `hashlib.sha1()` — broken cryptographic hashes |
| SEC006 | 🟡 MEDIUM | `verify=False` — SSL/TLS certificate verification disabled |
| SEC007 | 🟠 HIGH | Hardcoded `SECRET` or `TOKEN` variable values |
| SEC008 | 🟡 MEDIUM | `random.randint()`, `random.choice()` — non-cryptographic RNG |

**Why it matters:** AI models are trained on vast amounts of code that includes insecure patterns. `eval()` and `exec()` with user input are remote code execution vulnerabilities. `pickle.loads()` from untrusted input can execute arbitrary Python code.

**Common remediation patterns:**
```python
# ❌ Never do this
result = eval(user_input)

# ✅ Use ast.literal_eval() for data parsing
import ast
result = ast.literal_eval(user_input)  # Only parses literals, not arbitrary code

# ❌ Shell injection risk
subprocess.run(f"ls {user_path}", shell=True)

# ✅ Pass as list, shell=False
subprocess.run(["ls", user_path], shell=False, check=True)

# ❌ Broken password hashing
hashed = hashlib.md5(password.encode()).hexdigest()

# ✅ Proper password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# ❌ Non-cryptographic random for tokens
token = str(random.randint(100000, 999999))

# ✅ Cryptographically secure tokens
import secrets
token = secrets.token_urlsafe(32)
```

---

### Database Migrations

Detects missing migration infrastructure that makes production database schema management impossible.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| MIG001 | 🟠 HIGH | Missing Alembic configuration (`alembic.ini`, `migrations/env.py`) |
| MIG002 | 🔴 CRITICAL | `Base.metadata.create_all()` used instead of migration scripts |
| MIG003 | 🟠 HIGH | SQLite database configuration detected |
| MIG004 | 🟡 MEDIUM | `DROP TABLE`, `DROP DATABASE`, or `TRUNCATE TABLE` in application code |
| MIG005 | 🟡 MEDIUM | `engine.execute()` / `connection.execute()` bypassing migration framework |

**Why it matters:** `create_all()` is fine for a prototype but catastrophic in production — it cannot alter existing tables, cannot migrate data, and cannot be rolled back. SQLite cannot handle concurrent writes from multiple application instances.

**Common remediation patterns:**
```bash
# Initialize Alembic
pip install alembic
alembic init migrations

# Configure alembic.ini to use DATABASE_URL from environment
# In alembic/env.py:
# config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])

# Generate your first migration
alembic revision --autogenerate -m "initial schema"

# Apply migrations
alembic upgrade head

# In CI/CD pipeline
alembic upgrade head  # Run before deploying new application code
```

---

### Logging

Detects missing or insufficient logging infrastructure that makes production debugging impossible.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| LOG001 | 🟡 MEDIUM | `print()` used for application output instead of `logger.*()` |
| LOG002 | 🟡 MEDIUM | `logging.basicConfig()` — not suitable for production |
| LOG003 | 🔵 LOW | Missing `logger = logging.getLogger(__name__)` (negated — fires when absent) |
| LOG004 | 🔵 LOW | Root logger used directly (`logging.error()`) instead of module logger |
| LOG005 | 🔵 LOW | f-strings used in logging calls (eager evaluation performance concern) |

**Why it matters:** `print()` output cannot be filtered by log level, routed to log aggregators (CloudWatch, Datadog, ELK), or enriched with request context. In containerized deployments, unstructured stdout output is nearly useless for debugging production incidents.

**Common remediation patterns:**
```python
# ❌ Prototype pattern
print(f"Processing user {user_id}")
print(f"Error: {exc}")

# ✅ Production pattern
import logging

logger = logging.getLogger(__name__)  # Module-level logger

logger.info("Processing user %s", user_id)       # Lazy formatting
logger.error("Failed to process user: %s", exc)   # Not f-string
logger.exception("Unexpected error")               # Includes traceback

# ✅ Production logging configuration (in app startup)
import logging.config

logging.config.dictConfig({
    "version": 1,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        }
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "json"}
    },
    "root": {"level": "INFO", "handlers": ["console"]},
})
```

---

### Testing

Detects missing test infrastructure that makes safe iteration and deployment impossible.

| Rule | Severity | What it detects |
|------|----------|-----------------|
| TST001 | 🟠 HIGH | No test files matching pytest conventions found |
| TST002 | 🟡 MEDIUM | No test runner configuration (`pyproject.toml`, `pytest.ini`, `setup.cfg`) |
| TST003 | 🔵 LOW | No `def test_` functions found anywhere (negated — fires when absent) |
| TST004 | 🟡 MEDIUM | Skipped tests (`@pytest.mark.skip`, `@unittest.skip`) detected |
| TST005 | 🔵 LOW | No CI/CD pipeline configuration found |

**Why it matters:** AI-generated prototypes rarely include tests. Without automated tests, every deployment is a gamble, refactoring is impossible, and regressions are discovered by end users rather than automated checks.

**Common remediation patterns:**
```python
# tests/test_api.py
import pytest
from myapp import create_app

@pytest.fixture()
def client():
    app = create_app(testing=True)
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200

def test_requires_auth(client):
    response = client.get("/admin")
    assert response.status_code == 401  # Should reject unauthenticated requests
```

```toml
# pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = ["--strict-markers", "-v"]
```

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[dev]"
      - run: pytest --cov
```

---

## Example Output

### Terminal Output

```
Scanning /path/to/my-prototype ...
╭─────────────────────────────────────────────────────────────────╮
│            proto_gap Production-Readiness Report                 │
│                                                                  │
│  Repository:    /path/to/my-prototype                            │
│  Files scanned: 8                                                │
│  Total findings: 18                                              │
│    CRITICAL: 4   HIGH: 7   MEDIUM: 5   LOW: 2                   │
╰─────────────────────────────────────────────────────────────────╯

              Findings Summary               
╭────┬──────────┬─────────┬──────────────────┬───────────────────────────────────────────┬──────────────────────────────────╮
│ #  │ Severity │ Rule    │ Category         │ Title                                     │ Location                         │
├────┼──────────┼─────────┼──────────────────┼───────────────────────────────────────────┼──────────────────────────────────┤
│ 1  │ CRITICAL │ AUTH001 │ Authentication   │ Hardcoded JWT/secret key detected         │ settings.py:1                    │
│ 2  │ CRITICAL │ SEC001  │ Security         │ Dynamic code execution via eval()         │ app.py:28                        │
│ 3  │ CRITICAL │ MIG002  │ Database Migrat… │ create_all() used instead of migrations   │ database.py:12                   │
│ 4  │ HIGH     │ ERR001  │ Error Handling   │ Bare except clause detected               │ utils.py:5                       │
│ …  │ …        │ …       │ …                │ …                                         │ …                                │
╰────┴──────────┴─────────┴──────────────────┴───────────────────────────────────────────┴──────────────────────────────────╯

─────────────────────────────────── Detailed Findings ──────────────

  ▸ [CRITICAL][AUTH001] 1. Hardcoded JWT/secret key detected
    Authentication
    📁 Location: settings.py:1
    📋 Issue:  A short or hardcoded JWT secret or application secret key was found...
    🔧 Fix:   Move secret keys to environment variables and load them with os.environ...
```

### Markdown Output

```markdown
# proto_gap Production-Readiness Report

> Generated by **proto_gap** static analysis

**Repository:** `/path/to/my-prototype`  
**Files scanned:** 8  
**Total findings:** 18  

## Summary

| Severity | Count |
|:---------|------:|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 7 |
| 🟡 MEDIUM | 5 |
| 🔵 LOW | 2 |

## Findings

Each item below is an actionable gap. Check the box when resolved.

### Authentication

- [ ] 🔴 **[CRITICAL]** `AUTH001` Hardcoded JWT/secret key detected
  - 📁 **Location:** `settings.py:1`
  - 📋 **Issue:** A short or hardcoded JWT secret or application secret key was found...
  - 🔧 **Fix:** Move secret keys to environment variables and load them with os.environ...

### Security

- [ ] 🔴 **[CRITICAL]** `SEC001` Dynamic code execution via eval()/exec() detected
  - 📁 **Location:** `app.py:28`
  - 📋 **Issue:** Use of eval() or exec() with potentially user-controlled input...
  - 🔧 **Fix:** Remove eval()/exec() and replace with safe alternatives...
```

### JSON Output

```json
{
  "repo_path": "/path/to/my-prototype",
  "total_findings": 18,
  "summary": {
    "critical": 4,
    "high": 7,
    "medium": 5,
    "low": 2
  },
  "scanned_files": [
    "/path/to/my-prototype/app.py",
    "/path/to/my-prototype/settings.py"
  ],
  "errors": [],
  "findings": [
    {
      "category": "Authentication",
      "severity": "CRITICAL",
      "title": "Hardcoded JWT/secret key detected",
      "description": "A short or hardcoded JWT secret or application secret key...",
      "remediation": "Move secret keys to environment variables...",
      "file_path": "/path/to/my-prototype/settings.py",
      "line_number": 1,
      "rule_id": "AUTH001"
    }
  ]
}
```

---

## Severity Levels

| Level | Emoji | Meaning | Typical Action |
|-------|-------|---------|----------------|
| **CRITICAL** | 🔴 | Active security vulnerability or data loss risk. Block production deployment. | Fix immediately before any deployment |
| **HIGH** | 🟠 | Significant gap that will cause production incidents or security issues. | Fix in the current sprint before go-live |
| **MEDIUM** | 🟡 | Important improvement that reduces operational risk or technical debt. | Schedule in the backlog within 2 sprints |
| **LOW** | 🔵 | Best practice deviation with low immediate risk. | Address when refactoring the affected area |

---

## Rule Reference

All rules follow the format `CATEGORY + 3-digit number` (e.g. `AUTH001`, `SEC003`).

### Authentication Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| AUTH001 | CRITICAL | Regex | Hardcoded JWT/SECRET_KEY literal |
| AUTH002 | HIGH | Regex | Route definition without auth middleware |
| AUTH003 | CRITICAL | Regex | Hardcoded password literal |
| AUTH004 | HIGH | Regex | Wildcard CORS policy |
| AUTH005 | HIGH | Regex | Hardcoded API token or key |

### Error Handling Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| ERR001 | HIGH | AST | Bare `except:` clause |
| ERR002 | MEDIUM | AST | `except ... : pass` silent handler |
| ERR003 | MEDIUM | Regex | Error reported via `print()` |
| ERR004 | HIGH | Regex | `raise Exception(...)` generic raise |
| ERR005 | MEDIUM | AST | Function with external calls and no try/except |

### Environment Config Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| ENV001 | HIGH | Regex | `DEBUG = True` in source |
| ENV002 | HIGH | Regex | Hardcoded connection string or credential |
| ENV003 | MEDIUM | File | Missing `.env.example` / `.env.sample` |
| ENV004 | LOW | File | Missing `.gitignore` |
| ENV005 | MEDIUM | Regex | No `os.environ.get()` usage found (negated) |

### Security Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| SEC001 | CRITICAL | Regex | `eval()` or `exec()` detected |
| SEC002 | CRITICAL | Regex | `subprocess(..., shell=True)` |
| SEC003 | HIGH | Regex | `pickle.loads()` / `pickle.load()` |
| SEC004 | HIGH | Regex | `yaml.load()` without safe Loader |
| SEC005 | HIGH | Regex | `hashlib.md5()` or `hashlib.sha1()` |
| SEC006 | MEDIUM | Regex | `verify=False` SSL bypass |
| SEC007 | HIGH | Regex | Hardcoded SECRET or TOKEN value |
| SEC008 | MEDIUM | Regex | Non-cryptographic `random.*()` usage |

### Database Migration Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| MIG001 | HIGH | File | No Alembic configuration found |
| MIG002 | CRITICAL | Regex | `Base.metadata.create_all()` detected |
| MIG003 | HIGH | Regex | SQLite URL or `:memory:` detected |
| MIG004 | MEDIUM | Regex | `DROP TABLE` / `TRUNCATE` in source |
| MIG005 | MEDIUM | Regex | Raw `engine.execute()` bypassing migrations |

### Logging Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| LOG001 | MEDIUM | Regex | `print()` used for application output |
| LOG002 | MEDIUM | Regex | `logging.basicConfig()` used |
| LOG003 | LOW | Regex | No `logging.getLogger(__name__)` found (negated) |
| LOG004 | LOW | Regex | Root logger used directly |
| LOG005 | LOW | Regex | f-string in logging call |

### Testing Rules

| ID | Severity | Type | Description |
|----|----------|------|-------------|
| TST001 | HIGH | File | No test files found |
| TST002 | MEDIUM | File | No test runner configuration |
| TST003 | LOW | Regex | No `def test_` functions found (negated) |
| TST004 | MEDIUM | Regex | Skipped tests detected |
| TST005 | LOW | File | No CI/CD pipeline configuration |

---

## Extending proto_gap

`proto_gap` is designed to be extensible. You can add custom rules to the registry in `proto_gap/rules.py` or pass extra analyzer functions programmatically.

### Adding a Custom Regex Rule

Add a new `RegexRule` to the appropriate category list in `proto_gap/rules.py`:

```python
from proto_gap.rules import RegexRule, AUTH_RULES
from proto_gap.models import Category, Severity

# Detect hardcoded Stripe test keys
AUTH_RULES.append(
    RegexRule(
        rule_id="AUTH006",
        category=Category.AUTHENTICATION,
        severity=Severity.CRITICAL,
        pattern=r"sk_test_[A-Za-z0-9]{24,}",
        title="Hardcoded Stripe test key detected",
        description="A Stripe test secret key is hardcoded in source code.",
        remediation="Load the Stripe key from an environment variable: STRIPE_SECRET_KEY.",
        file_extensions=[".py", ".js", ".ts"],
    )
)
```

### Using Extra Analyzers Programmatically

Pass custom analyzer functions to the `Scanner` or `scan_repository()` function:

```python
from pathlib import Path
from proto_gap.scanner import scan_repository
from proto_gap.models import Category, Finding, Severity

def my_custom_analyzer(files: list[Path], repo_root: Path) -> list[Finding]:
    """Custom analyzer that checks for TODO comments."""
    findings = []
    for file_path in files:
        if file_path.suffix != ".py":
            continue
        source = file_path.read_text(encoding="utf-8", errors="replace")
        if "# TODO" in source or "# FIXME" in source:
            findings.append(
                Finding(
                    category=Category.TESTING,
                    severity=Severity.LOW,
                    title="TODO/FIXME comments found",
                    description="Unresolved TODO or FIXME comments indicate incomplete implementation.",
                    remediation="Resolve all TODO/FIXME comments before production deployment.",
                    file_path=file_path,
                    rule_id="CUSTOM001",
                )
            )
    return findings

report = scan_repository(
    Path("./my-prototype"),
    extra_analyzers=[my_custom_analyzer],
)
```

### Adding a Custom AST Rule

For AST-based checks, add an `ASTRule` to the registry and implement the hook in `proto_gap/analyzers.py`:

```python
# In rules.py
ASTRule(
    rule_id="ERR006",
    category=Category.ERROR_HANDLING,
    severity=Severity.MEDIUM,
    node_type="FunctionDef",
    title="Async function without timeout",
    description="Async functions making HTTP calls should have explicit timeouts.",
    remediation="Add a timeout parameter to all HTTP client calls.",
    hook="async_no_timeout",
)

# In analyzers.py, add to _visit_ast():
elif rule.hook == "async_no_timeout":
    findings.extend(_hook_async_no_timeout(rule, tree, file_path))
```

---

## Development

### Setup

```bash
git clone https://github.com/example/proto_gap.git
cd proto_gap
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=proto_gap --cov-report=term-missing

# Run a specific test module
pytest tests/test_analyzers.py -v

# Run a specific test class
pytest tests/test_scanner.py::TestScannerScan -v

# Run tests matching a keyword
pytest -k "authentication" -v
```

### Project Structure

```
proto_gap/
├── __init__.py          # Package init, version constant, re-exports
├── cli.py               # Typer CLI entry point
├── scanner.py           # Scanner orchestration (walks repo, runs analyzers)
├── analyzers.py         # Individual analyzer functions per category
├── models.py            # Severity, Category, Finding, ScanReport dataclasses
├── renderer.py          # Terminal, Markdown, and JSON renderers
└── rules.py             # Declarative rule registry (RegexRule, ASTRule, FilePresenceRule)

tests/
├── __init__.py
├── test_models.py       # Unit tests for data models
├── test_rules.py        # Unit tests for rule registry
├── test_analyzers.py    # Unit tests for each analyzer function
├── test_scanner.py      # Integration tests for full scanner pipeline
├── test_renderer.py     # Tests for all three output renderers
└── fixtures/
    └── sample_prototype/
        ├── app.py           # Synthetic prototype with intentional gaps
        └── requirements.txt # Fixture requirements file
```

### Running proto_gap on Itself

```bash
# Dogfood: scan the proto_gap source code
proto-gap . --output terminal

# Generate a self-analysis report
proto-gap . --output markdown --output-file self-analysis.md
```

### Code Style

The project uses:
- **ruff** for linting (configured in `pyproject.toml`)
- **Type hints** on all public functions
- **Docstrings** on all public functions and classes

```bash
# Lint
pip install ruff
ruff check proto_gap/

# Type check
pip install mypy
mypy proto_gap/
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository and create a feature branch.
2. Add tests for any new rules, analyzers, or features.
3. Ensure all existing tests pass: `pytest`.
4. Follow the existing code style (type hints, docstrings, PEP 8).
5. Open a pull request with a clear description of the change.

### Adding a New Rule

1. Add the rule definition to the appropriate category list in `proto_gap/rules.py`.
2. Assign a unique rule ID following the `CATEGORY###` format.
3. Add a test to `tests/test_rules.py` verifying the rule is registered.
4. Add a test to `tests/test_analyzers.py` with a synthetic code snippet that triggers the rule.
5. Update the [Rule Reference](#rule-reference) table in this README.

### Reporting Issues

Please open a GitHub issue with:
- The `proto_gap` version (`proto-gap --version`)
- The command you ran
- Expected vs. actual output
- A minimal code snippet that demonstrates the issue (if applicable)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built to bridge the gap between AI-empowered prototyping and production-grade engineering.*

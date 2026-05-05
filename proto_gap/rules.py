"""Declarative rule registry for proto_gap static analysis checks.

Provides a registry of pattern-based rules (regex patterns and AST hook
descriptors) organized by category. Analyzers consume these rules to
produce Finding objects without embedding patterns directly in analysis logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from proto_gap.models import Category, Severity


@dataclass
class RegexRule:
    """A rule that matches source text using a regular expression pattern.

    Attributes:
        rule_id: Unique identifier for this rule.
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        pattern: Regular expression pattern to search for.
        title: Short title for findings produced by this rule.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        file_extensions: File extensions this rule applies to (empty = all).
        negate: If True, a finding is produced when the pattern is NOT found.
    """

    rule_id: str
    category: Category
    severity: Severity
    pattern: str
    title: str
    description: str
    remediation: str
    file_extensions: list[str] = field(default_factory=list)
    negate: bool = False


@dataclass
class ASTRule:
    """A rule that triggers on specific AST node types or patterns.

    Attributes:
        rule_id: Unique identifier for this rule.
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        node_type: AST node type name to inspect (e.g. 'Try', 'FunctionDef').
        title: Short title for findings produced by this rule.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        hook: String key identifying the AST visitor logic in analyzers.
    """

    rule_id: str
    category: Category
    severity: Severity
    node_type: str
    title: str
    description: str
    remediation: str
    hook: str


@dataclass
class FilePresenceRule:
    """A rule that checks for the presence or absence of specific files.

    Attributes:
        rule_id: Unique identifier for this rule.
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        filename_patterns: Glob patterns for files to search for.
        title: Short title for findings produced when the file is missing.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        expect_present: If True, finding is raised when file is ABSENT.
    """

    rule_id: str
    category: Category
    severity: Severity
    filename_patterns: list[str]
    title: str
    description: str
    remediation: str
    expect_present: bool = True


# ---------------------------------------------------------------------------
# Authentication rules
# ---------------------------------------------------------------------------

AUTH_RULES: list[RegexRule | ASTRule] = [
    RegexRule(
        rule_id="AUTH001",
        category=Category.AUTHENTICATION,
        severity=Severity.CRITICAL,
        pattern=r"\bJWT_SECRET\s*=\s*['\"][^'\"]{1,20}['\"]|\bSECRET_KEY\s*=\s*['\"](?!os\.environ)[^'\"]{1,30}['\"]",
        title="Hardcoded JWT/secret key detected",
        description=(
            "A short or hardcoded JWT secret or application secret key was found "
            "directly in source code. Attackers can forge tokens or session cookies."
        ),
        remediation=(
            "Move secret keys to environment variables and load them with "
            "os.environ or a secrets manager. Minimum recommended secret length is 32 bytes."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="AUTH002",
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        pattern=r"@app\.route|@router\.(get|post|put|delete|patch)",
        title="Route definition found — verify authentication middleware",
        description=(
            "HTTP route handlers were detected. Prototype routes often lack "
            "authentication/authorization middleware, exposing endpoints publicly."
        ),
        remediation=(
            "Ensure all sensitive routes are protected with an authentication decorator "
            "or dependency (e.g. @login_required, Depends(get_current_user))."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="AUTH003",
        category=Category.AUTHENTICATION,
        severity=Severity.CRITICAL,
        pattern=r"password\s*=\s*['\"][^'\"]+['\"]|passwd\s*=\s*['\"][^'\"]+['\"]",
        title="Hardcoded password literal detected",
        description=(
            "A password value is hardcoded as a string literal in source code. "
            "This is a critical security vulnerability."
        ),
        remediation=(
            "Remove the hardcoded password and load credentials from environment "
            "variables or a secrets management service."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="AUTH004",
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        pattern=r"allow_any_origin|CORS.*allow_origins.*\*|Access-Control-Allow-Origin.*\*",
        title="Wildcard CORS policy detected",
        description=(
            "A wildcard (*) CORS policy was found, allowing any origin to make "
            "credentialed cross-origin requests to this service."
        ),
        remediation=(
            "Restrict CORS origins to a specific allowlist of trusted domains "
            "instead of using the wildcard '*'."
        ),
        file_extensions=[".py", ".js", ".ts"],
    ),
]

# ---------------------------------------------------------------------------
# Error handling rules
# ---------------------------------------------------------------------------

ERROR_HANDLING_RULES: list[RegexRule | ASTRule] = [
    ASTRule(
        rule_id="ERR001",
        category=Category.ERROR_HANDLING,
        severity=Severity.HIGH,
        node_type="ExceptHandler",
        title="Bare except clause detected",
        description=(
            "A bare 'except:' clause was found, which catches all exceptions "
            "including SystemExit and KeyboardInterrupt. This masks errors and "
            "makes debugging extremely difficult."
        ),
        remediation=(
            "Replace bare 'except:' with 'except Exception as e:' or a specific "
            "exception type, and log or re-raise appropriately."
        ),
        hook="bare_except",
    ),
    ASTRule(
        rule_id="ERR002",
        category=Category.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        node_type="ExceptHandler",
        title="Silent exception handler detected",
        description=(
            "An except block was found that catches exceptions but contains only "
            "a 'pass' statement, silently swallowing errors without logging or "
            "re-raising them."
        ),
        remediation=(
            "Add logging (e.g. logger.exception(e)) or re-raise the exception in "
            "the except block to avoid silently hiding failures."
        ),
        hook="silent_except",
    ),
    RegexRule(
        rule_id="ERR003",
        category=Category.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        pattern=r"print\s*\(.*[Ee]rror|print\s*\(.*[Ee]xcep|print\s*\(.*traceback",
        title="Error reported via print() instead of logging",
        description=(
            "Errors or exceptions are being reported using print() rather than a "
            "structured logging framework, which is not suitable for production."
        ),
        remediation=(
            "Replace print() error reporting with logger.error() or logger.exception() "
            "using the standard logging module or a structured logger."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="ERR004",
        category=Category.ERROR_HANDLING,
        severity=Severity.HIGH,
        pattern=r"raise\s+Exception\s*\(",
        title="Generic Exception raised directly",
        description=(
            "Code raises the base Exception class directly rather than a specific "
            "exception type, making error handling by callers imprecise."
        ),
        remediation=(
            "Define and raise specific exception subclasses that convey meaningful "
            "error semantics (e.g. ValueError, PermissionError, or custom domain exceptions)."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Environment configuration rules
# ---------------------------------------------------------------------------

ENV_CONFIG_RULES: list[RegexRule | FilePresenceRule] = [
    RegexRule(
        rule_id="ENV001",
        category=Category.ENV_CONFIG,
        severity=Severity.HIGH,
        pattern=r"DEBUG\s*=\s*True|debug\s*=\s*True",
        title="Debug mode enabled in source code",
        description=(
            "DEBUG=True is set directly in source code. Running in debug mode "
            "in production exposes stack traces and internal details to users."
        ),
        remediation=(
            "Load the DEBUG flag from an environment variable: "
            "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'"
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="ENV002",
        category=Category.ENV_CONFIG,
        severity=Severity.HIGH,
        pattern=r"(?:DATABASE_URL|DB_PASSWORD|DB_HOST|REDIS_URL|API_KEY|AWS_SECRET)\s*=\s*['\"][^'\"]+['\"]",
        title="Hardcoded service connection string or credential",
        description=(
            "A service URL, database password, or API key appears to be hardcoded "
            "as a string literal. Committing credentials to source control is a "
            "critical security risk."
        ),
        remediation=(
            "Move all credentials and connection strings to environment variables "
            "or a .env file (excluded from version control) and load with os.environ."
        ),
        file_extensions=[".py", ".js", ".ts", ".yaml", ".yml"],
    ),
    FilePresenceRule(
        rule_id="ENV003",
        category=Category.ENV_CONFIG,
        severity=Severity.MEDIUM,
        filename_patterns=[".env.example", ".env.sample", ".env.template"],
        title="No .env example file found",
        description=(
            "No .env.example or .env.sample file was found. Without a documented "
            "environment variable template, developers onboarding to the project "
            "won't know which variables to configure."
        ),
        remediation=(
            "Create a .env.example file listing all required environment variables "
            "with placeholder values and commit it to version control."
        ),
        expect_present=True,
    ),
    FilePresenceRule(
        rule_id="ENV004",
        category=Category.ENV_CONFIG,
        severity=Severity.LOW,
        filename_patterns=[".gitignore"],
        title="No .gitignore file found",
        description=(
            "No .gitignore file was found in the repository. This increases the "
            "risk of accidentally committing secrets, virtual environments, or "
            "compiled files to version control."
        ),
        remediation=(
            "Add a .gitignore file that excludes .env, __pycache__, .venv, "
            "*.pyc, and other sensitive or generated files."
        ),
        expect_present=True,
    ),
]

# ---------------------------------------------------------------------------
# Security rules
# ---------------------------------------------------------------------------

SECURITY_RULES: list[RegexRule] = [
    RegexRule(
        rule_id="SEC001",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        pattern=r"eval\s*\(|exec\s*\(",
        title="Dynamic code execution via eval()/exec() detected",
        description=(
            "Use of eval() or exec() with potentially user-controlled input "
            "can lead to arbitrary code execution vulnerabilities."
        ),
        remediation=(
            "Remove eval()/exec() and replace with safe alternatives. If dynamic "
            "evaluation is required, strictly validate and sanitize all inputs first."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC002",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        pattern=r"subprocess\.(?:call|run|Popen|check_output).*shell\s*=\s*True",
        title="Shell injection risk: subprocess with shell=True",
        description=(
            "subprocess functions called with shell=True and potentially "
            "user-controlled arguments create shell injection vulnerabilities."
        ),
        remediation=(
            "Use shell=False (default) and pass arguments as a list. "
            "If shell=True is necessary, ensure all inputs are strictly validated."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC003",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        pattern=r"pickle\.loads?\s*\(|pickle\.load\s*\(",
        title="Unsafe deserialization via pickle detected",
        description=(
            "pickle.load/loads() deserializes arbitrary Python objects, which can "
            "execute malicious code if the input comes from an untrusted source."
        ),
        remediation=(
            "Avoid using pickle for data received from external sources. "
            "Use safer formats like JSON or implement cryptographic signing for pickle data."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC004",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        pattern=r"yaml\.load\s*\([^)]*\)(?!.*Loader)|yaml\.load\s*\([^,)]+\s*\)",
        title="Unsafe YAML deserialization detected",
        description=(
            "yaml.load() without an explicit Loader argument uses the unsafe FullLoader "
            "by default in older PyYAML versions, enabling arbitrary code execution."
        ),
        remediation=(
            "Replace yaml.load() with yaml.safe_load() for untrusted input, "
            "or explicitly pass Loader=yaml.SafeLoader."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC005",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        pattern=r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
        title="Weak cryptographic hash function (MD5/SHA1) detected",
        description=(
            "MD5 and SHA1 are cryptographically broken and should not be used for "
            "security-sensitive operations like password hashing or integrity checks."
        ),
        remediation=(
            "Use SHA-256 or stronger (hashlib.sha256) for general hashing. "
            "For password hashing, use bcrypt, argon2, or hashlib.scrypt."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC006",
        category=Category.SECURITY,
        severity=Severity.MEDIUM,
        pattern=r"verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_SSL\s*=\s*False",
        title="SSL/TLS certificate verification disabled",
        description=(
            "SSL certificate verification is explicitly disabled, making the "
            "application vulnerable to man-in-the-middle attacks."
        ),
        remediation=(
            "Remove verify=False and use proper certificate verification. "
            "If using self-signed certs in development, provide the CA bundle path instead."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Database migration rules
# ---------------------------------------------------------------------------

MIGRATION_RULES: list[FilePresenceRule | RegexRule] = [
    FilePresenceRule(
        rule_id="MIG001",
        category=Category.MIGRATIONS,
        severity=Severity.HIGH,
        filename_patterns=["alembic.ini", "migrations/env.py", "alembic/env.py"],
        title="No database migration tool configuration found",
        description=(
            "No Alembic configuration was found. Without a migration tool, "
            "schema changes must be applied manually and cannot be version-controlled "
            "or rolled back safely."
        ),
        remediation=(
            "Initialize Alembic with 'alembic init migrations' and configure it to "
            "use your database URL from environment variables."
        ),
        expect_present=True,
    ),
    RegexRule(
        rule_id="MIG002",
        category=Category.MIGRATIONS,
        severity=Severity.CRITICAL,
        pattern=r"Base\.metadata\.create_all|metadata\.create_all",
        title="create_all() used instead of migration scripts",
        description=(
            "Base.metadata.create_all() is typically used in prototypes to create "
            "database tables directly. This approach does not support incremental "
            "schema changes or rollbacks in production."
        ),
        remediation=(
            "Replace create_all() with proper migration scripts managed by Alembic "
            "or another migration tool. Use create_all() only for test databases."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="MIG003",
        category=Category.MIGRATIONS,
        severity=Severity.HIGH,
        pattern=r"sqlite:///|:memory:",
        title="SQLite database configuration detected",
        description=(
            "SQLite is detected as the database backend. SQLite is not suitable "
            "for production workloads requiring concurrent writes or horizontal scaling."
        ),
        remediation=(
            "Switch to PostgreSQL or another production-grade database. "
            "Configure the DATABASE_URL environment variable to point to the production DB."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Logging rules
# ---------------------------------------------------------------------------

LOGGING_RULES: list[RegexRule | FilePresenceRule] = [
    RegexRule(
        rule_id="LOG001",
        category=Category.LOGGING,
        severity=Severity.MEDIUM,
        pattern=r"^(?!.*import logging|.*from logging|.*logger).*\bprint\s*\(",
        title="print() used instead of structured logging",
        description=(
            "Application output is written using print() rather than a structured "
            "logging framework. print() output cannot be filtered by log level, "
            "routed to log aggregators, or enriched with contextual metadata."
        ),
        remediation=(
            "Replace print() calls with logger.info(), logger.debug(), etc. using "
            "the standard logging module configured with appropriate handlers and formatters."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="LOG002",
        category=Category.LOGGING,
        severity=Severity.MEDIUM,
        pattern=r"logging\.basicConfig|basicConfig\s*\(",
        title="Logging configured with basicConfig (not production-ready)",
        description=(
            "logging.basicConfig() is a simple configuration method suitable for "
            "scripts and development but lacks the structured output, JSON formatting, "
            "and log rotation needed for production."
        ),
        remediation=(
            "Configure logging with dictConfig or a library like structlog or "
            "python-json-logger to produce structured JSON logs suitable for log aggregation."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="LOG003",
        category=Category.LOGGING,
        severity=Severity.LOW,
        pattern=r"logging\.getLogger\(__name__\)",
        title="Module-level logger correctly defined",
        description="Module-level logger using __name__ is present — this is the correct pattern.",
        remediation="No action required. This is a best practice.",
        negate=True,
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Testing rules
# ---------------------------------------------------------------------------

TESTING_RULES: list[FilePresenceRule | RegexRule] = [
    FilePresenceRule(
        rule_id="TST001",
        category=Category.TESTING,
        severity=Severity.HIGH,
        filename_patterns=["test_*.py", "*_test.py", "tests/*.py", "test/*.py"],
        title="No test files found in repository",
        description=(
            "No test files matching standard pytest conventions were found. "
            "Without automated tests, regressions cannot be detected and "
            "refactoring is risky."
        ),
        remediation=(
            "Add a tests/ directory with pytest test files. Aim for at least "
            "smoke tests covering critical business logic and API endpoints."
        ),
        expect_present=True,
    ),
    FilePresenceRule(
        rule_id="TST002",
        category=Category.TESTING,
        severity=Severity.MEDIUM,
        filename_patterns=["pytest.ini", "setup.cfg", "pyproject.toml"],
        title="No test runner configuration found",
        description=(
            "No pytest configuration file was found. Without explicit test "
            "configuration, CI systems may not know how to discover and run tests."
        ),
        remediation=(
            "Add a [tool.pytest.ini_options] section to pyproject.toml or a "
            "pytest.ini file specifying the test paths and any required plugins."
        ),
        expect_present=True,
    ),
    RegexRule(
        rule_id="TST003",
        category=Category.TESTING,
        severity=Severity.LOW,
        pattern=r"def test_",
        title="Test functions present",
        description="Test function definitions using the test_ prefix were found.",
        remediation="No action required. Ensure coverage is sufficient for critical paths.",
        negate=True,
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Unified registry
# ---------------------------------------------------------------------------

ALL_RULES: list[RegexRule | ASTRule | FilePresenceRule] = (
    AUTH_RULES
    + ERROR_HANDLING_RULES
    + ENV_CONFIG_RULES
    + SECURITY_RULES
    + MIGRATION_RULES
    + LOGGING_RULES
    + TESTING_RULES
)


def get_rules_by_category(
    category: Category,
) -> list[RegexRule | ASTRule | FilePresenceRule]:
    """Return all rules belonging to the specified category.

    Args:
        category: The Category enum value to filter by.

    Returns:
        List of rules whose category matches the requested category.
    """
    return [rule for rule in ALL_RULES if rule.category == category]


def get_rule_by_id(rule_id: str) -> Optional[RegexRule | ASTRule | FilePresenceRule]:
    """Look up a specific rule by its unique identifier.

    Args:
        rule_id: The unique rule identifier string (e.g. 'AUTH001').

    Returns:
        The matching rule, or None if no rule with that ID exists.
    """
    for rule in ALL_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None

"""Declarative rule registry for proto_gap static analysis checks.

Provides a registry of pattern-based rules (regex patterns and AST hook
descriptors) organized by category. Analyzers consume these rules to
produce Finding objects without embedding patterns directly in analysis logic.

Rule types:
- RegexRule: matches source text using a compiled regular expression
- ASTRule: triggers on specific AST node types via named hooks in analyzers
- FilePresenceRule: checks for the presence or absence of specific files

All rules are collected into ALL_RULES and can be filtered by category
using get_rules_by_category() or looked up by ID using get_rule_by_id().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from proto_gap.models import Category, Severity


@dataclass
class RegexRule:
    """A rule that matches source text using a regular expression pattern.

    Attributes:
        rule_id: Unique identifier for this rule (e.g. 'AUTH001').
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        pattern: Regular expression pattern string to search for.
        title: Short title for findings produced by this rule.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        file_extensions: File extensions this rule applies to (e.g. ['.py']).
            An empty list means the rule applies to all files.
        negate: If True, a finding is produced when NO match is found
            across all applicable files (used for "missing best practice" checks).
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

    AST rules are applied only to Python (.py) files and rely on named
    hook implementations in the analyzer functions to perform the actual
    tree walking logic.

    Attributes:
        rule_id: Unique identifier for this rule (e.g. 'ERR001').
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        node_type: AST node type name to inspect (e.g. 'ExceptHandler').
        title: Short title for findings produced by this rule.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        hook: String key identifying the AST visitor logic in analyzers.
            The analyzer's _visit_ast() function dispatches on this value.
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

    File presence rules search the entire repository tree for files matching
    any of the given glob patterns and raise a finding based on whether
    the file was found or not.

    Attributes:
        rule_id: Unique identifier for this rule (e.g. 'ENV003').
        category: The check category this rule belongs to.
        severity: Severity level of findings produced by this rule.
        filename_patterns: Glob patterns for files to search for
            (e.g. ['.env.example', '.env.sample']).
        title: Short title for findings produced by this rule.
        description: Detailed description of the issue.
        remediation: Actionable remediation hint.
        expect_present: If True (default), a finding is raised when no
            matching file is found. If False, a finding is raised when a
            matching file IS found.
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

AUTH_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    RegexRule(
        rule_id="AUTH001",
        category=Category.AUTHENTICATION,
        severity=Severity.CRITICAL,
        pattern=(
            r"JWT_SECRET\s*=\s*['\"][^'\"]{1,20}['\"]|"
            r"SECRET_KEY\s*=\s*['\"](?!os\.environ)[^'\"]{1,30}['\"]"
        ),
        title="Hardcoded JWT/secret key detected",
        description=(
            "A short or hardcoded JWT secret or application secret key was found "
            "directly in source code. Attackers can forge tokens or session cookies "
            "if they can read the source or binary."
        ),
        remediation=(
            "Move secret keys to environment variables and load them with "
            "os.environ or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault). "
            "Minimum recommended secret length is 32 random bytes."
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
            "authentication/authorization middleware, exposing endpoints publicly "
            "without any access control."
        ),
        remediation=(
            "Ensure all sensitive routes are protected with an authentication decorator "
            "or dependency injection (e.g. @login_required, Depends(get_current_user)). "
            "Apply authentication at the router or middleware level where possible."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="AUTH003",
        category=Category.AUTHENTICATION,
        severity=Severity.CRITICAL,
        pattern=r"(?i)password\s*=\s*['\"][^'\"]+['\"]|(?i)passwd\s*=\s*['\"][^'\"]+['\"]",
        title="Hardcoded password literal detected",
        description=(
            "A password value is hardcoded as a string literal in source code. "
            "This is a critical security vulnerability that exposes credentials to "
            "anyone with access to the repository or compiled binary."
        ),
        remediation=(
            "Remove the hardcoded password immediately. Load credentials from "
            "environment variables (os.environ['DB_PASSWORD']) or a secrets management "
            "service. Never commit credentials to version control."
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
            "credentialed cross-origin requests to this service. This can enable "
            "cross-site request forgery and data exfiltration from authenticated users."
        ),
        remediation=(
            "Restrict CORS origins to a specific allowlist of trusted domains "
            "instead of using the wildcard '*'. Configure allowed origins from "
            "an environment variable (e.g. ALLOWED_ORIGINS=https://app.example.com)."
        ),
        file_extensions=[".py", ".js", ".ts"],
    ),
    RegexRule(
        rule_id="AUTH005",
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        pattern=r"token\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]|api_key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        title="Hardcoded API token or key detected",
        description=(
            "An API token or key appears to be hardcoded as a string literal. "
            "Hardcoded tokens committed to source control can be harvested by "
            "malicious actors or exposed through log files."
        ),
        remediation=(
            "Store API tokens in environment variables or a secrets manager. "
            "Rotate any tokens that may have been committed to version control history. "
            "Consider using git-secrets or pre-commit hooks to prevent future leaks."
        ),
        file_extensions=[".py", ".js", ".ts"],
    ),
]

# ---------------------------------------------------------------------------
# Error handling rules
# ---------------------------------------------------------------------------

ERROR_HANDLING_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    ASTRule(
        rule_id="ERR001",
        category=Category.ERROR_HANDLING,
        severity=Severity.HIGH,
        node_type="ExceptHandler",
        title="Bare except clause detected",
        description=(
            "A bare 'except:' clause was found, which catches all exceptions "
            "including SystemExit and KeyboardInterrupt. This masks errors and "
            "makes debugging extremely difficult in production."
        ),
        remediation=(
            "Replace bare 'except:' with 'except Exception as e:' or a specific "
            "exception type. Always log or re-raise the exception to avoid hiding failures. "
            "Use 'except (TypeError, ValueError) as e:' for multiple specific types."
        ),
        hook="bare_except",
    ),
    ASTRule(
        rule_id="ERR002",
        category=Category.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        node_type="ExceptHandler",
        title="Silent exception handler (pass) detected",
        description=(
            "An except block was found that catches exceptions but contains only "
            "a 'pass' statement, silently swallowing errors without logging or "
            "re-raising them. Silent failures are extremely difficult to diagnose "
            "in production environments."
        ),
        remediation=(
            "Add logging (e.g. logger.exception(e)) or re-raise the exception in "
            "the except block to avoid silently hiding failures. If the exception "
            "is truly expected and safe to ignore, add a comment explaining why."
        ),
        hook="silent_except",
    ),
    RegexRule(
        rule_id="ERR003",
        category=Category.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        pattern=r"print\s*\(.*[Ee]rror|print\s*\(.*[Ee]xcep|print\s*\(.*[Tt]raceback",
        title="Error reported via print() instead of logging",
        description=(
            "Errors or exceptions are being reported using print() rather than a "
            "structured logging framework. print() output cannot be filtered by log "
            "level, routed to log aggregators, or enriched with contextual metadata "
            "such as request IDs or user context."
        ),
        remediation=(
            "Replace print() error reporting with logger.error() or logger.exception() "
            "using the standard logging module or a structured logger like structlog. "
            "Use logger.exception() inside except blocks to automatically capture "
            "the traceback."
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
            "exception type, making error handling by callers imprecise. Generic "
            "exceptions cannot be caught selectively and provide no semantic "
            "information about the failure mode."
        ),
        remediation=(
            "Define and raise specific exception subclasses that convey meaningful "
            "error semantics (e.g. ValueError, PermissionError, or a custom domain "
            "exception like class PaymentError(Exception): pass). This allows callers "
            "to handle different error conditions appropriately."
        ),
        file_extensions=[".py"],
    ),
    ASTRule(
        rule_id="ERR005",
        category=Category.ERROR_HANDLING,
        severity=Severity.MEDIUM,
        node_type="FunctionDef",
        title="Function with no exception handling around external calls",
        description=(
            "Functions that make external calls (I/O, network, database) without "
            "any try/except blocks may propagate raw exceptions to callers, "
            "exposing internal details and causing unhandled errors in production."
        ),
        remediation=(
            "Wrap external calls (file I/O, HTTP requests, database queries) in "
            "try/except blocks. Catch specific exception types, log the error with "
            "context, and raise a domain-specific exception or return a structured "
            "error response."
        ),
        hook="function_no_error_handling",
    ),
]

# ---------------------------------------------------------------------------
# Environment configuration rules
# ---------------------------------------------------------------------------

ENV_CONFIG_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    RegexRule(
        rule_id="ENV001",
        category=Category.ENV_CONFIG,
        severity=Severity.HIGH,
        pattern=r"DEBUG\s*=\s*True|debug\s*=\s*True",
        title="Debug mode enabled in source code",
        description=(
            "DEBUG=True is set directly in source code. Running in debug mode "
            "in production exposes detailed stack traces, internal configuration, "
            "and potentially sensitive data to end users."
        ),
        remediation=(
            "Load the DEBUG flag from an environment variable: "
            "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'. "
            "Default to False (safe) if the variable is not set."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="ENV002",
        category=Category.ENV_CONFIG,
        severity=Severity.HIGH,
        pattern=(
            r"(?:DATABASE_URL|DB_PASSWORD|DB_HOST|REDIS_URL|API_KEY|"
            r"AWS_SECRET|AWS_ACCESS_KEY|STRIPE_SECRET|SENDGRID_API_KEY)"
            r"\s*=\s*['\"][^'\"]+['\"]"
        ),
        title="Hardcoded service connection string or credential",
        description=(
            "A service URL, database password, or API key appears to be hardcoded "
            "as a string literal. Committing credentials to source control is a "
            "critical security risk that can lead to unauthorized access and data breaches."
        ),
        remediation=(
            "Move all credentials and connection strings to environment variables "
            "or a .env file (excluded from version control via .gitignore) and load "
            "with os.environ or python-dotenv. Document required variables in .env.example."
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
            "No .env.example or .env.sample file was found in the repository. "
            "Without a documented environment variable template, new developers "
            "onboarding to the project won't know which variables to configure, "
            "leading to runtime errors and inconsistent deployments."
        ),
        remediation=(
            "Create a .env.example file listing all required environment variables "
            "with placeholder values (not real secrets) and commit it to version control. "
            "Example: DATABASE_URL=postgresql://user:password@localhost/dbname"
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
            "No .gitignore file was found in the repository. This significantly "
            "increases the risk of accidentally committing secrets (.env files), "
            "virtual environments, compiled files, and other sensitive or generated "
            "artifacts to version control."
        ),
        remediation=(
            "Add a .gitignore file that excludes .env, __pycache__, .venv, venv/, "
            "*.pyc, *.pyo, .DS_Store, and other sensitive or generated files. "
            "Use gitignore.io to generate a comprehensive template for your stack."
        ),
        expect_present=True,
    ),
    RegexRule(
        rule_id="ENV005",
        category=Category.ENV_CONFIG,
        severity=Severity.MEDIUM,
        pattern=r"os\.environ\[|os\.getenv\(",
        title="Direct environment variable access without defaults",
        description=(
            "Environment variables are accessed directly via os.environ[] which "
            "raises KeyError if the variable is not set. This can cause cryptic "
            "startup failures in production deployments where variables are missing."
        ),
        remediation=(
            "Use os.environ.get('VAR_NAME', default_value) or os.getenv('VAR_NAME', default) "
            "to provide sensible defaults. For required variables, validate all environment "
            "variables at application startup and fail fast with a clear error message."
        ),
        file_extensions=[".py"],
        negate=True,
    ),
]

# ---------------------------------------------------------------------------
# Security rules
# ---------------------------------------------------------------------------

SECURITY_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    RegexRule(
        rule_id="SEC001",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        pattern=r"\beval\s*\(|\bexec\s*\(",
        title="Dynamic code execution via eval()/exec() detected",
        description=(
            "Use of eval() or exec() with potentially user-controlled input "
            "can lead to arbitrary code execution (RCE) vulnerabilities. Even "
            "indirect user influence over the evaluated string is dangerous."
        ),
        remediation=(
            "Remove eval()/exec() and replace with safe alternatives such as "
            "ast.literal_eval() for parsing data structures, or explicit dispatch "
            "tables for dynamic behavior. If absolutely required, strictly validate "
            "and whitelist all inputs before evaluation."
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
            "user-controlled arguments create shell injection vulnerabilities. "
            "An attacker can escape the intended command and execute arbitrary "
            "shell commands on the host system."
        ),
        remediation=(
            "Use shell=False (the default) and pass arguments as a list: "
            "subprocess.run(['ls', '-la', path], shell=False). "
            "If shell=True is absolutely necessary, ensure all inputs are "
            "strictly validated against an allowlist and use shlex.quote() for escaping."
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
            "execute malicious code embedded in the pickle stream. Any pickle data "
            "from an untrusted source (network, user upload, external storage) is "
            "a critical security risk."
        ),
        remediation=(
            "Avoid using pickle for data received from external sources. "
            "Use safer serialization formats like JSON (json module) or MessagePack. "
            "If pickle is required for internal use, implement cryptographic signing "
            "(HMAC) to verify data integrity before deserialization."
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
            "yaml.load() without an explicit safe Loader argument uses the unsafe "
            "FullLoader by default in older PyYAML versions, enabling arbitrary "
            "Python object construction and potential code execution through "
            "crafted YAML payloads."
        ),
        remediation=(
            "Replace yaml.load() with yaml.safe_load() for all untrusted input, "
            "or explicitly pass Loader=yaml.SafeLoader: "
            "yaml.load(data, Loader=yaml.SafeLoader). "
            "Use yaml.safe_load() as the default for all YAML parsing."
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
            "MD5 and SHA1 are cryptographically broken hash functions with known "
            "collision attacks. They should not be used for security-sensitive "
            "operations like password hashing, digital signatures, or data "
            "integrity verification."
        ),
        remediation=(
            "Use SHA-256 or stronger (hashlib.sha256) for general-purpose hashing. "
            "For password hashing specifically, use bcrypt (bcrypt library), "
            "argon2 (argon2-cffi library), or hashlib.scrypt with appropriate "
            "work factor parameters."
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
            "application vulnerable to man-in-the-middle (MITM) attacks. An "
            "attacker on the network can intercept and modify encrypted communications "
            "without detection."
        ),
        remediation=(
            "Remove verify=False and rely on proper certificate verification. "
            "For development with self-signed certificates, provide the CA bundle "
            "path: requests.get(url, verify='/path/to/ca-bundle.crt'). "
            "Never disable verification in production."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="SEC007",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        pattern=r"(?i)\bSECRET\b.*=.*['\"][a-zA-Z0-9]{8,}['\"]|\bTOKEN\b.*=.*['\"][a-zA-Z0-9]{8,}['\"]",
        title="Potential secret or token value hardcoded",
        description=(
            "A variable named SECRET or TOKEN appears to have a hardcoded string "
            "value. Hardcoded secrets in source code are discoverable through "
            "repository history, binary analysis, or unauthorized source access."
        ),
        remediation=(
            "Load secrets and tokens from environment variables at runtime. "
            "Audit your git history for previously committed secrets and rotate "
            "any that may have been exposed. Consider using pre-commit hooks "
            "with detect-secrets or git-secrets to prevent future incidents."
        ),
        file_extensions=[".py", ".js", ".ts"],
    ),
    RegexRule(
        rule_id="SEC008",
        category=Category.SECURITY,
        severity=Severity.MEDIUM,
        pattern=r"random\.(?:random|randint|choice|randrange)\s*\(",
        title="Non-cryptographic random number generator used",
        description=(
            "The standard random module uses a pseudo-random number generator "
            "(Mersenne Twister) that is not suitable for cryptographic purposes. "
            "If used for generating tokens, passwords, or session IDs, these values "
            "are predictable."
        ),
        remediation=(
            "Use the secrets module for generating cryptographically secure random "
            "values: secrets.token_hex(), secrets.token_urlsafe(), secrets.randbelow(). "
            "Or use os.urandom() for raw random bytes. Reserve the random module for "
            "non-security applications like simulations."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Database migration rules
# ---------------------------------------------------------------------------

MIGRATION_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    FilePresenceRule(
        rule_id="MIG001",
        category=Category.MIGRATIONS,
        severity=Severity.HIGH,
        filename_patterns=["alembic.ini", "migrations/env.py", "alembic/env.py"],
        title="No database migration tool configuration found",
        description=(
            "No Alembic configuration was found in the repository. Without a "
            "migration tool, database schema changes must be applied manually, "
            "cannot be version-controlled, and cannot be safely rolled back. "
            "This makes deployments risky and error-prone."
        ),
        remediation=(
            "Initialize Alembic with 'alembic init migrations' and configure it "
            "to load the database URL from environment variables. Run "
            "'alembic revision --autogenerate' to generate migration scripts from "
            "your SQLAlchemy models."
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
            "database tables directly from models. This approach does not support "
            "incremental schema changes, data migrations, or rollbacks in production "
            "environments with existing data."
        ),
        remediation=(
            "Replace create_all() with proper migration scripts managed by Alembic "
            "or another migration tool (Django migrations, Flyway, Liquibase). "
            "Reserve create_all() exclusively for test database setup in fixtures."
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
            "for production workloads that require concurrent writes, "
            "horizontal scaling, row-level locking, or advanced SQL features. "
            "SQLite has no user authentication and its file format may not be "
            "appropriate for production deployments."
        ),
        remediation=(
            "Switch to a production-grade database such as PostgreSQL or MySQL. "
            "Configure the DATABASE_URL environment variable to point to the "
            "production database. Keep SQLite only for local development or testing "
            "where appropriate."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="MIG004",
        category=Category.MIGRATIONS,
        severity=Severity.MEDIUM,
        pattern=r"DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE",
        title="Destructive SQL statement found in source code",
        description=(
            "DROP TABLE, DROP DATABASE, or TRUNCATE TABLE statements were found "
            "in source code. Destructive SQL operations in application code rather "
            "than controlled migration scripts risk accidental data loss in "
            "production environments."
        ),
        remediation=(
            "Move all schema modifications to versioned migration scripts. "
            "Require peer review and a multi-step approval process for any "
            "migration that destroys or truncates data. Add rollback scripts "
            "alongside any destructive migration."
        ),
        file_extensions=[".py", ".sql"],
    ),
    RegexRule(
        rule_id="MIG005",
        category=Category.MIGRATIONS,
        severity=Severity.MEDIUM,
        pattern=r"engine\.execute\s*\(|connection\.execute\s*\(",
        title="Raw SQL execution detected — potential migration bypass",
        description=(
            "Raw SQL execution via engine.execute() or connection.execute() was "
            "detected. Schema changes executed through raw SQL calls bypass the "
            "migration framework, making it impossible to track, replay, or "
            "roll back those changes."
        ),
        remediation=(
            "If this raw SQL performs schema changes, convert it to a proper "
            "Alembic migration script (op.execute() within a migration). For "
            "data queries, prefer SQLAlchemy ORM or Core query builders. "
            "Document any necessary raw SQL with a clear explanation."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Logging rules
# ---------------------------------------------------------------------------

LOGGING_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    RegexRule(
        rule_id="LOG001",
        category=Category.LOGGING,
        severity=Severity.MEDIUM,
        pattern=r"^(?!.*import logging|.*from logging|.*logger).*\bprint\s*\(",
        title="print() used instead of structured logging",
        description=(
            "Application output is written using print() rather than a structured "
            "logging framework. print() output cannot be filtered by log level, "
            "routed to log aggregators (e.g. CloudWatch, Datadog, ELK), "
            "or enriched with contextual metadata like request IDs or user context."
        ),
        remediation=(
            "Replace print() calls with logger.info(), logger.debug(), logger.warning() "
            "etc. using the standard logging module. Configure logging at application "
            "startup with appropriate handlers, formatters, and log levels."
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
            "scripts and local development, but it lacks the structured output, "
            "JSON formatting, log rotation, and centralized handler management "
            "needed for production systems."
        ),
        remediation=(
            "Configure logging with logging.config.dictConfig() or a library like "
            "structlog or python-json-logger to produce structured JSON logs suitable "
            "for log aggregation. Define log levels, handlers, and formatters explicitly."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="LOG003",
        category=Category.LOGGING,
        severity=Severity.LOW,
        pattern=r"logging\.getLogger\(__name__\)",
        title="Module-level logger correctly defined",
        description=(
            "Module-level logger using __name__ is present. This is the correct "
            "pattern for Python logging as it creates a logger hierarchy that mirrors "
            "the module hierarchy, enabling fine-grained log level control."
        ),
        remediation="No action required. This is a best practice — continue using it.",
        negate=True,
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="LOG004",
        category=Category.LOGGING,
        severity=Severity.LOW,
        pattern=r"logging\.warning\s*\(|logging\.error\s*\(|logging\.critical\s*\(",
        title="Root logger used directly instead of module-level logger",
        description=(
            "Direct use of logging.warning(), logging.error(), or logging.critical() "
            "uses the root logger, which cannot be selectively silenced or configured "
            "for specific modules. This makes log management more difficult as the "
            "application grows."
        ),
        remediation=(
            "Create a module-level logger: logger = logging.getLogger(__name__) "
            "and use logger.warning(), logger.error() etc. This allows log levels to "
            "be configured per-module in production."
        ),
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="LOG005",
        category=Category.LOGGING,
        severity=Severity.LOW,
        pattern=r"logger\.debug\s*\(f['\"]|logger\.info\s*\(f['\"]|logger\.warning\s*\(f['\"]|logger\.error\s*\(f['\"]|logger\.critical\s*\(f['\"]",
        title="f-string used in logging call (performance concern)",
        description=(
            "Logging calls use f-strings to format messages. f-strings evaluate "
            "eagerly even when the log level is disabled, causing unnecessary string "
            "formatting overhead that can impact performance under high load."
        ),
        remediation=(
            "Use lazy % formatting with logging: logger.debug('Value: %s', value) "
            "instead of logger.debug(f'Value: {value}'). The message is only "
            "formatted if the log level is enabled, improving performance."
        ),
        file_extensions=[".py"],
    ),
]

# ---------------------------------------------------------------------------
# Testing rules
# ---------------------------------------------------------------------------

TESTING_RULES: list[RegexRule | ASTRule | FilePresenceRule] = [
    FilePresenceRule(
        rule_id="TST001",
        category=Category.TESTING,
        severity=Severity.HIGH,
        filename_patterns=["test_*.py", "*_test.py", "tests/*.py", "test/*.py"],
        title="No test files found in repository",
        description=(
            "No test files matching standard pytest conventions (test_*.py or *_test.py) "
            "were found anywhere in the repository. Without automated tests, regressions "
            "cannot be reliably detected, refactoring is risky, and confidence in "
            "deployments is low."
        ),
        remediation=(
            "Add a tests/ directory with pytest test files. Start with smoke tests "
            "covering critical business logic and API endpoints. Aim for at least "
            "60% line coverage before considering the codebase production-ready. "
            "Use pytest fixtures for setup and teardown."
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
            "No pytest configuration file (pytest.ini, setup.cfg, or pyproject.toml) "
            "was found. Without explicit test configuration, CI/CD systems may not "
            "know how to discover and run tests, and teams may use inconsistent "
            "test execution commands."
        ),
        remediation=(
            "Add a [tool.pytest.ini_options] section to pyproject.toml specifying "
            "the testpaths, any required plugins, and other options. This ensures "
            "consistent test discovery across development environments and CI pipelines."
        ),
        expect_present=True,
    ),
    RegexRule(
        rule_id="TST003",
        category=Category.TESTING,
        severity=Severity.LOW,
        pattern=r"def test_",
        title="Test functions present in codebase",
        description=(
            "Test function definitions using the standard test_ prefix were found. "
            "This indicates that some automated testing exists in the repository."
        ),
        remediation=(
            "Ensure test coverage is sufficient for critical paths. Run "
            "'pytest --cov' to measure coverage and identify untested areas. "
            "Add tests for edge cases, error conditions, and integration points."
        ),
        negate=True,
        file_extensions=[".py"],
    ),
    RegexRule(
        rule_id="TST004",
        category=Category.TESTING,
        severity=Severity.MEDIUM,
        pattern=r"@pytest\.mark\.skip|@unittest\.skip|skipTest",
        title="Skipped tests detected",
        description=(
            "Test functions or classes marked with skip decorators were found. "
            "Skipped tests indicate known failures or incomplete test implementations "
            "that reduce the overall reliability of the test suite."
        ),
        remediation=(
            "Review all skipped tests and determine whether they can be fixed or "
            "should be removed. If a skip is necessary, add a detailed reason and "
            "a tracking issue reference: @pytest.mark.skip(reason='Issue #123: ...')."
        ),
        file_extensions=[".py"],
    ),
    FilePresenceRule(
        rule_id="TST005",
        category=Category.TESTING,
        severity=Severity.LOW,
        filename_patterns=[".github/workflows/*.yml", ".github/workflows/*.yaml", ".travis.yml", "Jenkinsfile", ".circleci/config.yml"],
        title="No CI/CD pipeline configuration found",
        description=(
            "No continuous integration configuration file was found. Without CI/CD "
            "automation, tests may not run consistently on every commit, allowing "
            "regressions to slip through code review undetected."
        ),
        remediation=(
            "Set up a CI/CD pipeline using GitHub Actions, GitLab CI, CircleCI, "
            "or another platform. Configure it to run the test suite on every pull "
            "request. Add status checks that block merging when tests fail."
        ),
        expect_present=True,
    ),
]

# ---------------------------------------------------------------------------
# Unified rule registry
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

    Iterates the full ALL_RULES registry and filters by category, preserving
    the original declaration order within the category.

    Args:
        category: The Category enum value to filter by.

    Returns:
        List of RegexRule, ASTRule, or FilePresenceRule objects whose
        category attribute matches the requested category. Returns an empty
        list if no rules exist for the category.
    """
    return [rule for rule in ALL_RULES if rule.category == category]


def get_rule_by_id(
    rule_id: str,
) -> Optional[RegexRule | ASTRule | FilePresenceRule]:
    """Look up a specific rule by its unique identifier.

    Performs a linear scan of ALL_RULES and returns the first rule whose
    rule_id matches the requested identifier. Rule IDs are formatted as
    a category prefix plus a zero-padded number (e.g. 'AUTH001', 'SEC006').

    Args:
        rule_id: The unique rule identifier string (e.g. 'AUTH001').

    Returns:
        The matching RegexRule, ASTRule, or FilePresenceRule, or None if no
        rule with that ID exists in the registry.
    """
    for rule in ALL_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def get_all_rule_ids() -> list[str]:
    """Return a sorted list of all registered rule IDs.

    Useful for validation, documentation generation, and debugging the
    rule registry contents.

    Returns:
        Alphabetically sorted list of all rule_id strings in ALL_RULES.
    """
    return sorted(rule.rule_id for rule in ALL_RULES)


def get_rules_by_type(
    rule_type: type,
) -> list[RegexRule | ASTRule | FilePresenceRule]:
    """Return all rules of a specific type from the registry.

    Useful when an analyzer needs to process only regex rules, only AST
    rules, or only file presence rules.

    Args:
        rule_type: One of RegexRule, ASTRule, or FilePresenceRule.

    Returns:
        List of rules that are instances of the specified type.
    """
    return [rule for rule in ALL_RULES if isinstance(rule, rule_type)]

"""Static analysis check functions for proto_gap.

Each public function in this module is an analyzer responsible for one check
category. Analyzers consume the rule registry and produce Finding objects from
AST inspection, regex pattern matching, or file presence checks.

Public API:
    analyze_authentication  - auth gaps (hardcoded secrets, missing middleware)
    analyze_error_handling  - error handling gaps (bare except, silent pass)
    analyze_env_config      - environment config gaps (debug mode, no .env example)
    analyze_security        - security vulnerabilities (eval, pickle, weak crypto)
    analyze_migrations      - migration strategy gaps (create_all, SQLite, no Alembic)
    analyze_logging         - logging gaps (print instead of logger, basicConfig)
    analyze_testing         - test coverage gaps (no test files, skipped tests)
"""

from __future__ import annotations

import ast
import fnmatch
import re
from pathlib import Path
from typing import Iterator

from proto_gap.models import Category, Finding, Severity
from proto_gap.rules import (
    ASTRule,
    FilePresenceRule,
    RegexRule,
    get_rules_by_category,
)


# ---------------------------------------------------------------------------
# Public analyzer functions
# ---------------------------------------------------------------------------


def analyze_authentication(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for authentication-related production gaps.

    Checks for:
    - Hardcoded JWT or application secret keys (AUTH001)
    - Route definitions without visible auth middleware (AUTH002)
    - Hardcoded password literals (AUTH003)
    - Wildcard CORS policies (AUTH004)
    - Hardcoded API tokens or keys (AUTH005)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for authentication issues found.
    """
    rules = get_rules_by_category(Category.AUTHENTICATION)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


def analyze_error_handling(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for error-handling production gaps.

    Checks for:
    - Bare except clauses (ERR001) via AST
    - Silent except handlers with only pass (ERR002) via AST
    - Errors reported via print() instead of logging (ERR003)
    - Generic Exception raised directly (ERR004)
    - Functions with no error handling around external calls (ERR005)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for error handling issues found.
    """
    rules = get_rules_by_category(Category.ERROR_HANDLING)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
        elif isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
    return findings


def analyze_env_config(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for environment configuration production gaps.

    Checks for:
    - Debug mode hardcoded in source (ENV001)
    - Hardcoded service connection strings or credentials (ENV002)
    - Missing .env example file (ENV003)
    - Missing .gitignore file (ENV004)
    - Direct os.environ[] access without defaults (ENV005, negated)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for environment config issues found.
    """
    rules = get_rules_by_category(Category.ENV_CONFIG)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


def analyze_security(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for security vulnerabilities.

    Checks for:
    - Dynamic code execution via eval()/exec() (SEC001)
    - subprocess with shell=True (SEC002)
    - Unsafe pickle deserialization (SEC003)
    - Unsafe YAML deserialization (SEC004)
    - Weak cryptographic hash functions MD5/SHA1 (SEC005)
    - SSL/TLS certificate verification disabled (SEC006)
    - Hardcoded SECRET or TOKEN values (SEC007)
    - Non-cryptographic random number generator (SEC008)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for security issues found.
    """
    rules = get_rules_by_category(Category.SECURITY)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


def analyze_migrations(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for database migration strategy gaps.

    Checks for:
    - Missing Alembic configuration (MIG001)
    - create_all() used instead of migration scripts (MIG002)
    - SQLite database configuration detected (MIG003)
    - Destructive SQL statements in source (MIG004)
    - Raw SQL execution bypassing migration framework (MIG005)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for migration-related issues found.
    """
    rules = get_rules_by_category(Category.MIGRATIONS)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


def analyze_logging(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for logging configuration production gaps.

    Checks for:
    - print() used instead of structured logging (LOG001)
    - Logging configured with basicConfig only (LOG002)
    - Missing module-level logger using __name__ (LOG003, negated)
    - Root logger used directly (LOG004)
    - f-strings used in logging calls (LOG005)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for logging issues found.
    """
    rules = get_rules_by_category(Category.LOGGING)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


def analyze_testing(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for test coverage production gaps.

    Checks for:
    - Missing test files matching pytest conventions (TST001)
    - Missing test runner configuration (TST002)
    - No test functions found (TST003, negated)
    - Skipped tests detected (TST004)
    - Missing CI/CD pipeline configuration (TST005)

    Args:
        files: List of file paths to analyze.
        repo_root: Root directory of the repository being scanned.

    Returns:
        List of Finding objects for testing issues found.
    """
    rules = get_rules_by_category(Category.TESTING)
    findings: list[Finding] = []
    for rule in rules:
        if isinstance(rule, RegexRule):
            findings.extend(_apply_regex_rule(rule, files))
        elif isinstance(rule, FilePresenceRule):
            findings.extend(_apply_file_presence_rule(rule, files, repo_root))
        elif isinstance(rule, ASTRule):
            findings.extend(_apply_ast_rule(rule, files))
    return findings


# ---------------------------------------------------------------------------
# Internal rule application helpers
# ---------------------------------------------------------------------------


def _apply_regex_rule(rule: RegexRule, files: list[Path]) -> list[Finding]:
    """Apply a regex-based rule to a filtered list of files.

    For normal (non-negated) rules, one finding is produced per file that
    contains a match. Only the first match per file is reported to avoid
    flooding the output with duplicate findings for the same rule.

    For negated rules (rule.negate=True), a single finding is produced when
    NO match is found across ALL applicable files. This is used to detect
    missing best practices (e.g. no module-level logger defined anywhere).

    Args:
        rule: The RegexRule to apply.
        files: Complete list of repository files to search.

    Returns:
        List of Finding objects produced by this rule. May be empty.
    """
    findings: list[Finding] = []
    applicable = _filter_by_extension(files, rule.file_extensions)

    try:
        pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        # Silently skip rules with invalid regex patterns
        return findings

    matched_any = False

    for file_path in applicable:
        source = _read_file_safe(file_path)
        if source is None:
            continue

        match = pattern.search(source)
        if match is not None:
            matched_any = True
            if not rule.negate:
                line_number = _line_number_for_offset(source, match.start())
                findings.append(
                    Finding(
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        remediation=rule.remediation,
                        file_path=file_path,
                        line_number=line_number,
                        rule_id=rule.rule_id,
                    )
                )
                # One finding per file per rule to avoid noise

    # For negated rules: fire when the pattern is absent from all checked files
    if rule.negate and not matched_any:
        findings.append(
            Finding(
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                file_path=None,
                line_number=None,
                rule_id=rule.rule_id,
            )
        )

    return findings


def _apply_ast_rule(rule: ASTRule, files: list[Path]) -> list[Finding]:
    """Apply an AST-based rule to all Python files in the list.

    Parses each .py file into an AST and delegates to _visit_ast() for the
    actual node inspection. Files that fail to parse (SyntaxError) are
    silently skipped so a single bad file does not block the entire analysis.

    Args:
        rule: The ASTRule to apply, containing the hook name to dispatch on.
        files: Complete list of repository files (non-.py files are ignored).

    Returns:
        List of Finding objects produced by this rule across all Python files.
    """
    findings: list[Finding] = []
    python_files = [f for f in files if f.suffix == ".py"]

    for file_path in python_files:
        source = _read_file_safe(file_path)
        if source is None:
            continue

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            # Skip files that cannot be parsed; they may be partially written
            continue
        except ValueError:
            # ast.parse can raise ValueError for source with null bytes
            continue

        findings.extend(_visit_ast(rule, tree, file_path, source))

    return findings


def _apply_file_presence_rule(
    rule: FilePresenceRule,
    files: list[Path],
    repo_root: Path,
) -> list[Finding]:
    """Apply a file-presence rule against the discovered repository files.

    Searches the file list for any file whose name or relative path matches
    any of the rule's glob patterns. A finding is produced based on whether
    the rule expects the file to be present or absent.

    Pattern matching supports:
    - Simple filename patterns: '.env.example', 'alembic.ini'
    - Wildcard filename patterns: 'test_*.py', '*.yml'
    - Path-relative patterns: 'tests/*.py', '.github/workflows/*.yml'

    Args:
        rule: The FilePresenceRule to apply.
        files: Complete list of repository files.
        repo_root: Root directory used to compute relative paths.

    Returns:
        A list containing 0 or 1 Finding objects.
    """
    found = _check_file_patterns(rule.filename_patterns, files, repo_root)

    if rule.expect_present and not found:
        return [
            Finding(
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                file_path=repo_root,
                line_number=None,
                rule_id=rule.rule_id,
            )
        ]
    elif not rule.expect_present and found:
        return [
            Finding(
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                file_path=repo_root,
                line_number=None,
                rule_id=rule.rule_id,
            )
        ]
    return []


# ---------------------------------------------------------------------------
# AST visitor logic
# ---------------------------------------------------------------------------


def _visit_ast(
    rule: ASTRule,
    tree: ast.AST,
    file_path: Path,
    source: str,
) -> list[Finding]:
    """Walk an AST tree and produce findings based on the rule's named hook.

    Each hook name corresponds to a specific analysis pattern. Adding new
    AST checks requires adding a new elif branch here and a matching ASTRule
    in rules.py with the corresponding hook string.

    Supported hooks:
        'bare_except'               - catches bare except: clauses
        'silent_except'             - catches except: pass clauses
        'function_no_error_handling'- catches functions with external calls but no try

    Args:
        rule: The ASTRule defining which hook to execute.
        tree: The parsed AST of the file to inspect.
        file_path: Path to the source file (used for Finding.file_path).
        source: Original source text (used for line number calculations).

    Returns:
        List of Finding objects for all matching AST nodes in the file.
    """
    findings: list[Finding] = []

    if rule.hook == "bare_except":
        findings.extend(_hook_bare_except(rule, tree, file_path))

    elif rule.hook == "silent_except":
        findings.extend(_hook_silent_except(rule, tree, file_path))

    elif rule.hook == "function_no_error_handling":
        findings.extend(_hook_function_no_error_handling(rule, tree, file_path))

    return findings


def _hook_bare_except(
    rule: ASTRule,
    tree: ast.AST,
    file_path: Path,
) -> list[Finding]:
    """Detect bare except clauses in the AST.

    A bare except clause is one where the ExceptHandler has no type specified
    (node.type is None), meaning it catches every possible exception including
    SystemExit, KeyboardInterrupt, and GeneratorExit.

    Args:
        rule: The ASTRule providing title/description/remediation text.
        tree: Parsed AST to walk.
        file_path: Source file path for Finding.file_path.

    Returns:
        One Finding per bare except clause found.
    """
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(
                Finding(
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    remediation=rule.remediation,
                    file_path=file_path,
                    line_number=node.lineno,
                    rule_id=rule.rule_id,
                )
            )
    return findings


def _hook_silent_except(
    rule: ASTRule,
    tree: ast.AST,
    file_path: Path,
) -> list[Finding]:
    """Detect silent except handlers that only contain a pass statement.

    A silent except is an ExceptHandler whose body consists of exactly one
    statement and that statement is ast.Pass. This pattern swallows exceptions
    without any logging, re-raising, or other handling.

    Args:
        rule: The ASTRule providing title/description/remediation text.
        tree: Parsed AST to walk.
        file_path: Source file path for Finding.file_path.

    Returns:
        One Finding per silent except handler found.
    """
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = node.body
            if len(body) == 1 and isinstance(body[0], ast.Pass):
                findings.append(
                    Finding(
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        remediation=rule.remediation,
                        file_path=file_path,
                        line_number=node.lineno,
                        rule_id=rule.rule_id,
                    )
                )
    return findings


def _hook_function_no_error_handling(
    rule: ASTRule,
    tree: ast.AST,
    file_path: Path,
) -> list[Finding]:
    """Detect functions that make I/O or network calls but lack try/except blocks.

    Heuristic: looks for function definitions that contain Call nodes matching
    common external-call patterns (open, requests.*, urllib, socket, etc.) but
    have no Try node anywhere in their direct body.

    This is a best-effort heuristic and may produce false positives for
    functions that handle errors indirectly through context managers or
    calling functions that wrap the error handling.

    Args:
        rule: The ASTRule providing title/description/remediation text.
        tree: Parsed AST to walk.
        file_path: Source file path for Finding.file_path.

    Returns:
        One Finding per function with unhandled external calls found.
    """
    findings: list[Finding] = []

    # Names that suggest external I/O or network operations
    external_call_names = frozenset({
        "open",
        "requests",
        "urllib",
        "httpx",
        "aiohttp",
        "socket",
        "connect",
        "execute",
        "query",
        "fetch",
        "send",
        "recv",
        "read",
        "write",
        "load",
        "dump",
    })

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check if the function body contains any Try nodes
        has_try = any(
            isinstance(child, ast.Try)
            for child in ast.walk(node)
            if child is not node
        )
        if has_try:
            continue

        # Check if the function body contains external call patterns
        has_external_call = False
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, ast.Call):
                call_name = _extract_call_name(child)
                if call_name and any(
                    ext in call_name.lower() for ext in external_call_names
                ):
                    has_external_call = True
                    break

        if has_external_call:
            findings.append(
                Finding(
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    remediation=rule.remediation,
                    file_path=file_path,
                    line_number=node.lineno,
                    rule_id=rule.rule_id,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _filter_by_extension(files: list[Path], extensions: list[str]) -> list[Path]:
    """Return only files whose suffix matches one of the given extensions.

    If extensions is empty, all files are returned unchanged — this allows
    rules that apply to any file type to omit the extensions field.

    Args:
        files: List of file paths to filter.
        extensions: List of file extensions to keep (e.g. ['.py', '.js']).
            Extensions should include the leading dot.

    Returns:
        Filtered list of file paths whose suffix appears in extensions,
        or the original list if extensions is empty.
    """
    if not extensions:
        return files
    ext_set = frozenset(extensions)
    return [f for f in files if f.suffix in ext_set]


def _read_file_safe(file_path: Path) -> str | None:
    """Read a file's contents and return the text, or None on error.

    Uses UTF-8 encoding with 'replace' error handling so that binary or
    non-UTF-8 files are readable without crashing the analyzer. Returns
    None if the file cannot be opened due to OS-level errors.

    Args:
        file_path: Path to the file to read.

    Returns:
        File contents as a string, or None if the file could not be read.
    """
    try:
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _line_number_for_offset(source: str, offset: int) -> int:
    """Calculate the 1-based line number for a character offset in source text.

    Args:
        source: Full source text of the file.
        offset: Character offset (0-based) of the match start position.

    Returns:
        1-based line number corresponding to the given offset.
    """
    return source[:offset].count("\n") + 1


def _check_file_patterns(
    patterns: list[str],
    files: list[Path],
    repo_root: Path,
) -> bool:
    """Check whether any file in the list matches any of the given glob patterns.

    Matching is performed against both the bare filename and the relative path
    from repo_root. This handles patterns like '.gitignore' (filename match)
    and 'tests/*.py' or '.github/workflows/*.yml' (relative path match).

    Args:
        patterns: List of glob patterns to match against.
        files: List of discovered repository files.
        repo_root: Repository root used to compute relative paths.

    Returns:
        True if at least one file matches at least one pattern, False otherwise.
    """
    for pattern in patterns:
        for file_path in files:
            # Match against the bare filename
            if fnmatch.fnmatch(file_path.name, pattern):
                return True

            # Match against the relative path from repo root
            try:
                relative = str(file_path.relative_to(repo_root))
                # Normalise separators to forward slashes for cross-platform
                relative_fwd = relative.replace("\\", "/")
                if fnmatch.fnmatch(relative_fwd, pattern):
                    return True
            except ValueError:
                # file_path is not relative to repo_root — skip
                continue

    return False


def _extract_call_name(node: ast.Call) -> str | None:
    """Extract a dotted name string from an AST Call node's func attribute.

    Handles simple Name nodes (e.g. 'open') and Attribute chains
    (e.g. 'requests.get', 'os.path.join').

    Args:
        node: An ast.Call node to extract the function name from.

    Returns:
        A dotted name string (e.g. 'requests.get'), or None if the call's
        func cannot be reduced to a simple name or attribute chain.
    """
    func = node.func
    parts: list[str] = []
    current: ast.expr = func

    while True:
        if isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        elif isinstance(current, ast.Name):
            parts.append(current.id)
            break
        else:
            # Complex expression (subscript, call chain, etc.) — give up
            return None

    return ".".join(reversed(parts))

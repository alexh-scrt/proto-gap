"""Static analysis check functions for proto_gap.

Each public function in this module is an analyzer responsible for one check
category. Analyzers consume the rule registry and produce Finding objects from
AST inspection, regex pattern matching, or file presence checks.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from proto_gap.models import Category, Finding, Severity
from proto_gap.rules import (
    ASTRule,
    FilePresenceRule,
    RegexRule,
    get_rules_by_category,
)


def analyze_authentication(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for authentication-related gaps.

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
    return findings


def analyze_error_handling(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for error-handling gaps.

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
    return findings


def analyze_env_config(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for environment configuration gaps.

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
    return findings


def analyze_security(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for security vulnerabilities.

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
    return findings


def analyze_migrations(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for database migration strategy gaps.

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
    return findings


def analyze_logging(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for logging configuration gaps.

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
    return findings


def analyze_testing(files: list[Path], repo_root: Path) -> list[Finding]:
    """Analyze repository files for test coverage gaps.

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
    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _apply_regex_rule(rule: RegexRule, files: list[Path]) -> list[Finding]:
    """Apply a regex-based rule to a list of files.

    For negated rules, a single finding is produced when no match is found
    across all applicable files.

    Args:
        rule: The RegexRule to apply.
        files: List of files to search.

    Returns:
        List of Finding objects produced by this rule.
    """
    findings: list[Finding] = []
    applicable = _filter_by_extension(files, rule.file_extensions)
    matched_any = False

    try:
        pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return findings

    for file_path in applicable:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for match in pattern.finditer(source):
            matched_any = True
            if not rule.negate:
                line_number = source[: match.start()].count("\n") + 1
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
                break  # One finding per file per rule

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
    """Apply an AST-based rule to all Python files.

    Args:
        rule: The ASTRule to apply.
        files: List of files to inspect.

    Returns:
        List of Finding objects produced by this rule.
    """
    findings: list[Finding] = []
    python_files = [f for f in files if f.suffix == ".py"]

    for file_path in python_files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError):
            continue

        findings.extend(_visit_ast(rule, tree, file_path))

    return findings


def _visit_ast(rule: ASTRule, tree: ast.AST, file_path: Path) -> list[Finding]:
    """Walk an AST tree and produce findings based on the rule's hook.

    Args:
        rule: The ASTRule defining what to look for.
        tree: Parsed AST of the file.
        file_path: Path to the file being analyzed (for reporting).

    Returns:
        List of Finding objects for matches found in the tree.
    """
    findings: list[Finding] = []

    if rule.hook == "bare_except":
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

    elif rule.hook == "silent_except":
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


def _apply_file_presence_rule(
    rule: FilePresenceRule,
    files: list[Path],
    repo_root: Path,
) -> list[Finding]:
    """Apply a file-presence rule against the list of discovered files.

    Args:
        rule: The FilePresenceRule to apply.
        files: List of all files found in the repository.
        repo_root: Root directory of the repository.

    Returns:
        List of Finding objects (0 or 1) based on whether the expected
        file is present or absent.
    """
    import fnmatch

    found = False
    for pattern in rule.filename_patterns:
        for file_path in files:
            relative = str(file_path.relative_to(repo_root))
            if fnmatch.fnmatch(file_path.name, pattern) or fnmatch.fnmatch(
                relative, pattern
            ):
                found = True
                break
        if found:
            break

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


def _filter_by_extension(files: list[Path], extensions: list[str]) -> list[Path]:
    """Return only files whose suffix matches one of the given extensions.

    If extensions is empty, all files are returned.

    Args:
        files: List of file paths to filter.
        extensions: List of extensions to keep (e.g. ['.py', '.js']).

    Returns:
        Filtered list of file paths.
    """
    if not extensions:
        return files
    return [f for f in files if f.suffix in extensions]

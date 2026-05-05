"""Scanner orchestration for proto_gap.

Walks a repository directory tree, collects Python and configuration files,
runs all analyzer functions against them, and aggregates the findings into
a unified ScanReport.

Public API:
    Scanner       - class-based interface with configurable options
    scan_repository - convenience function for simple one-shot scans
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from proto_gap.analyzers import (
    analyze_authentication,
    analyze_env_config,
    analyze_error_handling,
    analyze_logging,
    analyze_migrations,
    analyze_security,
    analyze_testing,
)
from proto_gap.models import Finding, ScanReport

# File extensions considered source code or configuration that should be scanned
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".env",
        ".txt",
        ".md",
        ".sql",
    }
)

# Special filenames to always include regardless of extension
SPECIAL_FILENAMES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".gitignore",
        ".dockerignore",
        "Makefile",
        "Dockerfile",
        "Jenkinsfile",
    }
)

# Directory names to prune from the os.walk traversal
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".idea",
        ".vscode",
        "dist",
        "build",
    }
)

# Type alias for analyzer callables
AnalyzerFn = Callable[[list[Path], Path], list[Finding]]

# Ordered list of all built-in analyzer functions
_BUILT_IN_ANALYZERS: list[AnalyzerFn] = [
    analyze_authentication,
    analyze_error_handling,
    analyze_env_config,
    analyze_security,
    analyze_migrations,
    analyze_logging,
    analyze_testing,
]


class Scanner:
    """Orchestrates all analyzers against a repository directory tree.

    Walks the repository, discovers scannable files, runs each registered
    analyzer function, and aggregates all findings into a ScanReport.
    Non-fatal errors (e.g. unreadable files, analyzer failures) are captured
    in the report's errors list rather than raising exceptions.

    Attributes:
        repo_path: Absolute resolved path to the repository root.
        max_file_size_bytes: Files larger than this limit are skipped.

    Example::

        from pathlib import Path
        from proto_gap.scanner import Scanner

        scanner = Scanner(Path('./my-prototype'))
        report = scanner.scan()
        print(report.total_count, 'findings')
    """

    def __init__(
        self,
        repo_path: Path,
        max_file_size_bytes: int = 1_000_000,
        extra_analyzers: list[AnalyzerFn] | None = None,
    ) -> None:
        """Initialize the Scanner with a repository path and optional settings.

        Args:
            repo_path: Path to the repository root directory to scan.
                Will be resolved to an absolute path.
            max_file_size_bytes: Maximum file size in bytes to include in the
                scan. Files exceeding this size are skipped and noted in the
                report's errors list. Defaults to 1 MB.
            extra_analyzers: Optional list of additional analyzer functions to
                run in addition to the built-in analyzers. Each must accept
                (files: list[Path], repo_root: Path) and return list[Finding].

        Raises:
            ValueError: If repo_path does not exist or is not a directory.
        """
        self.repo_path: Path = repo_path.resolve()
        self.max_file_size_bytes: int = max_file_size_bytes

        if not self.repo_path.exists():
            raise ValueError(
                f"Repository path does not exist: {self.repo_path}"
            )
        if not self.repo_path.is_dir():
            raise ValueError(
                f"Repository path is not a directory: {self.repo_path}"
            )

        self._analyzers: list[AnalyzerFn] = list(_BUILT_IN_ANALYZERS)
        if extra_analyzers:
            self._analyzers.extend(extra_analyzers)

    def scan(self) -> ScanReport:
        """Run all registered analyzers against the repository.

        Collects all scannable files from the repository tree, then runs
        each analyzer function in order. Findings from all analyzers are
        aggregated into a single ScanReport. Analyzer failures are caught
        and recorded as non-fatal errors.

        Returns:
            A ScanReport containing all findings, the list of scanned files,
            and any non-fatal errors encountered during discovery or analysis.
        """
        report = ScanReport(repo_path=self.repo_path)

        files, discovery_errors = self._collect_files()
        report.scanned_files = files
        report.errors.extend(discovery_errors)

        for analyzer in self._analyzers:
            try:
                findings = analyzer(files, self.repo_path)
                report.findings.extend(findings)
            except Exception as exc:  # noqa: BLE001
                report.errors.append(
                    f"Analyzer '{analyzer.__name__}' failed: "
                    f"{type(exc).__name__}: {exc}"
                )

        return report

    def _collect_files(self) -> tuple[list[Path], list[str]]:
        """Walk the repository directory tree and collect scannable files.

        Excludes directories listed in EXCLUDED_DIRS and any directory whose
        name ends with '.egg-info'. Files are included if their extension is
        in SCANNABLE_EXTENSIONS or their name is in SPECIAL_FILENAMES.
        Files exceeding max_file_size_bytes are skipped with a warning.

        Returns:
            A two-tuple of (files, errors):
            - files: List of Path objects for all discovered scannable files.
            - errors: List of non-fatal error message strings (e.g. for files
              that could not be stat'd or were too large).
        """
        files: list[Path] = []
        errors: list[str] = []

        for root, dirs, filenames in os.walk(self.repo_path, topdown=True):
            root_path = Path(root)

            # Prune excluded directories in-place to prevent os.walk descending
            dirs[:] = [
                d
                for d in dirs
                if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")
            ]

            for filename in filenames:
                file_path = root_path / filename

                # Determine whether this file should be scanned
                if (
                    file_path.suffix not in SCANNABLE_EXTENSIONS
                    and file_path.name not in SPECIAL_FILENAMES
                ):
                    continue

                # Check file size before adding
                try:
                    file_size = file_path.stat().st_size
                except OSError as exc:
                    errors.append(
                        f"Could not stat file '{file_path}': {exc}"
                    )
                    continue

                if file_size > self.max_file_size_bytes:
                    errors.append(
                        f"Skipped large file ({file_size:,} bytes): {file_path}"
                    )
                    continue

                files.append(file_path)

        return files, errors


def scan_repository(
    repo_path: Path,
    max_file_size_bytes: int = 1_000_000,
    extra_analyzers: list[AnalyzerFn] | None = None,
) -> ScanReport:
    """Convenience function to scan a repository using default settings.

    Creates a Scanner instance and runs scan() in a single call, suitable
    for programmatic use from CLI or library consumers.

    Args:
        repo_path: Path to the repository root directory to scan.
        max_file_size_bytes: Maximum file size in bytes to scan.
            Files exceeding this size are skipped. Defaults to 1 MB.
        extra_analyzers: Optional list of additional analyzer functions beyond
            the built-in set. Each must accept (list[Path], Path) and return
            list[Finding].

    Returns:
        A ScanReport containing all findings from the repository scan.

    Raises:
        ValueError: If repo_path does not exist or is not a directory.

    Example::

        from pathlib import Path
        from proto_gap.scanner import scan_repository

        report = scan_repository(Path('./my-prototype'))
        print(f'Found {report.critical_count} critical issues')
    """
    scanner = Scanner(
        repo_path=repo_path,
        max_file_size_bytes=max_file_size_bytes,
        extra_analyzers=extra_analyzers,
    )
    return scanner.scan()

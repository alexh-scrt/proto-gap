"""Scanner orchestration for proto_gap.

Walks a repository directory tree, collects Python and configuration files,
runs all analyzer functions against them, and aggregates the findings into
a unified ScanReport.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

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

# File extensions considered source code or configuration
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
    }
)

# Directories to exclude from scanning
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
        "*.egg-info",
    }
)

# Type alias for analyzer functions
AnalyzerFn = Callable[[list[Path], Path], list[Finding]]


class Scanner:
    """Orchestrates all analyzers against a repository directory.

    Attributes:
        repo_path: Absolute path to the repository root to scan.
        max_file_size_bytes: Files larger than this are skipped to avoid
            memory issues with very large generated files.
    """

    def __init__(
        self,
        repo_path: Path,
        max_file_size_bytes: int = 1_000_000,
    ) -> None:
        """Initialize the Scanner.

        Args:
            repo_path: Path to the repository root directory to scan.
            max_file_size_bytes: Maximum file size in bytes to scan.
                Files exceeding this limit are skipped.

        Raises:
            ValueError: If repo_path does not exist or is not a directory.
        """
        self.repo_path = repo_path.resolve()
        self.max_file_size_bytes = max_file_size_bytes

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {self.repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {self.repo_path}")

        self._analyzers: list[AnalyzerFn] = [
            analyze_authentication,
            analyze_error_handling,
            analyze_env_config,
            analyze_security,
            analyze_migrations,
            analyze_logging,
            analyze_testing,
        ]

    def scan(self) -> ScanReport:
        """Run all analyzers against the repository and return an aggregated report.

        Returns:
            A ScanReport containing all findings, scanned file paths, and any
            non-fatal errors encountered during the scan.
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
                    f"Analyzer {analyzer.__name__} failed: {type(exc).__name__}: {exc}"
                )

        return report

    def _collect_files(self) -> tuple[list[Path], list[str]]:
        """Walk the repository tree and collect scannable files.

        Returns:
            A tuple of (files, errors) where files is a list of Path objects
            for scannable files and errors is a list of non-fatal error strings.
        """
        files: list[Path] = []
        errors: list[str] = []

        for root, dirs, filenames in os.walk(self.repo_path):
            root_path = Path(root)

            # Prune excluded directories in-place so os.walk skips them
            dirs[:] = [
                d
                for d in dirs
                if d not in EXCLUDED_DIRS and not d.endswith(".egg-info")
            ]

            for filename in filenames:
                file_path = root_path / filename

                # Include files with scannable extensions OR special config files
                if (
                    file_path.suffix not in SCANNABLE_EXTENSIONS
                    and file_path.name
                    not in (
                        ".env.example",
                        ".env.sample",
                        ".env.template",
                        ".gitignore",
                        ".dockerignore",
                        "Makefile",
                        "Dockerfile",
                    )
                ):
                    continue

                try:
                    file_size = file_path.stat().st_size
                    if file_size > self.max_file_size_bytes:
                        errors.append(
                            f"Skipped large file ({file_size} bytes): {file_path}"
                        )
                        continue
                    files.append(file_path)
                except OSError as exc:
                    errors.append(f"Could not stat file {file_path}: {exc}")

        return files, errors


def scan_repository(
    repo_path: Path,
    max_file_size_bytes: int = 1_000_000,
) -> ScanReport:
    """Convenience function to scan a repository using default settings.

    Args:
        repo_path: Path to the repository root directory to scan.
        max_file_size_bytes: Maximum file size in bytes to scan.

    Returns:
        A ScanReport containing all findings from the repository.

    Raises:
        ValueError: If repo_path does not exist or is not a directory.
    """
    scanner = Scanner(repo_path=repo_path, max_file_size_bytes=max_file_size_bytes)
    return scanner.scan()

"""Data models for proto_gap findings and scan reports.

Defines the core domain objects:
- Severity: enumeration of finding priority levels
- Category: enumeration of analysis check categories
- Finding: a single detected gap or issue
- ScanReport: aggregated result of a full repository scan
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    """Priority level assigned to a production-readiness finding.

    Severity levels are ordered from highest to lowest priority:
    CRITICAL > HIGH > MEDIUM > LOW
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __lt__(self, other: "Severity") -> bool:
        """Allow severity comparison by priority order (CRITICAL > HIGH > MEDIUM > LOW).

        Args:
            other: The other Severity to compare against.

        Returns:
            True if this severity is lower priority than other.
        """
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        """Less-than-or-equal comparison by priority order.

        Args:
            other: The other Severity to compare against.

        Returns:
            True if this severity is lower priority than or equal to other.
        """
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        """Greater-than comparison by priority order.

        Args:
            other: The other Severity to compare against.

        Returns:
            True if this severity is higher priority than other.
        """
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        """Greater-than-or-equal comparison by priority order.

        Args:
            other: The other Severity to compare against.

        Returns:
            True if this severity is higher priority than or equal to other.
        """
        return self == other or self > other


class Category(str, Enum):
    """Check category classifying the type of production-readiness gap.

    Each category corresponds to a distinct domain of production concerns
    that proto_gap analyzes independently.
    """

    AUTHENTICATION = "Authentication"
    ERROR_HANDLING = "Error Handling"
    ENV_CONFIG = "Environment Config"
    SECURITY = "Security"
    MIGRATIONS = "Database Migrations"
    LOGGING = "Logging"
    TESTING = "Testing"


@dataclass
class Finding:
    """A single detected production-readiness gap.

    Represents one specific issue found during static analysis of a repository.
    Findings are produced by analyzer functions and aggregated into a ScanReport.

    Attributes:
        category: The check category this finding belongs to.
        severity: Priority level indicating urgency of remediation.
        title: Short, human-readable description of the issue.
        description: Detailed explanation of why this is a problem in production.
        remediation: Actionable hint describing how to fix the issue.
        file_path: Optional path to the file where the issue was found.
        line_number: Optional line number within the file.
        rule_id: Optional identifier of the rule that triggered this finding.
    """

    category: Category
    severity: Severity
    title: str
    description: str
    remediation: str
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dictionary suitable for JSON output.

        Returns:
            A dictionary with all finding fields, where Path objects are
            converted to strings and None values are preserved.
        """
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "file_path": str(self.file_path) if self.file_path is not None else None,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
        }

    def __str__(self) -> str:
        """Return a concise human-readable string representation.

        Returns:
            A single-line summary of the finding including severity, category, and title.
        """
        location = ""
        if self.file_path is not None:
            location = f" @ {self.file_path}"
            if self.line_number is not None:
                location += f":{self.line_number}"
        return (
            f"[{self.severity.value}] {self.category.value}: {self.title}{location}"
        )


@dataclass
class ScanReport:
    """Aggregated result of a full repository scan.

    Produced by the Scanner after running all analyzers against a repository.
    Provides summary statistics and grouped access to findings, as well as
    serialization to dictionary form for JSON output.

    Attributes:
        repo_path: The root directory that was scanned.
        findings: List of all Finding objects discovered during the scan.
        scanned_files: List of all file paths that were analyzed.
        errors: Any non-fatal error messages encountered during scanning.
    """

    repo_path: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity findings.

        Returns:
            Count of findings with Severity.CRITICAL.
        """
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH severity findings.

        Returns:
            Count of findings with Severity.HIGH.
        """
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of MEDIUM severity findings.

        Returns:
            Count of findings with Severity.MEDIUM.
        """
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of LOW severity findings.

        Returns:
            Count of findings with Severity.LOW.
        """
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        """Total number of findings across all categories and severities.

        Returns:
            The length of the findings list.
        """
        return len(self.findings)

    def findings_by_severity(self) -> list[Finding]:
        """Return all findings sorted by severity, highest priority first.

        Findings with the same severity preserve their original insertion order.

        Returns:
            List of Finding objects sorted CRITICAL > HIGH > MEDIUM > LOW.
        """
        order: dict[Severity, int] = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        return sorted(self.findings, key=lambda f: order[f.severity])

    def findings_by_category(self) -> dict[Category, list[Finding]]:
        """Return all findings grouped by their check category.

        Every Category enum value appears as a key, even if it has no findings,
        so callers can iterate over all categories without key errors.

        Returns:
            Ordered dictionary mapping each Category to its list of Finding objects.
            Within each category list, findings appear in their original order.
        """
        groups: dict[Category, list[Finding]] = {cat: [] for cat in Category}
        for finding in self.findings:
            groups[finding.category].append(finding)
        return groups

    def has_findings_in_category(self, category: Category) -> bool:
        """Check whether any findings exist for the given category.

        Args:
            category: The Category to check.

        Returns:
            True if at least one finding belongs to the specified category.
        """
        return any(f.category == category for f in self.findings)

    def findings_at_or_above_severity(self, min_severity: Severity) -> list[Finding]:
        """Return findings at or above a minimum severity threshold.

        Args:
            min_severity: The minimum Severity level to include.

        Returns:
            List of findings whose severity is >= min_severity, sorted by
            severity descending.
        """
        return [
            f for f in self.findings_by_severity()
            if f.severity >= min_severity
        ]

    def to_dict(self) -> dict:
        """Serialize the scan report to a plain dictionary suitable for JSON output.

        The findings are included in severity-sorted order (CRITICAL first).
        All Path objects are converted to strings.

        Returns:
            A dictionary representation of the full scan report, including
            a summary breakdown by severity level.
        """
        return {
            "repo_path": str(self.repo_path),
            "total_findings": self.total_count,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "scanned_files": [str(p) for p in self.scanned_files],
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings_by_severity()],
        }

    def __str__(self) -> str:
        """Return a concise human-readable summary of the scan report.

        Returns:
            A single-line summary showing the repo path and finding counts.
        """
        return (
            f"ScanReport({self.repo_path}: "
            f"{self.total_count} findings — "
            f"CRITICAL={self.critical_count}, "
            f"HIGH={self.high_count}, "
            f"MEDIUM={self.medium_count}, "
            f"LOW={self.low_count})"
        )

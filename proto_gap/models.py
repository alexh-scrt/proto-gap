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
    """Priority level assigned to a production-readiness finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __lt__(self, other: "Severity") -> bool:
        """Allow severity comparison by priority order (CRITICAL > HIGH > MEDIUM > LOW)."""
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class Category(str, Enum):
    """Check category classifying the type of production-readiness gap."""

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

    Attributes:
        category: The check category this finding belongs to.
        severity: Priority level indicating urgency of remediation.
        title: Short, human-readable description of the issue.
        description: Detailed explanation of why this is a problem.
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
        """Serialize the finding to a plain dictionary suitable for JSON output."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "file_path": str(self.file_path) if self.file_path else None,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
        }


@dataclass
class ScanReport:
    """Aggregated result of a full repository scan.

    Attributes:
        repo_path: The root directory that was scanned.
        findings: List of all findings discovered during the scan.
        scanned_files: List of all files that were analyzed.
        errors: Any non-fatal errors encountered during scanning.
    """

    repo_path: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    def findings_by_severity(self) -> list[Finding]:
        """Return findings sorted by severity (CRITICAL first)."""
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(self.findings, key=lambda f: order[f.severity])

    def findings_by_category(self) -> dict[Category, list[Finding]]:
        """Return findings grouped by category."""
        groups: dict[Category, list[Finding]] = {cat: [] for cat in Category}
        for finding in self.findings:
            groups[finding.category].append(finding)
        return groups

    def to_dict(self) -> dict:
        """Serialize the scan report to a plain dictionary suitable for JSON output."""
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

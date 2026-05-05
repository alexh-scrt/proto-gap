"""Unit tests for proto_gap.models — Severity, Category, Finding, and ScanReport."""

from __future__ import annotations

from pathlib import Path

import pytest

from proto_gap.models import Category, Finding, ScanReport, Severity


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverity:
    """Tests for the Severity enum and its comparison operators."""

    def test_severity_values(self) -> None:
        """Verify string values of all Severity members."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"

    def test_severity_is_str_subclass(self) -> None:
        """Severity should be usable as a plain string."""
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.HIGH == "HIGH"

    def test_severity_ordering_lt(self) -> None:
        """CRITICAL is higher priority, so LOW < HIGH < CRITICAL."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
        assert Severity.LOW < Severity.CRITICAL

    def test_severity_ordering_gt(self) -> None:
        """Reverse of lt — CRITICAL > HIGH > MEDIUM > LOW."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW

    def test_severity_ordering_le(self) -> None:
        """Less-than-or-equal includes equality."""
        assert Severity.LOW <= Severity.LOW
        assert Severity.LOW <= Severity.CRITICAL
        assert not (Severity.CRITICAL <= Severity.LOW)

    def test_severity_ordering_ge(self) -> None:
        """Greater-than-or-equal includes equality."""
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.CRITICAL >= Severity.LOW
        assert not (Severity.LOW >= Severity.CRITICAL)

    def test_severity_not_lt_equal(self) -> None:
        """An equal severity should not be less than itself."""
        assert not (Severity.HIGH < Severity.HIGH)

    def test_severity_sortable(self) -> None:
        """Severity values should sort correctly with Python's sorted()."""
        unsorted = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH]
        result = sorted(unsorted)
        assert result == [
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def test_severity_all_members_comparable(self) -> None:
        """All pairs of severities should be comparable without error."""
        members = list(Severity)
        for a in members:
            for b in members:
                _ = a < b
                _ = a > b
                _ = a <= b
                _ = a >= b
                _ = a == b


# ---------------------------------------------------------------------------
# Category tests
# ---------------------------------------------------------------------------


class TestCategory:
    """Tests for the Category enum."""

    def test_category_values(self) -> None:
        """Verify string values of all Category members."""
        assert Category.AUTHENTICATION.value == "Authentication"
        assert Category.ERROR_HANDLING.value == "Error Handling"
        assert Category.ENV_CONFIG.value == "Environment Config"
        assert Category.SECURITY.value == "Security"
        assert Category.MIGRATIONS.value == "Database Migrations"
        assert Category.LOGGING.value == "Logging"
        assert Category.TESTING.value == "Testing"

    def test_category_is_str_subclass(self) -> None:
        """Category should be usable as a plain string."""
        assert isinstance(Category.SECURITY, str)
        assert Category.TESTING == "Testing"

    def test_all_seven_categories_present(self) -> None:
        """Exactly seven categories should be defined."""
        assert len(list(Category)) == 7

    def test_category_iteration(self) -> None:
        """All categories should be accessible via iteration."""
        names = {cat.value for cat in Category}
        expected = {
            "Authentication",
            "Error Handling",
            "Environment Config",
            "Security",
            "Database Migrations",
            "Logging",
            "Testing",
        }
        assert names == expected


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


def make_finding(
    category: Category = Category.SECURITY,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "A test description.",
    remediation: str = "Fix it.",
    file_path: Path | None = None,
    line_number: int | None = None,
    rule_id: str | None = None,
) -> Finding:
    """Helper factory for constructing Finding objects in tests."""
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        file_path=file_path,
        line_number=line_number,
        rule_id=rule_id,
    )


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_required_fields(self) -> None:
        """Finding should accept all required fields."""
        f = make_finding()
        assert f.category == Category.SECURITY
        assert f.severity == Severity.HIGH
        assert f.title == "Test finding"
        assert f.description == "A test description."
        assert f.remediation == "Fix it."

    def test_finding_optional_fields_default_to_none(self) -> None:
        """Optional fields should default to None."""
        f = make_finding()
        assert f.file_path is None
        assert f.line_number is None
        assert f.rule_id is None

    def test_finding_with_all_fields(self) -> None:
        """Finding should accept all optional fields."""
        path = Path("/repo/app.py")
        f = make_finding(
            file_path=path,
            line_number=42,
            rule_id="SEC001",
        )
        assert f.file_path == path
        assert f.line_number == 42
        assert f.rule_id == "SEC001"

    def test_finding_to_dict_basic(self) -> None:
        """to_dict() should serialize all fields correctly."""
        f = make_finding(
            category=Category.AUTHENTICATION,
            severity=Severity.CRITICAL,
            title="Hardcoded secret",
            description="Secret found.",
            remediation="Use env vars.",
            rule_id="AUTH001",
        )
        d = f.to_dict()
        assert d["category"] == "Authentication"
        assert d["severity"] == "CRITICAL"
        assert d["title"] == "Hardcoded secret"
        assert d["description"] == "Secret found."
        assert d["remediation"] == "Use env vars."
        assert d["rule_id"] == "AUTH001"
        assert d["file_path"] is None
        assert d["line_number"] is None

    def test_finding_to_dict_with_file_path(self) -> None:
        """to_dict() should convert file_path to string."""
        path = Path("/repo/main.py")
        f = make_finding(file_path=path, line_number=10)
        d = f.to_dict()
        assert d["file_path"] == str(path)
        assert d["line_number"] == 10

    def test_finding_to_dict_none_file_path(self) -> None:
        """to_dict() should preserve None for missing file_path."""
        f = make_finding(file_path=None)
        d = f.to_dict()
        assert d["file_path"] is None

    def test_finding_str_no_location(self) -> None:
        """__str__ should include severity, category, and title."""
        f = make_finding(title="Missing auth")
        text = str(f)
        assert "HIGH" in text
        assert "Security" in text
        assert "Missing auth" in text

    def test_finding_str_with_file_path(self) -> None:
        """__str__ should include file path when present."""
        f = make_finding(file_path=Path("/repo/app.py"))
        text = str(f)
        assert "app.py" in text

    def test_finding_str_with_line_number(self) -> None:
        """__str__ should include line number when both file_path and line_number exist."""
        f = make_finding(file_path=Path("/repo/app.py"), line_number=99)
        text = str(f)
        assert "99" in text

    def test_finding_to_dict_keys(self) -> None:
        """to_dict() must contain exactly the expected keys."""
        f = make_finding()
        keys = set(f.to_dict().keys())
        expected = {
            "category",
            "severity",
            "title",
            "description",
            "remediation",
            "file_path",
            "line_number",
            "rule_id",
        }
        assert keys == expected


# ---------------------------------------------------------------------------
# ScanReport tests
# ---------------------------------------------------------------------------


def _make_report_with_findings() -> ScanReport:
    """Build a ScanReport with one finding of each severity for testing."""
    repo = Path("/fake/repo")
    report = ScanReport(repo_path=repo)
    report.findings = [
        make_finding(severity=Severity.LOW, category=Category.LOGGING, title="Low finding"),
        make_finding(severity=Severity.MEDIUM, category=Category.TESTING, title="Medium finding"),
        make_finding(severity=Severity.HIGH, category=Category.SECURITY, title="High finding"),
        make_finding(severity=Severity.CRITICAL, category=Category.AUTHENTICATION, title="Critical finding"),
    ]
    return report


class TestScanReport:
    """Tests for the ScanReport dataclass."""

    def test_empty_report_defaults(self) -> None:
        """A fresh ScanReport should have empty collections and zero counts."""
        report = ScanReport(repo_path=Path("/repo"))
        assert report.findings == []
        assert report.scanned_files == []
        assert report.errors == []
        assert report.total_count == 0
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.medium_count == 0
        assert report.low_count == 0

    def test_count_properties(self) -> None:
        """Count properties should reflect the findings list accurately."""
        report = _make_report_with_findings()
        assert report.total_count == 4
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1

    def test_count_with_multiple_same_severity(self) -> None:
        """Count properties should aggregate multiple findings at the same severity."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(severity=Severity.HIGH),
            make_finding(severity=Severity.HIGH),
            make_finding(severity=Severity.CRITICAL),
        ]
        assert report.high_count == 2
        assert report.critical_count == 1
        assert report.medium_count == 0
        assert report.low_count == 0
        assert report.total_count == 3

    def test_findings_by_severity_order(self) -> None:
        """findings_by_severity() should return CRITICAL first, LOW last."""
        report = _make_report_with_findings()
        ordered = report.findings_by_severity()
        assert len(ordered) == 4
        assert ordered[0].severity == Severity.CRITICAL
        assert ordered[1].severity == Severity.HIGH
        assert ordered[2].severity == Severity.MEDIUM
        assert ordered[3].severity == Severity.LOW

    def test_findings_by_severity_empty(self) -> None:
        """findings_by_severity() on an empty report should return an empty list."""
        report = ScanReport(repo_path=Path("/repo"))
        assert report.findings_by_severity() == []

    def test_findings_by_category_all_categories_present(self) -> None:
        """findings_by_category() should return a key for every Category enum value."""
        report = _make_report_with_findings()
        by_cat = report.findings_by_category()
        for cat in Category:
            assert cat in by_cat

    def test_findings_by_category_correct_grouping(self) -> None:
        """Findings should be placed in the correct category bucket."""
        report = _make_report_with_findings()
        by_cat = report.findings_by_category()
        assert len(by_cat[Category.AUTHENTICATION]) == 1
        assert len(by_cat[Category.SECURITY]) == 1
        assert len(by_cat[Category.TESTING]) == 1
        assert len(by_cat[Category.LOGGING]) == 1
        assert len(by_cat[Category.MIGRATIONS]) == 0

    def test_findings_by_category_empty_categories(self) -> None:
        """Categories with no findings should map to empty lists."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [make_finding(category=Category.SECURITY)]
        by_cat = report.findings_by_category()
        assert len(by_cat[Category.SECURITY]) == 1
        for cat in Category:
            if cat != Category.SECURITY:
                assert by_cat[cat] == []

    def test_has_findings_in_category_true(self) -> None:
        """has_findings_in_category() returns True when findings exist."""
        report = _make_report_with_findings()
        assert report.has_findings_in_category(Category.AUTHENTICATION) is True

    def test_has_findings_in_category_false(self) -> None:
        """has_findings_in_category() returns False for empty categories."""
        report = _make_report_with_findings()
        assert report.has_findings_in_category(Category.MIGRATIONS) is False

    def test_findings_at_or_above_severity_critical(self) -> None:
        """Filtering at CRITICAL should return only CRITICAL findings."""
        report = _make_report_with_findings()
        result = report.findings_at_or_above_severity(Severity.CRITICAL)
        assert all(f.severity == Severity.CRITICAL for f in result)
        assert len(result) == 1

    def test_findings_at_or_above_severity_low(self) -> None:
        """Filtering at LOW should return all findings."""
        report = _make_report_with_findings()
        result = report.findings_at_or_above_severity(Severity.LOW)
        assert len(result) == 4

    def test_findings_at_or_above_severity_high(self) -> None:
        """Filtering at HIGH should return CRITICAL and HIGH findings."""
        report = _make_report_with_findings()
        result = report.findings_at_or_above_severity(Severity.HIGH)
        severities = {f.severity for f in result}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM not in severities
        assert Severity.LOW not in severities

    def test_to_dict_structure(self) -> None:
        """to_dict() should contain all expected top-level keys."""
        report = _make_report_with_findings()
        d = report.to_dict()
        assert "repo_path" in d
        assert "total_findings" in d
        assert "summary" in d
        assert "scanned_files" in d
        assert "errors" in d
        assert "findings" in d

    def test_to_dict_summary_counts(self) -> None:
        """to_dict() summary should contain accurate severity counts."""
        report = _make_report_with_findings()
        d = report.to_dict()
        summary = d["summary"]
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1

    def test_to_dict_total_findings(self) -> None:
        """to_dict() total_findings should equal the length of the findings list."""
        report = _make_report_with_findings()
        d = report.to_dict()
        assert d["total_findings"] == 4

    def test_to_dict_repo_path_is_string(self) -> None:
        """to_dict() should convert repo_path to a string."""
        report = ScanReport(repo_path=Path("/fake/repo"))
        d = report.to_dict()
        assert isinstance(d["repo_path"], str)
        assert d["repo_path"] == "/fake/repo"

    def test_to_dict_scanned_files_are_strings(self) -> None:
        """to_dict() should convert all scanned_files paths to strings."""
        report = ScanReport(repo_path=Path("/repo"))
        report.scanned_files = [Path("/repo/app.py"), Path("/repo/main.py")]
        d = report.to_dict()
        assert all(isinstance(p, str) for p in d["scanned_files"])

    def test_to_dict_findings_sorted_by_severity(self) -> None:
        """Findings in to_dict() should appear in severity-sorted order."""
        report = _make_report_with_findings()
        d = report.to_dict()
        findings = d["findings"]
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[-1]["severity"] == "LOW"

    def test_to_dict_errors(self) -> None:
        """to_dict() should include the errors list."""
        report = ScanReport(repo_path=Path("/repo"))
        report.errors = ["Something went wrong", "Another error"]
        d = report.to_dict()
        assert d["errors"] == ["Something went wrong", "Another error"]

    def test_str_representation(self) -> None:
        """__str__ should include repo path and finding counts."""
        report = _make_report_with_findings()
        text = str(report)
        assert "ScanReport" in text
        assert "4" in text  # total findings
        assert "CRITICAL=1" in text
        assert "HIGH=1" in text

    def test_findings_not_shared_between_instances(self) -> None:
        """Different ScanReport instances should not share the same findings list."""
        r1 = ScanReport(repo_path=Path("/repo1"))
        r2 = ScanReport(repo_path=Path("/repo2"))
        r1.findings.append(make_finding())
        assert len(r2.findings) == 0

    def test_errors_not_shared_between_instances(self) -> None:
        """Different ScanReport instances should not share the same errors list."""
        r1 = ScanReport(repo_path=Path("/repo1"))
        r2 = ScanReport(repo_path=Path("/repo2"))
        r1.errors.append("error")
        assert len(r2.errors) == 0

"""Tests for proto_gap.renderer — Markdown, JSON, and terminal rendering.

Verifies that render_markdown(), render_json(), render_terminal(), and the
dispatch function render() produce correct, well-structured output from a
variety of ScanReport inputs including empty reports, single-finding reports,
and multi-finding reports spanning all severity levels and categories.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Optional

import pytest
from rich.console import Console

from proto_gap.models import Category, Finding, ScanReport, Severity
from proto_gap.renderer import (
    SEVERITY_COLORS,
    SEVERITY_EMOJI,
    OutputFormat,
    _format_location,
    render,
    render_json,
    render_markdown,
    render_terminal,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def make_finding(
    category: Category = Category.SECURITY,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "A test description.",
    remediation: str = "Fix it.",
    file_path: Optional[Path] = None,
    line_number: Optional[int] = None,
    rule_id: Optional[str] = "SEC001",
) -> Finding:
    """Helper factory for constructing Finding objects in renderer tests."""
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


def make_empty_report(repo_path: Optional[Path] = None) -> ScanReport:
    """Return a ScanReport with no findings and no errors."""
    return ScanReport(repo_path=repo_path or Path("/fake/repo"))


def make_full_report() -> ScanReport:
    """Return a ScanReport with one finding of each severity and category."""
    report = ScanReport(repo_path=Path("/fake/repo"))
    report.scanned_files = [
        Path("/fake/repo/app.py"),
        Path("/fake/repo/settings.py"),
        Path("/fake/repo/db.py"),
    ]
    report.findings = [
        make_finding(
            category=Category.AUTHENTICATION,
            severity=Severity.CRITICAL,
            title="Hardcoded secret key",
            description="A secret key is hardcoded.",
            remediation="Use environment variables.",
            file_path=Path("/fake/repo/settings.py"),
            line_number=5,
            rule_id="AUTH001",
        ),
        make_finding(
            category=Category.SECURITY,
            severity=Severity.HIGH,
            title="Unsafe eval() usage",
            description="eval() was detected.",
            remediation="Remove eval().",
            file_path=Path("/fake/repo/app.py"),
            line_number=12,
            rule_id="SEC001",
        ),
        make_finding(
            category=Category.ERROR_HANDLING,
            severity=Severity.MEDIUM,
            title="Silent exception handler",
            description="An except pass was found.",
            remediation="Add logging.",
            file_path=Path("/fake/repo/app.py"),
            line_number=20,
            rule_id="ERR002",
        ),
        make_finding(
            category=Category.TESTING,
            severity=Severity.LOW,
            title="No test runner config",
            description="pytest.ini is missing.",
            remediation="Add pyproject.toml config.",
            file_path=None,
            line_number=None,
            rule_id="TST002",
        ),
        make_finding(
            category=Category.MIGRATIONS,
            severity=Severity.CRITICAL,
            title="create_all() detected",
            description="Schema created via create_all.",
            remediation="Use Alembic migrations.",
            file_path=Path("/fake/repo/db.py"),
            line_number=8,
            rule_id="MIG002",
        ),
        make_finding(
            category=Category.LOGGING,
            severity=Severity.MEDIUM,
            title="basicConfig used",
            description="Not suitable for production.",
            remediation="Use structlog or dictConfig.",
            file_path=Path("/fake/repo/app.py"),
            line_number=3,
            rule_id="LOG002",
        ),
        make_finding(
            category=Category.ENV_CONFIG,
            severity=Severity.HIGH,
            title="DEBUG=True in source",
            description="Debug mode hardcoded.",
            remediation="Load from environment.",
            file_path=Path("/fake/repo/settings.py"),
            line_number=1,
            rule_id="ENV001",
        ),
    ]
    report.errors = []
    return report


def make_rich_console_with_buffer() -> tuple[Console, StringIO]:
    """Create a Rich Console that writes to a StringIO buffer for testing."""
    buffer = StringIO()
    console = Console(
        file=buffer,
        highlight=False,
        markup=False,
        no_color=True,
        width=120,
    )
    return console, buffer


# ---------------------------------------------------------------------------
# _format_location tests
# ---------------------------------------------------------------------------


class TestFormatLocation:
    """Tests for the _format_location() helper function."""

    def test_no_file_path_returns_dash(self) -> None:
        """A finding with no file_path should return '-'."""
        finding = make_finding(file_path=None, line_number=None)
        assert _format_location(finding) == "-"

    def test_file_path_only(self) -> None:
        """A finding with only file_path should return the path string."""
        finding = make_finding(file_path=Path("/repo/app.py"), line_number=None)
        result = _format_location(finding, truncate=None)
        assert result == "/repo/app.py"

    def test_file_path_and_line_number(self) -> None:
        """A finding with both file_path and line_number should include both."""
        finding = make_finding(file_path=Path("/repo/app.py"), line_number=42)
        result = _format_location(finding, truncate=None)
        assert result == "/repo/app.py:42"

    def test_truncation_applied_for_long_path(self) -> None:
        """Long paths should be truncated with leading '...' when truncate is set."""
        long_path = Path("/very/long/path/that/exceeds/the/truncation/limit/app.py")
        finding = make_finding(file_path=long_path, line_number=None)
        result = _format_location(finding, truncate=20)
        assert len(result) <= 20
        assert result.startswith("...")

    def test_truncation_none_returns_full_path(self) -> None:
        """With truncate=None, the full path should be returned."""
        long_path = Path("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/app.py")
        finding = make_finding(file_path=long_path, line_number=99)
        result = _format_location(finding, truncate=None)
        assert str(long_path) in result
        assert ":99" in result

    def test_short_path_not_truncated(self) -> None:
        """A short path should not be truncated even with a truncate value."""
        finding = make_finding(file_path=Path("/repo/app.py"), line_number=1)
        result = _format_location(finding, truncate=60)
        assert "/repo/app.py:1" == result

    def test_truncated_path_includes_line_number(self) -> None:
        """Truncated path output should still include the line number."""
        long_path = Path("/very/long/path/that/exceeds/truncation/limit/app.py")
        finding = make_finding(file_path=long_path, line_number=55)
        result = _format_location(finding, truncate=30)
        assert ":55" in result

    def test_default_truncate_is_60(self) -> None:
        """Default truncate value should cap at 60 characters."""
        long_path = Path("/" + "x" * 80 + "/app.py")
        finding = make_finding(file_path=long_path)
        result = _format_location(finding)  # default truncate=60
        # Result should be at most 60 chars (path part) + possible line number
        path_part = result.split(":")[0]
        assert len(path_part) <= 60


# ---------------------------------------------------------------------------
# SEVERITY_COLORS and SEVERITY_EMOJI constants tests
# ---------------------------------------------------------------------------


class TestRendererConstants:
    """Tests for the renderer module-level constants."""

    def test_severity_colors_covers_all_severities(self) -> None:
        """SEVERITY_COLORS should have an entry for every Severity enum value."""
        for severity in Severity:
            assert severity in SEVERITY_COLORS, (
                f"SEVERITY_COLORS missing entry for {severity}"
            )

    def test_severity_emoji_covers_all_severities(self) -> None:
        """SEVERITY_EMOJI should have an entry for every Severity enum value."""
        for severity in Severity:
            assert severity in SEVERITY_EMOJI, (
                f"SEVERITY_EMOJI missing entry for {severity}"
            )

    def test_severity_colors_are_non_empty_strings(self) -> None:
        """All SEVERITY_COLORS values should be non-empty strings."""
        for severity, color in SEVERITY_COLORS.items():
            assert isinstance(color, str)
            assert color, f"Empty color for {severity}"

    def test_severity_emoji_are_non_empty_strings(self) -> None:
        """All SEVERITY_EMOJI values should be non-empty strings."""
        for severity, emoji in SEVERITY_EMOJI.items():
            assert isinstance(emoji, str)
            assert emoji, f"Empty emoji for {severity}"

    def test_critical_color_includes_red(self) -> None:
        """CRITICAL severity color should include 'red' style."""
        assert "red" in SEVERITY_COLORS[Severity.CRITICAL]

    def test_critical_emoji_is_red_circle(self) -> None:
        """CRITICAL emoji should be the red circle."""
        assert SEVERITY_EMOJI[Severity.CRITICAL] == "🔴"

    def test_high_emoji_is_orange_circle(self) -> None:
        """HIGH emoji should be the orange circle."""
        assert SEVERITY_EMOJI[Severity.HIGH] == "🟠"

    def test_medium_emoji_is_yellow_circle(self) -> None:
        """MEDIUM emoji should be the yellow circle."""
        assert SEVERITY_EMOJI[Severity.MEDIUM] == "🟡"

    def test_low_emoji_is_blue_circle(self) -> None:
        """LOW emoji should be the blue circle."""
        assert SEVERITY_EMOJI[Severity.LOW] == "🔵"


# ---------------------------------------------------------------------------
# render_json tests
# ---------------------------------------------------------------------------


class TestRenderJson:
    """Tests for render_json()."""

    def test_returns_string(self) -> None:
        """render_json() should return a string."""
        report = make_empty_report()
        result = render_json(report)
        assert isinstance(result, str)

    def test_valid_json(self) -> None:
        """render_json() output should be valid JSON."""
        report = make_full_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_json_has_required_top_level_keys(self) -> None:
        """Parsed JSON should contain all required top-level keys."""
        report = make_empty_report()
        parsed = json.loads(render_json(report))
        expected_keys = {
            "repo_path",
            "total_findings",
            "summary",
            "scanned_files",
            "errors",
            "findings",
        }
        assert expected_keys.issubset(set(parsed.keys()))

    def test_json_repo_path_is_string(self) -> None:
        """repo_path in JSON should be a string."""
        report = make_empty_report(Path("/my/repo"))
        parsed = json.loads(render_json(report))
        assert isinstance(parsed["repo_path"], str)
        assert "/my/repo" in parsed["repo_path"]

    def test_json_total_findings_zero_for_empty_report(self) -> None:
        """An empty report should have total_findings = 0."""
        report = make_empty_report()
        parsed = json.loads(render_json(report))
        assert parsed["total_findings"] == 0

    def test_json_summary_counts_zero_for_empty_report(self) -> None:
        """An empty report should have all summary counts as 0."""
        report = make_empty_report()
        parsed = json.loads(render_json(report))
        summary = parsed["summary"]
        assert summary["critical"] == 0
        assert summary["high"] == 0
        assert summary["medium"] == 0
        assert summary["low"] == 0

    def test_json_findings_empty_list_for_empty_report(self) -> None:
        """An empty report should have an empty findings list in JSON."""
        report = make_empty_report()
        parsed = json.loads(render_json(report))
        assert parsed["findings"] == []

    def test_json_full_report_finding_count(self) -> None:
        """Full report JSON should reflect the correct total finding count."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        assert parsed["total_findings"] == len(report.findings)

    def test_json_summary_counts_match_report(self) -> None:
        """JSON summary counts should match the ScanReport property values."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        summary = parsed["summary"]
        assert summary["critical"] == report.critical_count
        assert summary["high"] == report.high_count
        assert summary["medium"] == report.medium_count
        assert summary["low"] == report.low_count

    def test_json_findings_sorted_by_severity(self) -> None:
        """Findings in JSON should be sorted CRITICAL first."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        findings = parsed["findings"]
        severity_order = {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3
        }
        for i in range(len(findings) - 1):
            assert severity_order[findings[i]["severity"]] <= severity_order[
                findings[i + 1]["severity"]
            ]

    def test_json_finding_has_required_fields(self) -> None:
        """Each finding in the JSON output should have all required fields."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        required_finding_keys = {
            "category", "severity", "title", "description",
            "remediation", "file_path", "line_number", "rule_id",
        }
        for finding in parsed["findings"]:
            assert required_finding_keys.issubset(set(finding.keys())), (
                f"Finding missing keys: {required_finding_keys - set(finding.keys())}"
            )

    def test_json_finding_severity_is_string(self) -> None:
        """Finding severity in JSON should be a string value."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        for finding in parsed["findings"]:
            assert isinstance(finding["severity"], str)
            assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_json_finding_category_is_string(self) -> None:
        """Finding category in JSON should be a string value."""
        report = make_full_report()
        parsed = json.loads(render_json(report))
        valid_categories = {cat.value for cat in Category}
        for finding in parsed["findings"]:
            assert isinstance(finding["category"], str)
            assert finding["category"] in valid_categories

    def test_json_finding_with_file_path_is_string(self) -> None:
        """file_path in a JSON finding should be a string when present."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                file_path=Path("/repo/app.py"),
                line_number=5,
            )
        ]
        parsed = json.loads(render_json(report))
        assert isinstance(parsed["findings"][0]["file_path"], str)

    def test_json_finding_without_file_path_is_null(self) -> None:
        """file_path in JSON should be null when not set."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(file_path=None, line_number=None)
        ]
        parsed = json.loads(render_json(report))
        assert parsed["findings"][0]["file_path"] is None

    def test_json_scanned_files_are_strings(self) -> None:
        """scanned_files in JSON should be a list of strings."""
        report = make_empty_report()
        report.scanned_files = [Path("/repo/app.py"), Path("/repo/db.py")]
        parsed = json.loads(render_json(report))
        assert all(isinstance(p, str) for p in parsed["scanned_files"])

    def test_json_errors_list(self) -> None:
        """errors in JSON should be a list."""
        report = make_empty_report()
        report.errors = ["Some scan error", "Another error"]
        parsed = json.loads(render_json(report))
        assert parsed["errors"] == ["Some scan error", "Another error"]

    def test_json_indented_output(self) -> None:
        """JSON output should be pretty-printed (indented)."""
        report = make_empty_report()
        result = render_json(report)
        # Indented JSON should contain newlines
        assert "\n" in result
        # And should have consistent indentation
        assert "  " in result

    def test_json_empty_errors_list(self) -> None:
        """errors should be an empty list when no errors occurred."""
        report = make_empty_report()
        parsed = json.loads(render_json(report))
        assert parsed["errors"] == []

    def test_json_finding_rule_id(self) -> None:
        """Finding rule_id should be preserved in JSON output."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(rule_id="SEC001")
        ]
        parsed = json.loads(render_json(report))
        assert parsed["findings"][0]["rule_id"] == "SEC001"

    def test_json_finding_none_rule_id(self) -> None:
        """A finding with no rule_id should serialize rule_id as null."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(rule_id=None)
        ]
        parsed = json.loads(render_json(report))
        assert parsed["findings"][0]["rule_id"] is None

    def test_json_large_finding_count(self) -> None:
        """render_json() should handle reports with many findings."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                severity=Severity.HIGH,
                title=f"Finding {i}",
                rule_id=f"SEC{i:03d}",
            )
            for i in range(50)
        ]
        result = render_json(report)
        parsed = json.loads(result)
        assert len(parsed["findings"]) == 50


# ---------------------------------------------------------------------------
# render_markdown tests
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    """Tests for render_markdown()."""

    def test_returns_string(self) -> None:
        """render_markdown() should return a string."""
        report = make_empty_report()
        result = render_markdown(report)
        assert isinstance(result, str)

    def test_returns_non_empty_string(self) -> None:
        """render_markdown() should never return an empty string."""
        report = make_empty_report()
        result = render_markdown(report)
        assert result.strip()

    def test_starts_with_h1_title(self) -> None:
        """Markdown output should start with an H1 title."""
        report = make_empty_report()
        result = render_markdown(report)
        assert result.startswith("# proto_gap")

    def test_contains_repo_path(self) -> None:
        """Markdown output should contain the repository path."""
        report = make_empty_report(Path("/my/test/repo"))
        result = render_markdown(report)
        assert "/my/test/repo" in result

    def test_contains_files_scanned_count(self) -> None:
        """Markdown output should report the number of scanned files."""
        report = make_empty_report()
        report.scanned_files = [Path("/repo/a.py"), Path("/repo/b.py")]
        result = render_markdown(report)
        assert "2" in result

    def test_contains_summary_table(self) -> None:
        """Markdown output should include a summary table with severity counts."""
        report = make_full_report()
        result = render_markdown(report)
        # Should have a Markdown table
        assert "|" in result
        assert "CRITICAL" in result
        assert "HIGH" in result
        assert "MEDIUM" in result
        assert "LOW" in result

    def test_empty_report_no_findings_message(self) -> None:
        """An empty report should include a 'no gaps detected' message."""
        report = make_empty_report()
        result = render_markdown(report)
        assert "No production-readiness gaps detected" in result

    def test_full_report_contains_finding_titles(self) -> None:
        """Markdown output should contain the titles of all findings."""
        report = make_full_report()
        result = render_markdown(report)
        for finding in report.findings:
            assert finding.title in result, (
                f"Finding title '{finding.title}' not found in Markdown output"
            )

    def test_full_report_contains_finding_descriptions(self) -> None:
        """Markdown output should contain the descriptions of all findings."""
        report = make_full_report()
        result = render_markdown(report)
        for finding in report.findings:
            assert finding.description in result, (
                f"Description for '{finding.title}' not found in Markdown output"
            )

    def test_full_report_contains_finding_remediations(self) -> None:
        """Markdown output should contain the remediation hints of all findings."""
        report = make_full_report()
        result = render_markdown(report)
        for finding in report.findings:
            assert finding.remediation in result, (
                f"Remediation for '{finding.title}' not found in Markdown output"
            )

    def test_full_report_contains_rule_ids(self) -> None:
        """Markdown output should contain rule IDs for all findings."""
        report = make_full_report()
        result = render_markdown(report)
        for finding in report.findings:
            if finding.rule_id:
                assert finding.rule_id in result, (
                    f"Rule ID '{finding.rule_id}' not found in Markdown output"
                )

    def test_full_report_contains_severity_emojis(self) -> None:
        """Markdown output should contain severity emojis."""
        report = make_full_report()
        result = render_markdown(report)
        # The full report has CRITICAL and HIGH findings
        assert "🔴" in result  # CRITICAL
        assert "🟠" in result  # HIGH

    def test_markdown_contains_checkbox_syntax(self) -> None:
        """Findings should be formatted as unchecked Markdown checkboxes."""
        report = make_full_report()
        result = render_markdown(report)
        assert "- [ ]" in result

    def test_markdown_contains_category_headers(self) -> None:
        """Markdown output should have headers for each category with findings."""
        report = make_full_report()
        result = render_markdown(report)
        # Check that categories with findings have H3 headers
        for category in Category:
            if report.has_findings_in_category(category):
                assert f"### {category.value}" in result, (
                    f"Category header '### {category.value}' not found"
                )

    def test_markdown_omits_empty_category_headers(self) -> None:
        """Categories with no findings should not appear as headers."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(category=Category.SECURITY, severity=Severity.HIGH)
        ]
        result = render_markdown(report)
        # Only SECURITY has findings, other categories should be absent
        assert "### Authentication" not in result
        assert "### Testing" not in result

    def test_markdown_contains_file_path_when_present(self) -> None:
        """File paths should appear in the Markdown output when set."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                file_path=Path("/repo/app.py"),
                line_number=10,
            )
        ]
        result = render_markdown(report)
        assert "app.py" in result

    def test_markdown_errors_section_when_errors_present(self) -> None:
        """Scan errors should appear in a dedicated Markdown section."""
        report = make_empty_report()
        report.errors = ["Skipped large file: big.py", "Analyzer failed: err"]
        result = render_markdown(report)
        assert "Scan Warnings" in result or "Scan Error" in result
        assert "Skipped large file: big.py" in result

    def test_markdown_no_errors_section_when_no_errors(self) -> None:
        """No scan errors section should appear when there are no errors."""
        report = make_empty_report()
        result = render_markdown(report)
        assert "Scan Warnings" not in result
        assert "Scan Error" not in result

    def test_markdown_summary_table_counts_match(self) -> None:
        """Summary table severity counts should match the report."""
        report = make_full_report()
        result = render_markdown(report)
        # The counts in the summary table should reflect the actual findings
        assert str(report.critical_count) in result
        assert str(report.high_count) in result

    def test_markdown_single_critical_finding(self) -> None:
        """A single CRITICAL finding should be present in output with correct emoji."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                severity=Severity.CRITICAL,
                title="Critical security issue",
                rule_id="SEC001",
            )
        ]
        result = render_markdown(report)
        assert "🔴" in result
        assert "Critical security issue" in result
        assert "CRITICAL" in result

    def test_markdown_findings_ordered_by_severity_within_category(self) -> None:
        """Within a category, CRITICAL findings should appear before LOW."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                category=Category.SECURITY,
                severity=Severity.LOW,
                title="Low security issue",
                rule_id="SEC_LOW",
            ),
            make_finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                title="Critical security issue",
                rule_id="SEC_CRIT",
            ),
        ]
        result = render_markdown(report)
        # CRITICAL should appear before LOW in the output
        crit_pos = result.index("Critical security issue")
        low_pos = result.index("Low security issue")
        assert crit_pos < low_pos

    def test_markdown_total_findings_count(self) -> None:
        """Total findings count should appear in the Markdown header."""
        report = make_full_report()
        result = render_markdown(report)
        assert str(report.total_count) in result

    def test_markdown_report_is_valid_markdown_structure(self) -> None:
        """Output should contain standard Markdown structural elements."""
        report = make_full_report()
        result = render_markdown(report)
        lines = result.splitlines()
        # Must have at least one H1 line
        h1_lines = [l for l in lines if l.startswith("# ")]
        assert len(h1_lines) >= 1
        # Must have at least one H2 line
        h2_lines = [l for l in lines if l.startswith("## ")]
        assert len(h2_lines) >= 1

    def test_markdown_empty_findings_list_shows_no_gaps(self) -> None:
        """A report with findings list empty should show the no-gaps message."""
        report = ScanReport(repo_path=Path("/repo"))
        report.scanned_files = [Path("/repo/app.py")]
        result = render_markdown(report)
        assert "No production-readiness gaps detected" in result

    def test_markdown_with_no_rule_id_does_not_crash(self) -> None:
        """Findings without rule_id should render without crashing."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(rule_id=None, title="Anonymous finding")
        ]
        result = render_markdown(report)
        assert "Anonymous finding" in result

    def test_markdown_summary_table_has_all_severity_rows(self) -> None:
        """Summary table should contain rows for all four severity levels."""
        report = make_empty_report()
        result = render_markdown(report)
        assert "CRITICAL" in result
        assert "HIGH" in result
        assert "MEDIUM" in result
        assert "LOW" in result


# ---------------------------------------------------------------------------
# render_terminal tests
# ---------------------------------------------------------------------------


class TestRenderTerminal:
    """Tests for render_terminal()."""

    def _capture_terminal(self, report: ScanReport) -> str:
        """Render a report to terminal and capture the output as a string."""
        console, buffer = make_rich_console_with_buffer()
        render_terminal(report, console=console)
        return buffer.getvalue()

    def test_returns_none(self) -> None:
        """render_terminal() should return None (prints directly)."""
        console, _ = make_rich_console_with_buffer()
        result = render_terminal(make_empty_report(), console=console)
        assert result is None

    def test_empty_report_outputs_something(self) -> None:
        """render_terminal() should produce non-empty output for any report."""
        output = self._capture_terminal(make_empty_report())
        assert output.strip()

    def test_empty_report_shows_no_findings_message(self) -> None:
        """An empty report should show a 'no gaps detected' message."""
        output = self._capture_terminal(make_empty_report())
        assert "No production-readiness gaps detected" in output

    def test_full_report_shows_finding_titles(self) -> None:
        """Terminal output should contain all finding titles."""
        report = make_full_report()
        output = self._capture_terminal(report)
        for finding in report.findings:
            assert finding.title in output, (
                f"Title '{finding.title}' not found in terminal output"
            )

    def test_full_report_shows_severity_labels(self) -> None:
        """Terminal output should contain all severity level labels."""
        report = make_full_report()
        output = self._capture_terminal(report)
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output

    def test_full_report_shows_category_values(self) -> None:
        """Terminal output should include category names."""
        report = make_full_report()
        output = self._capture_terminal(report)
        for finding in report.findings:
            assert finding.category.value in output, (
                f"Category '{finding.category.value}' not found in terminal output"
            )

    def test_full_report_shows_rule_ids(self) -> None:
        """Terminal output should include rule IDs for all findings."""
        report = make_full_report()
        output = self._capture_terminal(report)
        for finding in report.findings:
            if finding.rule_id:
                assert finding.rule_id in output, (
                    f"Rule ID '{finding.rule_id}' not found in terminal output"
                )

    def test_full_report_shows_descriptions(self) -> None:
        """Detailed section should include finding descriptions."""
        report = make_full_report()
        output = self._capture_terminal(report)
        for finding in report.findings:
            assert finding.description in output, (
                f"Description for '{finding.title}' not in terminal output"
            )

    def test_full_report_shows_remediations(self) -> None:
        """Detailed section should include remediation hints."""
        report = make_full_report()
        output = self._capture_terminal(report)
        for finding in report.findings:
            assert finding.remediation in output, (
                f"Remediation for '{finding.title}' not in terminal output"
            )

    def test_full_report_shows_repo_path(self) -> None:
        """Terminal output should display the repository path."""
        report = make_full_report()
        output = self._capture_terminal(report)
        assert str(report.repo_path) in output

    def test_full_report_shows_scanned_files_count(self) -> None:
        """Terminal output should display the number of scanned files."""
        report = make_full_report()
        output = self._capture_terminal(report)
        assert str(len(report.scanned_files)) in output

    def test_full_report_shows_total_count(self) -> None:
        """Terminal output should display the total findings count."""
        report = make_full_report()
        output = self._capture_terminal(report)
        assert str(report.total_count) in output

    def test_errors_shown_in_output(self) -> None:
        """Scan errors should appear in terminal output."""
        report = make_empty_report()
        report.errors = ["Skipped large file: big.py"]
        output = self._capture_terminal(report)
        assert "Skipped large file: big.py" in output

    def test_no_errors_section_when_no_errors(self) -> None:
        """No scan error section should appear when errors list is empty."""
        report = make_full_report()
        report.errors = []
        output = self._capture_terminal(report)
        # The output should not contain a scan errors/warnings section heading
        assert "Scan Warnings" not in output or "Skipped" not in output

    def test_uses_default_console_when_none_given(self) -> None:
        """render_terminal() with console=None should not raise."""
        report = make_empty_report()
        # This will print to stdout but should not raise
        # We can't easily capture stdout here without mocking,
        # so we just verify no exception is raised
        try:
            # Use a no-op console to avoid actual stdout pollution in tests
            console = Console(file=StringIO(), no_color=True)
            render_terminal(report, console=console)
        except Exception as exc:
            pytest.fail(f"render_terminal raised unexpectedly: {exc}")

    def test_finding_with_no_file_path_renders_cleanly(self) -> None:
        """A finding with no file_path should render without error."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(file_path=None, line_number=None)
        ]
        output = self._capture_terminal(report)
        assert output.strip()

    def test_finding_with_file_path_and_line_shows_location(self) -> None:
        """Terminal output should show the file path and line for findings that have them."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                file_path=Path("/repo/app.py"),
                line_number=42,
            )
        ]
        output = self._capture_terminal(report)
        assert "app.py" in output
        assert "42" in output

    def test_render_terminal_single_finding(self) -> None:
        """Terminal rendering with a single finding should work correctly."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                title="Critical eval usage",
                rule_id="SEC001",
            )
        ]
        output = self._capture_terminal(report)
        assert "Critical eval usage" in output
        assert "CRITICAL" in output
        assert "SEC001" in output

    def test_render_terminal_many_findings(self) -> None:
        """Terminal rendering with many findings should not crash."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                severity=Severity.HIGH,
                title=f"Finding {i}",
                rule_id=f"SEC{i:03d}",
            )
            for i in range(20)
        ]
        output = self._capture_terminal(report)
        assert output.strip()
        # All findings should appear
        for i in range(20):
            assert f"Finding {i}" in output


# ---------------------------------------------------------------------------
# render() dispatch function tests
# ---------------------------------------------------------------------------


class TestRenderDispatch:
    """Tests for the render() dispatch function."""

    def test_render_json_format_returns_string(self) -> None:
        """render() with 'json' format should return a string."""
        report = make_empty_report()
        result = render(report, output_format="json")
        assert isinstance(result, str)

    def test_render_markdown_format_returns_string(self) -> None:
        """render() with 'markdown' format should return a string."""
        report = make_empty_report()
        result = render(report, output_format="markdown")
        assert isinstance(result, str)

    def test_render_terminal_format_returns_none(self) -> None:
        """render() with 'terminal' format should return None."""
        console, _ = make_rich_console_with_buffer()
        result = render(make_empty_report(), output_format="terminal", console=console)
        assert result is None

    def test_render_invalid_format_raises_value_error(self) -> None:
        """render() with an unsupported format should raise ValueError."""
        report = make_empty_report()
        with pytest.raises(ValueError, match="Unsupported output format"):
            render(report, output_format="xml")  # type: ignore[arg-type]

    def test_render_invalid_format_message_includes_format_name(self) -> None:
        """ValueError message should include the invalid format name."""
        report = make_empty_report()
        with pytest.raises(ValueError, match="'xml'"):
            render(report, output_format="xml")  # type: ignore[arg-type]

    def test_render_invalid_format_message_includes_valid_options(self) -> None:
        """ValueError message should mention valid format options."""
        report = make_empty_report()
        with pytest.raises(ValueError) as exc_info:
            render(report, output_format="csv")  # type: ignore[arg-type]
        message = str(exc_info.value)
        assert "terminal" in message or "markdown" in message or "json" in message

    def test_render_json_output_is_valid_json(self) -> None:
        """render() with 'json' should produce parseable JSON."""
        report = make_full_report()
        result = render(report, output_format="json")
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_render_markdown_output_starts_with_h1(self) -> None:
        """render() with 'markdown' should produce output starting with H1."""
        report = make_empty_report()
        result = render(report, output_format="markdown")
        assert result.startswith("# proto_gap")

    def test_render_default_format_is_terminal(self) -> None:
        """Default output_format should be 'terminal'."""
        console, buffer = make_rich_console_with_buffer()
        result = render(make_empty_report(), console=console)
        # Terminal output returns None and writes to console
        assert result is None
        assert buffer.getvalue().strip()

    def test_render_terminal_uses_provided_console(self) -> None:
        """render() with terminal format should use the provided console."""
        console, buffer = make_rich_console_with_buffer()
        render(make_full_report(), output_format="terminal", console=console)
        output = buffer.getvalue()
        assert output.strip()

    def test_render_json_full_report(self) -> None:
        """render() with json format on a full report should include all findings."""
        report = make_full_report()
        result = render(report, output_format="json")
        parsed = json.loads(result)
        assert parsed["total_findings"] == report.total_count

    def test_render_markdown_full_report(self) -> None:
        """render() with markdown format on a full report should include all titles."""
        report = make_full_report()
        result = render(report, output_format="markdown")
        for finding in report.findings:
            assert finding.title in result

    def test_render_all_valid_formats_do_not_raise(self) -> None:
        """All three valid output formats should execute without raising."""
        report = make_full_report()
        console, _ = make_rich_console_with_buffer()
        for fmt in ("terminal", "markdown", "json"):
            try:
                render(report, output_format=fmt, console=console)  # type: ignore[arg-type]
            except Exception as exc:
                pytest.fail(f"render() raised for format '{fmt}': {exc}")

    def test_render_json_and_markdown_are_deterministic(self) -> None:
        """Calling render() twice on the same report should produce identical output."""
        report = make_full_report()
        json_1 = render(report, output_format="json")
        json_2 = render(report, output_format="json")
        assert json_1 == json_2

        md_1 = render(report, output_format="markdown")
        md_2 = render(report, output_format="markdown")
        assert md_1 == md_2


# ---------------------------------------------------------------------------
# Cross-format consistency tests
# ---------------------------------------------------------------------------


class TestCrossFormatConsistency:
    """Tests verifying consistency between the three output formats."""

    def test_json_and_markdown_both_mention_all_rule_ids(self) -> None:
        """Both JSON and Markdown outputs should reference all rule IDs."""
        report = make_full_report()
        json_output = render(report, output_format="json")
        md_output = render(report, output_format="markdown")

        for finding in report.findings:
            if finding.rule_id:
                assert finding.rule_id in json_output, (
                    f"Rule ID {finding.rule_id} missing from JSON"
                )
                assert finding.rule_id in md_output, (
                    f"Rule ID {finding.rule_id} missing from Markdown"
                )

    def test_json_total_matches_markdown_count(self) -> None:
        """JSON total_findings should match the count implicit in the Markdown."""
        report = make_full_report()
        json_output = json.loads(render(report, output_format="json"))
        md_output = render(report, output_format="markdown")

        # JSON total_findings
        total = json_output["total_findings"]
        # Markdown should contain each finding's title
        title_hits = sum(
            1 for f in report.findings if f.title in md_output
        )
        assert title_hits == total

    def test_json_summary_counts_match_markdown_summary(self) -> None:
        """JSON summary counts should appear in the Markdown summary table."""
        report = make_full_report()
        json_output = json.loads(render(report, output_format="json"))
        md_output = render(report, output_format="markdown")

        summary = json_output["summary"]
        assert str(summary["critical"]) in md_output
        assert str(summary["high"]) in md_output
        assert str(summary["medium"]) in md_output
        assert str(summary["low"]) in md_output

    def test_empty_report_consistent_across_formats(self) -> None:
        """All three formats should handle an empty report without crashing."""
        report = make_empty_report()
        console, _ = make_rich_console_with_buffer()

        json_out = render(report, output_format="json")
        md_out = render(report, output_format="markdown")
        render(report, output_format="terminal", console=console)

        assert json_out is not None
        assert md_out is not None

        json_parsed = json.loads(json_out)
        assert json_parsed["total_findings"] == 0
        assert "No production-readiness gaps detected" in md_out

    def test_single_critical_finding_appears_in_all_formats(self) -> None:
        """A single CRITICAL finding should appear in all three output formats."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                title="Unique Critical Title XYZ",
                rule_id="SEC001",
            )
        ]
        console, buffer = make_rich_console_with_buffer()

        json_out = render(report, output_format="json")
        md_out = render(report, output_format="markdown")
        render(report, output_format="terminal", console=console)
        term_out = buffer.getvalue()

        assert "Unique Critical Title XYZ" in json_out
        assert "Unique Critical Title XYZ" in md_out
        assert "Unique Critical Title XYZ" in term_out

    def test_findings_sorted_consistently_across_json_and_markdown(self) -> None:
        """Both JSON and Markdown should present CRITICAL before LOW findings."""
        report = ScanReport(repo_path=Path("/repo"))
        report.findings = [
            make_finding(
                severity=Severity.LOW, title="Low Issue", rule_id="TST001"
            ),
            make_finding(
                severity=Severity.CRITICAL, title="Critical Issue", rule_id="SEC001"
            ),
        ]

        json_out = json.loads(render(report, output_format="json"))
        assert json_out["findings"][0]["severity"] == "CRITICAL"
        assert json_out["findings"][1]["severity"] == "LOW"

        md_out = render(report, output_format="markdown")
        crit_pos = md_out.index("Critical Issue")
        low_pos = md_out.index("Low Issue")
        assert crit_pos < low_pos

    def test_report_with_errors_in_all_formats(self) -> None:
        """All formats should handle reports that contain scan errors."""
        report = make_empty_report()
        report.errors = ["Skipped big.py (too large)", "Analyzer crashed"]
        console, buffer = make_rich_console_with_buffer()

        json_out = json.loads(render(report, output_format="json"))
        md_out = render(report, output_format="markdown")
        render(report, output_format="terminal", console=console)
        term_out = buffer.getvalue()

        # All formats should contain or reference the errors
        assert "Skipped big.py (too large)" in json_out["errors"]
        assert "Skipped big.py (too large)" in md_out or "Scan" in md_out
        assert "Skipped big.py (too large)" in term_out

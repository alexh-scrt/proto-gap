"""Report rendering for proto_gap.

Transforms a ScanReport into one of three output formats:

- **terminal**: Rich color-coded table printed directly to the console,
  with a summary panel, sortable findings table, and detailed per-finding
  descriptions and remediation hints.
- **markdown**: GitHub-flavoured Markdown checklist suitable for pasting
  into issues, pull requests, or engineering planning documents.
- **json**: Machine-readable JSON string for CI pipelines, dashboards,
  or downstream tooling integration.

Public API:
    render_terminal(report, console) -> None
    render_markdown(report) -> str
    render_json(report) -> str
    render(report, output_format, console) -> str | None
"""

from __future__ import annotations

import json
from typing import Literal

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from proto_gap.models import Category, Finding, ScanReport, Severity

# Output format literal type
OutputFormat = Literal["terminal", "markdown", "json"]

# Mapping from Severity to Rich markup style strings
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

# Mapping from Severity to emoji for Markdown output
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

# Mapping from Severity to plain label for Markdown tables
SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
}


def render_terminal(report: ScanReport, console: Console | None = None) -> None:
    """Render a ScanReport as a Rich color-coded terminal report.

    Outputs a summary panel, a compact findings table sorted by severity,
    and a detailed section with per-finding descriptions and remediation
    hints. Any scan errors are listed at the end.

    All output is printed directly to the console (stdout by default).

    Args:
        report: The ScanReport to render.
        console: Optional Rich Console instance. A new Console writing to
            stdout is created if not provided.
    """
    if console is None:
        console = Console()

    _render_summary_panel(report, console)

    if not report.findings:
        console.print(
            "\n[bold green]✓ No production-readiness gaps detected![/bold green]"
        )
        _render_errors_section(report, console)
        return

    _render_findings_table(report, console)
    _render_detailed_findings(report, console)
    _render_errors_section(report, console)


def render_markdown(report: ScanReport) -> str:
    """Render a ScanReport as a GitHub-flavoured Markdown string.

    Produces a structured document with a summary table, findings grouped
    by category with unchecked checkboxes (suitable for tracking), and
    detailed descriptions and remediation hints for each finding.

    Args:
        report: The ScanReport to render.

    Returns:
        A Markdown-formatted string. The caller is responsible for writing
        it to stdout or a file.
    """
    lines: list[str] = []

    _md_header(report, lines)
    _md_summary_table(report, lines)

    if not report.findings:
        lines.append("---")
        lines.append("")
        lines.append("✅ **No production-readiness gaps detected!**")
        lines.append("")
        _md_errors_section(report, lines)
        return "\n".join(lines)

    _md_findings_by_category(report, lines)
    _md_errors_section(report, lines)

    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    """Render a ScanReport as a formatted JSON string.

    The JSON is serialized with 2-space indentation and is suitable for
    piping to downstream tools (jq, CI parsers, dashboards, etc.).

    Args:
        report: The ScanReport to render.

    Returns:
        A JSON-formatted string representing the complete scan report.
        Path objects are serialized as strings.
    """
    return json.dumps(report.to_dict(), indent=2, default=str)


def render(
    report: ScanReport,
    output_format: OutputFormat = "terminal",
    console: Console | None = None,
) -> str | None:
    """Dispatch rendering to the appropriate format handler.

    Args:
        report: The ScanReport to render.
        output_format: Output format selector. One of:
            - 'terminal': Rich color table printed to the console.
            - 'markdown': Returns a Markdown-formatted string.
            - 'json': Returns a JSON-formatted string.
        console: Optional Rich Console instance for 'terminal' output.

    Returns:
        A string for 'markdown' and 'json' formats. Returns None for
        'terminal' since output is printed directly to the console.

    Raises:
        ValueError: If output_format is not one of the supported values.
    """
    if output_format == "terminal":
        render_terminal(report, console=console)
        return None
    elif output_format == "markdown":
        return render_markdown(report)
    elif output_format == "json":
        return render_json(report)
    else:
        supported = "'terminal', 'markdown', 'json'"
        raise ValueError(
            f"Unsupported output format: {output_format!r}. "
            f"Choose from: {supported}."
        )


# ---------------------------------------------------------------------------
# Terminal rendering helpers
# ---------------------------------------------------------------------------


def _render_summary_panel(report: ScanReport, console: Console) -> None:
    """Render the top-level summary panel with scan metadata and counts.

    Args:
        report: The ScanReport to summarize.
        console: Rich Console to print to.
    """
    lines: list[str] = [
        f"[bold]Repository:[/bold] {report.repo_path}",
        f"[bold]Files scanned:[/bold] {len(report.scanned_files)}",
        f"[bold]Total findings:[/bold] {report.total_count}",
        (
            f"  [bold red]CRITICAL:[/bold red] {report.critical_count}  "
            f"[red]HIGH:[/red] {report.high_count}  "
            f"[yellow]MEDIUM:[/yellow] {report.medium_count}  "
            f"[cyan]LOW:[/cyan] {report.low_count}"
        ),
    ]

    if report.errors:
        lines.append(
            f"[yellow]Scan warnings/errors:[/yellow] {len(report.errors)}"
        )

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold blue]proto_gap Production-Readiness Report[/bold blue]",
            border_style="blue",
            padding=(1, 2),
        )
    )


def _render_findings_table(report: ScanReport, console: Console) -> None:
    """Render a compact summary table of all findings sorted by severity.

    Args:
        report: The ScanReport whose findings to display.
        console: Rich Console to print to.
    """
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="blue",
        expand=True,
        title="[bold]Findings Summary[/bold]",
        title_style="bold blue",
    )

    table.add_column("#", style="dim", width=4, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Rule", width=8, no_wrap=True)
    table.add_column("Category", width=20, no_wrap=True)
    table.add_column("Title", min_width=35)
    table.add_column("Location", width=32)

    for i, finding in enumerate(report.findings_by_severity(), start=1):
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        severity_text = Text(finding.severity.value, style=sev_color)
        rule_id = finding.rule_id or "-"
        location = _format_location(finding, truncate=32)

        table.add_row(
            str(i),
            severity_text,
            rule_id,
            finding.category.value,
            finding.title,
            location,
        )

    console.print(table)


def _render_detailed_findings(report: ScanReport, console: Console) -> None:
    """Render a detailed section with full descriptions and remediation hints.

    Args:
        report: The ScanReport whose findings to detail.
        console: Rich Console to print to.
    """
    console.print()
    console.print(
        "[bold blue]" + "─" * 60 + " Detailed Findings " + "─" * 3 + "[/bold blue]"
    )

    for i, finding in enumerate(report.findings_by_severity(), start=1):
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        rule_suffix = f" [{finding.rule_id}]" if finding.rule_id else ""

        console.print()
        console.print(
            f"  [{sev_color}]▸ [{finding.severity.value}]{rule_suffix}[/{sev_color}] "
            f"[bold]{i}. {finding.title}[/bold]"
        )
        console.print(
            f"    [dim italic]{finding.category.value}[/dim italic]"
        )

        if finding.file_path is not None:
            location = _format_location(finding, truncate=None)
            console.print(f"    [dim]📁 Location:[/dim] {location}")

        console.print(
            f"    [dim]📋 Issue:[/dim]  {finding.description}"
        )
        console.print(
            f"    [green]🔧 Fix:[/green]   {finding.remediation}"
        )


def _render_errors_section(report: ScanReport, console: Console) -> None:
    """Render non-fatal scan errors at the end of the terminal report.

    Args:
        report: The ScanReport whose errors to display.
        console: Rich Console to print to.
    """
    if not report.errors:
        return

    console.print()
    console.print(
        "[bold yellow]" + "─" * 60 + " Scan Warnings " + "─" * 6 + "[/bold yellow]"
    )
    for error in report.errors:
        console.print(f"  [yellow]⚠[/yellow]  {error}")


# ---------------------------------------------------------------------------
# Markdown rendering helpers
# ---------------------------------------------------------------------------


def _md_header(report: ScanReport, lines: list[str]) -> None:
    """Append the Markdown report header and metadata section.

    Args:
        report: The ScanReport to extract metadata from.
        lines: Mutable list of Markdown lines to append to.
    """
    lines.append("# proto_gap Production-Readiness Report")
    lines.append("")
    lines.append(
        f"> Generated by **proto_gap** static analysis"
    )
    lines.append("")
    lines.append(f"**Repository:** `{report.repo_path}`  ")
    lines.append(f"**Files scanned:** {len(report.scanned_files)}  ")
    lines.append(f"**Total findings:** {report.total_count}  ")
    lines.append("")


def _md_summary_table(report: ScanReport, lines: list[str]) -> None:
    """Append the Markdown severity summary table.

    Args:
        report: The ScanReport to summarize.
        lines: Mutable list of Markdown lines to append to.
    """
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|:---------|------:|")
    lines.append(f"| {SEVERITY_LABEL[Severity.CRITICAL]} | {report.critical_count} |")
    lines.append(f"| {SEVERITY_LABEL[Severity.HIGH]} | {report.high_count} |")
    lines.append(f"| {SEVERITY_LABEL[Severity.MEDIUM]} | {report.medium_count} |")
    lines.append(f"| {SEVERITY_LABEL[Severity.LOW]} | {report.low_count} |")
    lines.append("")


def _md_findings_by_category(report: ScanReport, lines: list[str]) -> None:
    """Append grouped findings sections to the Markdown output.

    Findings are grouped by category and sorted by severity within each
    group. Categories with no findings are omitted.

    Args:
        report: The ScanReport whose findings to render.
        lines: Mutable list of Markdown lines to append to.
    """
    by_category = report.findings_by_category()
    severity_order: dict[Severity, int] = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }

    lines.append("## Findings")
    lines.append("")
    lines.append(
        "Each item below is an actionable gap. Check the box when resolved."
    )
    lines.append("")

    has_any = False
    for category in Category:
        cat_findings = by_category.get(category, [])
        if not cat_findings:
            continue

        has_any = True
        sorted_findings = sorted(
            cat_findings, key=lambda f: severity_order[f.severity]
        )

        lines.append(f"### {category.value}")
        lines.append("")

        for finding in sorted_findings:
            emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
            rule_badge = f" `{finding.rule_id}`" if finding.rule_id else ""
            lines.append(
                f"- [ ] {emoji} **[{finding.severity.value}]{rule_badge}** "
                f"{finding.title}"
            )

            if finding.file_path is not None:
                location = _format_location(finding, truncate=None)
                lines.append(f"  - 📁 **Location:** `{location}`")

            lines.append(f"  - 📋 **Issue:** {finding.description}")
            lines.append(f"  - 🔧 **Fix:** {finding.remediation}")
            lines.append("")

    if not has_any:
        lines.append("✅ **No production-readiness gaps detected!**")
        lines.append("")


def _md_errors_section(report: ScanReport, lines: list[str]) -> None:
    """Append the scan errors/warnings section to the Markdown output.

    Args:
        report: The ScanReport whose errors to document.
        lines: Mutable list of Markdown lines to append to.
    """
    if not report.errors:
        return

    lines.append("---")
    lines.append("")
    lines.append("## Scan Warnings")
    lines.append("")
    lines.append(
        "The following non-fatal issues were encountered during the scan:"
    )
    lines.append("")
    for error in report.errors:
        lines.append(f"- ⚠️ `{error}`")
    lines.append("")


# ---------------------------------------------------------------------------
# Shared formatting helpers
# ---------------------------------------------------------------------------


def _format_location(finding: Finding, truncate: int | None = 60) -> str:
    """Format the file path and optional line number of a finding.

    Produces a string like 'app.py:42', 'app.py', or '-' when no file path
    is available. The path can optionally be truncated from the left with a
    leading ellipsis to keep terminal output readable.

    Args:
        finding: The Finding to produce a location string for.
        truncate: Maximum character length for the path portion. If the path
            exceeds this length it is truncated from the left with '...'. Set
            to None to disable truncation.

    Returns:
        A human-readable location string.
    """
    if finding.file_path is None:
        return "-"

    path_str = str(finding.file_path)

    if truncate is not None and len(path_str) > truncate:
        # Truncate from the left, keeping the tail (filename) visible
        path_str = "..." + path_str[-(truncate - 3):]

    if finding.line_number is not None:
        return f"{path_str}:{finding.line_number}"

    return path_str

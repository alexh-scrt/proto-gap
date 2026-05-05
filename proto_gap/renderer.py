"""Report rendering for proto_gap.

Transforms a ScanReport into one of three output formats:
- Rich terminal table with color-coded severity levels
- Markdown checklist suitable for GitHub issues or pull request comments
- Machine-readable JSON string
"""

from __future__ import annotations

import json
from typing import Literal

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from proto_gap.models import Category, Finding, ScanReport, Severity

# Output format type alias
OutputFormat = Literal["terminal", "markdown", "json"]

# Severity colors for Rich terminal output
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

# Severity emoji for Markdown output
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}


def render_terminal(report: ScanReport, console: Console | None = None) -> None:
    """Render a ScanReport as a color-coded Rich terminal table.

    Prints directly to stdout (or the provided Console) using Rich markup.

    Args:
        report: The ScanReport to render.
        console: Optional Rich Console instance. A default console is created
            if not provided.
    """
    if console is None:
        console = Console()

    # Header panel
    header_lines = [
        f"[bold]Repository:[/bold] {report.repo_path}",
        f"[bold]Files scanned:[/bold] {len(report.scanned_files)}",
        f"[bold]Total findings:[/bold] {report.total_count}",
        f"  [bold red]CRITICAL:[/bold red] {report.critical_count}  "
        f"[red]HIGH:[/red] {report.high_count}  "
        f"[yellow]MEDIUM:[/yellow] {report.medium_count}  "
        f"[cyan]LOW:[/cyan] {report.low_count}",
    ]
    if report.errors:
        header_lines.append(
            f"[yellow]Scan errors:[/yellow] {len(report.errors)}"
        )

    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold blue]proto_gap Scan Report[/bold blue]",
            border_style="blue",
        )
    )

    if not report.findings:
        console.print(
            "[bold green]✓ No production-readiness gaps detected![/bold green]"
        )
        return

    # Findings table
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="blue",
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10, no_wrap=True)
    table.add_column("Category", width=18, no_wrap=True)
    table.add_column("Title", width=40)
    table.add_column("Location", width=30)
    table.add_column("Rule", width=8, no_wrap=True)

    for finding in report.findings_by_severity():
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        severity_text = Text(finding.severity.value, style=sev_color)

        location = _format_location(finding)
        rule_id = finding.rule_id or "-"

        table.add_row(
            severity_text,
            finding.category.value,
            finding.title,
            location,
            rule_id,
        )

    console.print(table)

    # Detailed findings
    console.print()
    console.print("[bold blue]── Detailed Findings ──────────────────────────────────────[/bold blue]")

    for i, finding in enumerate(report.findings_by_severity(), start=1):
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        console.print(
            f"\n[{sev_color}][{finding.severity.value}][/{sev_color}] "
            f"[bold]{i}. {finding.title}[/bold] "
            f"([dim]{finding.category.value}[/dim])"
        )
        if finding.file_path:
            loc = _format_location(finding)
            console.print(f"  [dim]Location:[/dim] {loc}")
        console.print(f"  [dim]Description:[/dim] {finding.description}")
        console.print(f"  [dim]Remediation:[/dim] [green]{finding.remediation}[/green]")

    if report.errors:
        console.print()
        console.print("[bold yellow]── Scan Errors ──────────────────────────────────────────[/bold yellow]")
        for error in report.errors:
            console.print(f"  [yellow]⚠[/yellow] {error}")


def render_markdown(report: ScanReport) -> str:
    """Render a ScanReport as a Markdown checklist string.

    The output is suitable for pasting into GitHub issues, pull requests,
    or engineering planning documents.

    Args:
        report: The ScanReport to render.

    Returns:
        A Markdown-formatted string representing the scan report.
    """
    lines: list[str] = []

    lines.append("# proto_gap Production-Readiness Report")
    lines.append("")
    lines.append(f"**Repository:** `{report.repo_path}`  ")
    lines.append(f"**Files scanned:** {len(report.scanned_files)}  ")
    lines.append(f"**Total findings:** {report.total_count}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 CRITICAL | {report.critical_count} |")
    lines.append(f"| 🟠 HIGH | {report.high_count} |")
    lines.append(f"| 🟡 MEDIUM | {report.medium_count} |")
    lines.append(f"| 🔵 LOW | {report.low_count} |")
    lines.append("")

    if not report.findings:
        lines.append("✅ **No production-readiness gaps detected!**")
        return "\n".join(lines)

    # Group findings by category
    by_category = report.findings_by_category()

    lines.append("## Findings by Category")
    lines.append("")

    for category, cat_findings in by_category.items():
        if not cat_findings:
            continue

        lines.append(f"### {category.value}")
        lines.append("")

        # Sort by severity within category
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_findings = sorted(cat_findings, key=lambda f: order[f.severity])

        for finding in sorted_findings:
            emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
            rule_badge = f" `{finding.rule_id}`" if finding.rule_id else ""
            lines.append(f"- [ ] {emoji} **[{finding.severity.value}]{rule_badge} {finding.title}**")

            if finding.file_path:
                loc = _format_location(finding)
                lines.append(f"  - 📁 `{loc}`")

            lines.append(f"  - 📋 {finding.description}")
            lines.append(f"  - 🔧 {finding.remediation}")
            lines.append("")

    if report.errors:
        lines.append("## Scan Errors")
        lines.append("")
        for error in report.errors:
            lines.append(f"- ⚠️ `{error}`")
        lines.append("")

    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    """Render a ScanReport as a formatted JSON string.

    The JSON output is machine-readable and suitable for integration with
    CI pipelines, dashboards, or downstream tooling.

    Args:
        report: The ScanReport to render.

    Returns:
        A JSON-formatted string representing the scan report.
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
        output_format: One of 'terminal', 'markdown', or 'json'.
        console: Optional Rich Console for terminal output.

    Returns:
        A string for 'markdown' and 'json' formats, or None for 'terminal'
        (which prints directly to the console).

    Raises:
        ValueError: If an unsupported output_format is specified.
    """
    if output_format == "terminal":
        render_terminal(report, console=console)
        return None
    elif output_format == "markdown":
        return render_markdown(report)
    elif output_format == "json":
        return render_json(report)
    else:
        raise ValueError(
            f"Unsupported output format: {output_format!r}. "
            "Choose from: 'terminal', 'markdown', 'json'."
        )


def _format_location(finding: Finding) -> str:
    """Format the file path and optional line number of a finding.

    Args:
        finding: The Finding to format a location string for.

    Returns:
        A human-readable location string like 'app.py:42' or 'app.py'.
    """
    if finding.file_path is None:
        return "-"
    path_str = str(finding.file_path)
    if finding.line_number is not None:
        return f"{path_str}:{finding.line_number}"
    return path_str

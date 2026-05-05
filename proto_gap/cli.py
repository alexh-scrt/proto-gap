"""Typer-based CLI entry point for proto_gap.

Provides the 'proto-gap' command which accepts a repository path and output
format flags, runs the scanner, and displays or writes the resulting report.

Usage examples::

    proto-gap ./my-prototype
    proto-gap ./my-prototype --output markdown --output-file report.md
    proto-gap ./my-prototype --output json | jq '.findings'
    proto-gap --version

Exit codes:
    0  - scan completed with no findings, or only LOW/MEDIUM findings
    1  - invalid arguments or I/O error
    2  - scan completed with one or more HIGH severity findings
    3  - scan completed with one or more CRITICAL severity findings
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from proto_gap import __version__
from proto_gap.renderer import OutputFormat, render
from proto_gap.scanner import scan_repository

# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="proto-gap",
    help=(
        "[bold]proto-gap[/bold] statically analyzes an AI-generated prototype "
        "codebase and produces a prioritized production-readiness gap checklist.\n\n"
        "It scans for missing authentication, error handling, environment "
        "configuration, security vulnerabilities, database migration strategies, "
        "logging, and test coverage."
    ),
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=False,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# Primary console (stdout) for normal output
console = Console()

# Error console (stderr) for diagnostics and error messages
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    """Print the package version string and exit when --version is passed.

    Args:
        value: True when the flag is present, False otherwise.
    """
    if value:
        typer.echo(f"proto-gap {__version__}")
        raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Main scan command
# ---------------------------------------------------------------------------


@app.command()
def scan(
    repo_path: Path = typer.Argument(
        default=Path("."),
        help=(
            "Path to the repository directory to analyze. "
            "Defaults to the current working directory."
        ),
        show_default=True,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help=(
            "Output format for the report. "
            "One of: [bold]terminal[/bold] (color table), "
            "[bold]markdown[/bold] (GitHub checklist), "
            "[bold]json[/bold] (machine-readable)."
        ),
        metavar="FORMAT",
        show_default=True,
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-f",
        help=(
            "Write the report to this file path instead of stdout. "
            "Applicable only for [bold]markdown[/bold] and [bold]json[/bold] formats. "
            "The file is created or overwritten."
        ),
        writable=True,
        show_default=False,
    ),
    max_file_size: int = typer.Option(
        1_000_000,
        "--max-file-size",
        help=(
            "Maximum file size in bytes to scan. "
            "Files larger than this limit are skipped to avoid memory issues "
            "with very large generated or binary files."
        ),
        show_default=True,
        min=1,
    ),
    no_exit_codes: bool = typer.Option(
        False,
        "--no-exit-codes",
        help=(
            "Always exit with code 0 regardless of finding severity. "
            "Useful in CI pipelines where a non-zero exit should not fail the build."
        ),
        show_default=True,
        is_flag=True,
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show the proto-gap version and exit.",
        callback=_version_callback,
        is_eager=True,
        show_default=False,
    ),
) -> None:
    """Scan a repository directory for production-readiness gaps.

    Performs static analysis across the target repository, checking for:

    \b
    • Missing or weak authentication / authorization
    • Poor error handling (bare except, silent failures)
    • Insecure environment configuration (hardcoded secrets, debug mode)
    • Security vulnerabilities (eval, pickle, shell injection)
    • Missing database migration strategy (create_all, SQLite, no Alembic)
    • Inadequate logging (print() instead of structured logs)
    • Insufficient test coverage (no tests, no CI, skipped tests)

    [bold]Exit codes:[/bold]

    \b
    0  No findings, or only MEDIUM/LOW findings
    1  Argument or I/O error
    2  One or more HIGH severity findings detected
    3  One or more CRITICAL severity findings detected

    [bold]Examples:[/bold]

    \b
        proto-gap ./my-prototype
        proto-gap ./my-prototype --output markdown --output-file report.md
        proto-gap ./my-prototype --output json | jq '.summary'
        proto-gap . --max-file-size 500000
    """
    # ------------------------------------------------------------------
    # Validate the output format argument
    # ------------------------------------------------------------------
    valid_formats: tuple[str, ...] = ("terminal", "markdown", "json")
    if output not in valid_formats:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid output format [bold]{output!r}[/bold]. "
            f"Choose from: {', '.join(valid_formats)}"
        )
        raise typer.Exit(code=1)

    output_format: OutputFormat = output  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Emit a progress message appropriate to the output format
    # ------------------------------------------------------------------
    _emit_scan_start(repo_path, output_format)

    # ------------------------------------------------------------------
    # Run the scanner
    # ------------------------------------------------------------------
    try:
        report = scan_repository(
            repo_path=repo_path,
            max_file_size_bytes=max_file_size,
        )
    except ValueError as exc:
        err_console.print(
            f"[bold red]Error:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc
    except PermissionError as exc:
        err_console.print(
            f"[bold red]Permission error while scanning:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001
        err_console.print(
            f"[bold red]Unexpected error during scan:[/bold red] "
            f"{type(exc).__name__}: {exc}"
        )
        raise typer.Exit(code=1) from exc

    # ------------------------------------------------------------------
    # Render the report
    # ------------------------------------------------------------------
    try:
        result = render(
            report,
            output_format=output_format,
            console=console,
        )
    except ValueError as exc:
        err_console.print(
            f"[bold red]Renderer error:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    # ------------------------------------------------------------------
    # Write string output (markdown / json) to file or stdout
    # ------------------------------------------------------------------
    if result is not None:
        if output_file is not None:
            _write_output_file(output_file, result)
        else:
            # Print to stdout without the Rich markup layer
            typer.echo(result)

    # ------------------------------------------------------------------
    # Emit a completion summary to stderr when using file/non-terminal output
    # ------------------------------------------------------------------
    if output_format != "terminal":
        _emit_scan_summary(report, output_file)

    # ------------------------------------------------------------------
    # Set exit code based on highest finding severity
    # ------------------------------------------------------------------
    if not no_exit_codes:
        if report.critical_count > 0:
            raise typer.Exit(code=3)
        elif report.high_count > 0:
            raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _emit_scan_start(repo_path: Path, output_format: OutputFormat) -> None:
    """Emit a scan-start progress message to the appropriate stream.

    For terminal output the message is printed to stdout via the Rich console
    so it appears before the report. For other formats it goes to stderr so
    it does not pollute the report content.

    Args:
        repo_path: Repository path being scanned.
        output_format: Selected output format.
    """
    message = f"Scanning [bold]{repo_path}[/bold] ..."
    if output_format == "terminal":
        console.print(f"[dim]{message}[/dim]")
    else:
        err_console.print(f"[dim]{message}[/dim]")


def _emit_scan_summary(
    report: object,
    output_file: Optional[Path],
) -> None:
    """Emit a brief scan-completion summary to stderr.

    This is printed after non-terminal output (markdown/json) so the user
    gets a quick overview without looking inside the generated file/output.

    Args:
        report: The completed ScanReport.
        output_file: Path the report was written to, or None for stdout.
    """
    from proto_gap.models import ScanReport  # local import to avoid circularity

    if not isinstance(report, ScanReport):
        return

    destination = str(output_file) if output_file is not None else "stdout"
    err_console.print(
        f"[dim]Report written to [bold]{destination}[/bold]. "
        f"Findings: "
        f"[bold red]{report.critical_count} CRITICAL[/bold red], "
        f"[red]{report.high_count} HIGH[/red], "
        f"[yellow]{report.medium_count} MEDIUM[/yellow], "
        f"[cyan]{report.low_count} LOW[/cyan][/dim]"
    )


def _write_output_file(output_file: Path, content: str) -> None:
    """Write a string report to the specified file path.

    Creates parent directories if needed. On failure, prints an error to
    stderr and exits with code 1.

    Args:
        output_file: Destination file path.
        content: Report content string to write.
    """
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")
        err_console.print(
            f"[dim]Report saved to [bold]{output_file}[/bold][/dim]"
        )
    except OSError as exc:
        err_console.print(
            f"[bold red]Error writing report to '{output_file}':[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Package entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Primary entry point invoked by the 'proto-gap' console script.

    Delegates directly to the Typer application. Any unhandled exceptions
    that bubble past Typer's own error handling are caught here to ensure a
    clean non-zero exit rather than a raw traceback.
    """
    try:
        app()
    except SystemExit:
        # Allow SystemExit (which Typer uses for --help and Exit()) to propagate
        raise
    except Exception as exc:  # noqa: BLE001
        err_console.print(
            f"[bold red]Fatal error:[/bold red] {type(exc).__name__}: {exc}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
